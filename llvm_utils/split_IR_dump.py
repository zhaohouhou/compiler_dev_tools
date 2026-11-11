#!/usr/bin/env python3
"""
split_IR_dump_v2.py

改进版 split_IR_dump.py：

1. 支持 loop-level pass dump
   原脚本正则要求 "; *** IR Dump After <Pass> on <Func> ***"，loop pass 格式是
   "; *** IR Dump After <Pass> on loop %for.body.i in <Func> ***"，匹配失败。
   改进后：
     - 支持可选的 on 子句
     - 支持 "on loop ... in <Func>" 提取函数名
     - 支持无 on 子句的 dump（逐行扫描兜底）

2. 支持 llc / Machine IR dump 过滤
   llc -print-after-all / -print-machine-instrs 输出格式：
     - Header: "# *** IR Dump After <Pass> on <Func> ***"
     - 函数开始: "# Machine code for function <Func>:"
     - 函数结束: "# End machine code for function <Func>."
   改进后支持 # 开头 header 和 Machine IR 函数标记。

3. 保持流式处理，不修改原脚本。

Usage:
    python3 /tmp/split_IR_dump_v2.py input.log out_dir
    python3 /tmp/split_IR_dump_v2.py input.log out_dir --func my_kernel
"""

import os
import re
import argparse
import sys

IS_DEBUG = 1

# 改进的 dump header 正则：
#   支持 ; 或 # 开头
#   支持 "IR Dump" 或 "Machine IR Dump"
#   支持可选的 on 子句
#   group(1): PassName
#   group(2): on_target (可选，如 "_Z3foo" 或 "loop %for.body.i in _Z3foo")
DUMP_HEADER_RE = re.compile(
    r"^(?:[;#]\s+)?\*\*\*\s+(?:IR Dump|Machine IR Dump) After\s+(.+?)"
    r"(?:\s+on\s+([^*]+?))?\s*\*\*\*[:]?$"
)

# LLVM IR 函数定义: define ... @func(
FUNC_START_RE = re.compile(r"^define\s+.*@([^(]+)\(")

# Machine IR 函数标记
MACHINE_FUNC_START_RE = re.compile(r"^#\s*Machine code for function\s+([^:]+):")
MACHINE_FUNC_END_RE = re.compile(r"^#\s*End machine code for function\s+([^:]+)\.")


def extract_pass_and_target(header_line):
    m = DUMP_HEADER_RE.match(header_line)
    if not m:
        if IS_DEBUG:
            print(f"[DEBUG] extract_pass_and_target: no match for header: {header_line.strip()!r}")
        return None, None
    pass_name = m.group(1).strip()
    on_target = m.group(2).strip() if m.group(2) else None
    # 清理非法字符
    pass_name = re.sub(r"[^\w-]", "_", pass_name)
    if IS_DEBUG:
        print(f"[DEBUG] extract_pass_and_target: pass='{pass_name}', target='{on_target}'")
    return pass_name, on_target


def extract_func_from_target(on_target):
    """从 on_target 提取函数名。"""
    if not on_target:
        return None
    # 处理 "loop %for.body.i in _Z3foo" -> "_Z3foo"
    m = re.search(r"\bin\s+([^\s]+)\s*$", on_target)
    if m:
        func = m.group(1)
        if IS_DEBUG:
            print(f"[DEBUG] extract_func_from_target: extracted '{func}' from loop target '{on_target}'")
        return func
    # 否则整个 on_target 就是函数名（如 "_Z3foo"）
    if IS_DEBUG:
        print(f"[DEBUG] extract_func_from_target: target '{on_target}' is function name")
    return on_target.strip()


def match_func(name, pattern):
    if pattern is None:
        return True
    if name is None:
        return False
    return re.search(pattern, name) is not None


def extract_target_functions(lines, pattern, target_from_header=None):
    """过滤保留目标函数。"""
    result = []

    # 快速路径：header 明确给出函数名且匹配 pattern，保留全部
    if target_from_header and match_func(target_from_header, pattern):
        if IS_DEBUG:
            print(f"[DEBUG] extract_target_functions: fast path, target_from_header='{target_from_header}' matches")
        return list(lines)

    if IS_DEBUG:
        print(f"[DEBUG] extract_target_functions: scanning {len(lines)} lines, pattern={pattern!r}")

    # 保守路径：逐行扫描
    in_llvm_func = False
    in_machine_func = False
    brace_depth = 0

    for line in lines:
        # LLVM IR 函数定义
        m = FUNC_START_RE.match(line)
        if m:
            func_name = m.group(1)
            match = match_func(func_name, pattern)
            if IS_DEBUG:
                print(f"[DEBUG] LLVM func candidate: '{func_name}' -> match={match}")
            if match:
                in_llvm_func = True
                brace_depth = line.count("{") - line.count("}")
                result.append(line)
            else:
                in_llvm_func = False
            continue

        # Machine IR 函数开始
        m = MACHINE_FUNC_START_RE.match(line)
        if m:
            func_name = m.group(1)
            match = match_func(func_name, pattern)
            if IS_DEBUG:
                print(f"[DEBUG] Machine func start: '{func_name}' -> match={match}")
            if match:
                in_machine_func = True
                result.append(line)
            else:
                in_machine_func = False
            continue

        # Machine IR 函数结束
        m = MACHINE_FUNC_END_RE.match(line)
        if m:
            if IS_DEBUG:
                print(f"[DEBUG] Machine func end: '{m.group(1)}'")
            if in_machine_func:
                result.append(line)
            in_machine_func = False
            continue

        if in_llvm_func:
            result.append(line)
            brace_depth += line.count("{") - line.count("}")
            if brace_depth <= 0:
                in_llvm_func = False
            continue

        if in_machine_func:
            result.append(line)

    if IS_DEBUG:
        print(f"[DEBUG] extract_target_functions: kept {len(result)} lines")
    return result


def process_block(block_lines, block_id, output_dir, func_pattern):
    if not block_lines:
        return

    header = block_lines[0]
    body = block_lines[1:]

    if IS_DEBUG:
        print(f"[DEBUG] process_block #{block_id}: header={header.strip()!r}, body={len(body)} lines")

    pass_name, on_target = extract_pass_and_target(header)
    if pass_name is None:
        if IS_DEBUG:
            print(f"[DEBUG] process_block #{block_id}: header not recognized, skipping")
        return  # 不是有效的 dump block

    target_func = extract_func_from_target(on_target)

    if IS_DEBUG:
        print(f"[DEBUG] process_block #{block_id}: pass='{pass_name}', extracted_func='{target_func}'")

    # 如果 func_pattern 提供且 header 明确说了别的函数，直接跳过
    if func_pattern and target_func and not match_func(target_func, func_pattern):
        if IS_DEBUG:
            print(f"[DEBUG] process_block #{block_id}: target_func '{target_func}' does not match pattern {func_pattern!r}, skip")
        return

    filtered = extract_target_functions(body, func_pattern, target_func)

    if not filtered:
        if IS_DEBUG:
            print(f"[DEBUG] process_block #{block_id}: no lines kept, skip output")
        return

    filename = os.path.join(
        output_dir,
        f"{block_id:03d}_{pass_name}.ll"
    )

    if IS_DEBUG:
        print(f"[DEBUG] process_block #{block_id}: writing {len(filtered)} lines to {filename}")

    with open(filename, "w", encoding="utf-8") as out:
        out.write(header)
        out.writelines(filtered)


def main():
    parser = argparse.ArgumentParser(
        description="Split LLVM -print-after-all / llc dump and filter by function")
    parser.add_argument("input_file", help="Input log file")
    parser.add_argument("output_dir", help="Output directory")
    parser.add_argument(
        "--func",
        help="Function name regex to filter (default: no filtering)",
        default=None
    )

    args = parser.parse_args()

    if not os.path.isfile(args.input_file):
        print(f"[ERROR] Input file not found: {args.input_file}")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    with open(args.input_file, "r", encoding="utf-8", errors="ignore") as f:
        current_block = []
        block_id = 0
        matched_first_pass = False

        for line in f:
            if DUMP_HEADER_RE.match(line):
                matched_first_pass = True
                if IS_DEBUG:
                    print(f"\n[DEBUG] main: found dump header: {line.strip()!r}")
                if current_block:
                    block_id += 1
                    process_block(
                        current_block,
                        block_id,
                        args.output_dir,
                        args.func
                    )
                current_block = [line]
            else:
                if matched_first_pass:
                    current_block.append(line)

        if IS_DEBUG:
            print(f"\n[DEBUG] main: EOF, final block has {len(current_block)} lines")

        if current_block:
            block_id += 1
            process_block(
                current_block,
                block_id,
                args.output_dir,
                args.func
            )

    if IS_DEBUG:
        print(f"[DEBUG] main: done, total blocks processed={block_id}")


if __name__ == '__main__':
    main()

