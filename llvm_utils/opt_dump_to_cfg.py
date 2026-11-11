#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
optdump2cfg.py — 把 LLVM opt -print-before/-print-after 的文本输出画成 CFG 图（PDF）。

用法（opt 的 dump 打到 stderr，重定向用 2>）：

    opt -O2 -print-after=reassociate test.ll -o /dev/null 2> dump.txt
    python3 optdump2cfg.py dump.txt
    python3 optdump2cfg.py dump.txt -o out/foo
    python3 optdump2cfg.py dump.txt -f '^main$' --names-only
    python3 optdump2cfg.py dump.txt --backedge-color green

输入约定：一次喂一个 pass 的 dump，可以含多个函数、多个 banner
（比如 before+after 各一个）。

banner 行两种格式都认：
    裸 stderr 格式：  *** IR Dump After ReassociatePass ***
    注释/文件格式：  ; *** IR Dump After ReassociatePass on _Z3foo ***

输出：每个函数画两个独立的 PDF 文件，不合并：
    full  —— 节点内是该基本块的完整指令（看代码用）
    names —— 节点只有基本块名字（看结构/截图讨论用）

文件名规则（PREFIX 默认是输入文件去后缀，stdin 则是 cfg）：
    只画到一个函数时：  <PREFIX>.full.pdf / <PREFIX>.names.pdf
    有多个函数时：      <PREFIX>.<序号>_<标题>.full.pdf 等，标题含 phase/pass/函数名，
                        文件名里非法字符替换成下划线，不会互相覆盖。

依赖：graphviz 的 `dot` 命令。

边的提取：
    直接解析 terminator 指令（br/switch/invoke/callbr/indirectbr 等），
    不依赖 "; preds =" 注释——注释是打印器附带的，terminator 才是 IR 本体。
    解析不到目标的基本块（理论上不该发生）会以红色虚线节点画出来，方便发现。
    回边用 DFS 三色标记识别（指向栈上灰色节点的边，自环也算），默认蓝色加粗，
    可用 --backedge-color 改颜色，给 none 关闭。
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

# ---------------------------------------------------------------------------
# 正则
# ---------------------------------------------------------------------------

BANNER_RE = re.compile(
    r'^\s*;?\s*\*{3}\s*IR Dump (Before|After)\s+(.*?)'
    r'(?:\s+on\s+([\w.$-]+))?\s*\*{3}\s*$'
)

# define 开头（declare 不算，declare 没有函数体）
DEFINE_RE = re.compile(r'^\s*define\b')

# 从 define 行里抠函数名：@foo( 或 @"weird name"(
FUNC_NAME_RE = re.compile(r'@("(?:[^"\\]|\\.)+"|[\w.$-]+)\s*\(')

# 基本块标签行。LLVM IR 文本格式里标签顶格，指令反而缩进两格：
#   entry:
#   3:
#   "quoted name":
# 行尾允许跟 "; preds = ..." 注释。
# 名字字符集按 LLVM 标识符规则：[-a-zA-Z$._][-a-zA-Z$._0-9]*，外加纯数字和引号名字。
LABEL_RE = re.compile(
    r'^\s*(?P<name>"(?:[^"\\]|\\.)+"|[-A-Za-z$._][-\w.$]*|\d+)'
    r':(?:[ \t]*;.*)?\s*$'
)

# label 目标的通用写法：label %foo / label %"foo bar" / label %3
LABEL_PAT = r'"(?:[^"\\]|\\.)+"|[\w.$-]+|\d+'
LABEL_REF_RE = re.compile(r'\blabel\s+%(' + LABEL_PAT + ')')

# br i1 %c, label %t, label %f
BR_COND_RE = re.compile(
    r'\bbr\s+i1\b.+?,\s*label\s+%(' + LABEL_PAT + r')\s*,\s*label\s+%(' + LABEL_PAT + ')'
)

# switch i32 %x, label %def [ i32 1, label %a, i32 2, label %b ]
SWITCH_RE = re.compile(
    r'\bswitch\b.+?,\s*label\s+%(' + LABEL_PAT + r')\s*\[(?P<cases>.*?)\]'
)
CASE_RE = re.compile(r'(?P<val>[^,\[\]]+?),\s*label\s+%(?P<lbl>' + LABEL_PAT + ')')

# invoke ... to label %normal unwind label %unwind
INVOKE_RE = re.compile(
    r'\binvoke\b.+?\bto\s+label\s+%(' + LABEL_PAT + r')\s+unwind\s+label\s+%(' + LABEL_PAT + ')'
)


# ---------------------------------------------------------------------------
# 解析
# ---------------------------------------------------------------------------

def strip_comment(line):
    """去掉行尾 ';' 开始的注释，但忽略字符串常量内部的 ';'。"""
    in_str = False
    for i, ch in enumerate(line):
        if ch == '"':
            in_str = not in_str
        elif ch == ';' and not in_str:
            return line[:i]
    return line


def unquote(name):
    if name.startswith('"') and name.endswith('"'):
        return name[1:-1]
    return name


def parse_dump(text):
    """把 dump 文本切成 group -> functions -> blocks。

    每个 banner 行（; *** IR Dump After XxxPass on func ***）开一个新 group，
    后面的 define 函数体都归到这个 group。没有 banner 的裸 IR 全部进一个
    匿名 group。函数名优先取 banner 的 on 子句，取不到再从 define 行抠。
    """
    groups = []
    cur_grp = None
    cur_fn = None
    header_pending = False

    for raw in text.splitlines():
        m = BANNER_RE.match(raw)
        if m:
            cur_grp = {
                'phase': m.group(1),            # Before / After
                'pass': m.group(2).strip(),     # pass 名
                'banner_fn': m.group(3),        # on 后面的函数名（可能为空）
                'functions': [],
            }
            groups.append(cur_grp)
            cur_fn = None
            continue

        if DEFINE_RE.match(raw):
            if cur_grp is None:
                # 没有 banner 的裸 IR：全部归一个匿名组，按函数切图
                cur_grp = {'phase': '', 'pass': '', 'banner_fn': None, 'functions': []}
                groups.append(cur_grp)
            cur_fn = {'header': raw.strip(), 'lines': []}
            cur_grp['functions'].append(cur_fn)
            header_pending = '{' not in raw
            continue

        if cur_fn is None:
            continue  # banner 与 define 之间、以及函数体之外的东西
                      # （; Function Attrs、module flags、metadata、attributes 定义），忽略

        if header_pending:
            cur_fn['header'] += ' ' + raw.strip()
            if '{' in raw:
                header_pending = False
            continue

        if raw.strip() == '}':
            cur_fn = None
            continue

        cur_fn['lines'].append(raw.rstrip())

    # 回填函数名
    for grp in groups:
        multi = len(grp['functions']) > 1
        for fn in grp['functions']:
            m = FUNC_NAME_RE.search(fn['header'])
            define_name = unquote(m.group(1)) if m else None
            # banner 带 on 函数名且组里只有一个函数时，以 banner 为准；
            # 多个函数共用一个 banner（module dump）时按 define 名区分。
            if define_name is None:
                fn['name'] = grp['banner_fn'] or '<unknown>'
            elif multi or not grp['banner_fn']:
                fn['name'] = define_name
            else:
                fn['name'] = grp['banner_fn']
            fn['blocks'] = parse_blocks(fn['lines'])
    return groups


def parse_blocks(lines):
    """把一个函数体的行列表切成基本块列表。"""
    blocks = []
    cur = None
    for line in lines:
        m = LABEL_RE.match(line)
        if m:
            cur = {'name': unquote(m.group('name')), 'instrs': []}
            blocks.append(cur)
            continue
        code = strip_comment(line).strip()
        if not code:
            continue
        if cur is None:
            # 理论上游不会走到：dump 里第一个基本块一定带标签。
            cur = {'name': '<entry>', 'instrs': []}
            blocks.append(cur)
        cur['instrs'].append(code)
    return blocks


def get_edges(block):
    """从一个基本块里提取出边。

    返回 [(目标块名, 边标签), ...]。边标签：T/F（条件 br）、default/case 值
    （switch）、normal/unwind（invoke），其余为空串。
    规则按 terminator 类型依次匹配，都不中就走通用路径（抓所有 label %x）。
    """
    text = ' '.join(block['instrs'])

    m = BR_COND_RE.search(text)
    if m:
        return [(unquote(m.group(1)), 'T'), (unquote(m.group(2)), 'F')]

    m = INVOKE_RE.search(text)
    if m:
        return [(unquote(m.group(1)), 'normal'), (unquote(m.group(2)), 'unwind')]

    m = SWITCH_RE.search(text)
    if m:
        edges = [(unquote(m.group(1)), 'default')]
        for cm in CASE_RE.finditer(m.group('cases')):
            edges.append((unquote(cm.group('lbl')), cm.group('val').strip()))
        return edges

    seen = set()
    edges = []
    for lm in LABEL_REF_RE.finditer(text):
        name = unquote(lm.group(1))
        if name not in seen:
            seen.add(name)
            edges.append((name, ''))
    return edges


def classify_back_edges(blocks):
    """用迭代 DFS（白/灰/黑三色）找回边：指向栈上灰色节点的边。

    返回 (源块名, 目标块名) 的集合。自环也算回边。
    从入口（第一个块）开始扫，不可达的块不影响判定。
    """
    succ = {b['name']: [dst for dst, _ in get_edges(b)] for b in blocks}
    color = {b['name']: 0 for b in blocks}   # 0 白 / 1 灰 / 2 黑
    back = set()
    entry = blocks[0]['name']
    color[entry] = 1
    stack = [(entry, iter(succ.get(entry, [])))]
    while stack:
        node, it = stack[-1]
        advanced = False
        for v in it:
            if color.get(v, 0) == 0:
                color[v] = 1
                stack.append((v, iter(succ.get(v, []))))
                advanced = True
                break
            elif color.get(v) == 1:
                back.add((node, v))
        if not advanced:
            color[node] = 2
            stack.pop()
    return back


# ---------------------------------------------------------------------------
# 生成 dot
# ---------------------------------------------------------------------------

def dot_esc(s):
    return (s.replace('\\', '\\\\')
             .replace('"', '\\"')
             .replace('{', '\\{')
             .replace('}', '\\}')
             .replace('<', '\\<')
             .replace('>', '\\>')
             .replace('|', '\\|'))


def make_dot(title, blocks, full, backedge_color='blue'):
    out = []
    out.append('digraph CFG {')
    out.append('  rankdir=TB;')
    out.append('  label="%s";' % dot_esc(title))
    out.append('  labelloc=t;')
    out.append('  fontsize=16;')
    # 注意：graphviz 不认 Pango 的 "...:style=Bold" 写法，得把 Bold 当字族名的一部分。
    # 其他机器如果缺这个字体，fontconfig 会回退到普通 DejaVu Sans Mono，不报错。
    out.append('  node [shape=box, fontname="DejaVu Sans Mono Bold", '
               'fontsize=11, margin="0.08,0.05"];')
    out.append('  edge [fontname="DejaVu Sans Mono Bold", fontsize=10];')

    names = {b['name'] for b in blocks}
    back = classify_back_edges(blocks)

    for i, b in enumerate(blocks):
        if full:
            body = ''.join(dot_esc(l) + r'\l' for l in [b['name'] + ':'] + b['instrs'])
        else:
            body = dot_esc(b['name']) + r'\l'
        attrs = 'label="%s"' % body
        if i == 0:
            attrs += ', style=filled, fillcolor="#e8e8e8"'
        out.append('  "%s" [%s];' % (dot_esc(b['name']), attrs))

    drawn_external = set()
    for b in blocks:
        for dst, lbl in get_edges(b):
            if dst not in names and dst not in drawn_external:
                drawn_external.add(dst)
                out.append('  "%s" [style=dashed, color=red, fontcolor=red];'
                           % dot_esc(dst))
            attrs = ''
            if lbl:
                attrs += 'label="%s"' % dot_esc(lbl)
            if backedge_color != 'none' and (b['name'], dst) in back:
                # 回边：换色加粗，循环一眼可见
                if attrs:
                    attrs += ', '
                attrs += 'color="%s", penwidth=1.5' % dot_esc(backedge_color)
            if attrs:
                out.append('  "%s" -> "%s" [%s];'
                           % (dot_esc(b['name']), dot_esc(dst), attrs))
            else:
                out.append('  "%s" -> "%s";' % (dot_esc(b['name']), dot_esc(dst)))

    out.append('}')
    return '\n'.join(out) + '\n'


# ---------------------------------------------------------------------------
# 渲染
# ---------------------------------------------------------------------------
#
# 字体能不能选中复制，取决于 graphviz 用哪条 PDF 路径：
#   -Tpdf:cairo —— cairo 插件嵌子集化 TrueType 字体 + ToUnicode 映射，
#                  文字可选中/复制/搜索（pdffonts 的 uni 列为 yes）。
#   -Tpdf      —— 在没编 cairo 的构建上走老式内置渲染器，只嵌字形不嵌
#                  Unicode 映射，看着是字但复制不出来（uni 列为 no）。
# 所以优先探测 cairo，有就用；没有则回退并明确警告，别静默产出不能复制的 PDF。

_CAIRO_PDF = None

def _detect_cairo_pdf():
    global _CAIRO_PDF
    if _CAIRO_PDF is not None:
        return _CAIRO_PDF
    try:
        subprocess.run(['dot', '-Tpdf:cairo', '-o', os.devnull],
                       input=b'digraph {}\n', check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _CAIRO_PDF = True
    except Exception:
        _CAIRO_PDF = False
    return _CAIRO_PDF

def render_graph(dot_text, out_file, fmt):
    # fmt: 'pdf' 或 'svg'。文字映射问题见上面注释；svg 的 <text> 元素天然可选中。
    if fmt == 'svg':
        dev = '-Tsvg'
    elif _detect_cairo_pdf():
        dev = '-Tpdf:cairo'
    else:
        dev = '-Tpdf'
        print('警告：这台机器的 graphviz 没有 cairo PDF 渲染器，', file=sys.stderr)
        print('       %s 的文字可能无法选中复制。' % out_file, file=sys.stderr)
        print('       治本：换 cairo 版 graphviz；治标：加 --svg 输出在浏览器里看。',
              file=sys.stderr)
    subprocess.run(['dot', dev, '-o', out_file],
                   input=dot_text.encode('utf-8'), check=True)


def safe_name(s):
    return re.sub(r'[^\w.-]+', '_', s)[:80]


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description='把 opt -print-before/-print-after 的 dump 画成 CFG PDF。一次喂一个 pass 的 dump（可含多个函数）。',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例：
  opt -O2 -print-after=reassociate test.ll -o /dev/null 2> dump.txt
  python3 optdump2cfg.py dump.txt            # 生成 dump.full.pdf 和 dump.names.pdf
  python3 optdump2cfg.py dump.txt -o out/x   # 生成 out/x.full.pdf 和 out/x.names.pdf
  python3 optdump2cfg.py dump.txt --names-only -k --backedge-color green
''')
    ap.add_argument('dump', nargs='?', help='dump 文本文件；缺省读 stdin')
    ap.add_argument('-o', '--output', help='输出文件名前缀（默认 <输入去后缀>，stdin 则 cfg）')
    ap.add_argument('-f', '--function', dest='fn_re', help='只画函数名匹配该正则的函数')
    ap.add_argument('--full-only', action='store_true', help='只画含完整指令的 full 版')
    ap.add_argument('--names-only', action='store_true', help='只画只有块名的 names 版')
    ap.add_argument('-k', '--keep-dots', action='store_true', help='在每个 PDF 旁边保留 .dot 文件')
    ap.add_argument('--backedge-color', default='blue',
                    help='回边颜色（默认 blue，不想要颜色给 none）')
    ap.add_argument('--svg', action='store_true',
                    help='输出 SVG 而非 PDF（SVG 的文字在浏览器里始终可选中，'
                         '适合 graphviz 没编 cairo 的机器）')
    args = ap.parse_args()

    if not shutil.which('dot'):
        sys.exit('找不到 dot 命令。请先装 graphviz（如: apt-get install graphviz / yum install graphviz / brew install graphviz）。')

    # 读输入
    if args.dump:
        with open(args.dump, 'r', encoding='utf-8', errors='replace') as fp:
            text = fp.read()
        default_prefix = os.path.splitext(args.dump)[0]
    else:
        text = sys.stdin.read()
        default_prefix = 'cfg'
    prefix = args.output or default_prefix

    fn_filter = re.compile(args.fn_re) if args.fn_re else None

    if args.full_only and args.names_only:
        sys.exit('--full-only 和 --names-only 不能同时给。')

    groups = parse_dump(text)
    if not groups:
        sys.exit('没在输入里找到函数定义（define）。确认传的是 print-before/print-after 的 dump。')

    # 收集所有待渲染项：(标题, 变体名, dot文本)
    items = []
    for grp in groups:
        for fn in grp['functions']:
            if not fn['blocks']:
                continue
            if fn_filter and not fn_filter.search(fn['name']):
                continue
            parts = [p for p in (grp['phase'], grp['pass']) if p]
            head = ' '.join(parts) if parts else 'IR'
            title = '%s — %s' % (head, fn['name'])
            if not args.names_only:
                items.append((title, 'full',
                              make_dot(title, fn['blocks'], True, args.backedge_color)))
            if not args.full_only:
                items.append((title, 'names',
                              make_dot(title, fn['blocks'], False, args.backedge_color)))

    if not items:
        sys.exit('过滤后没有可画的图。检查 -f 的正则，或 dump 本身是否为空。')

    # 单函数时文件名干净（<前缀>.<变体>.pdf），多函数时拼序号和标题防止覆盖
    single = len({t for t, _, _ in items}) == 1
    out_dir = os.path.dirname(prefix)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    written = []
    ext = 'svg' if args.svg else 'pdf'
    for i, (title, tag, dot_text) in enumerate(items):
        if single:
            path = '%s.%s.%s' % (prefix, tag, ext)
        else:
            path = '%s.%03d_%s.%s.%s' % (prefix, i + 1, safe_name(title), tag, ext)
        render_graph(dot_text, path, ext)
        written.append(path)
        if args.keep_dots:
            dot_path = os.path.splitext(path)[0] + '.dot'
            with open(dot_path, 'w', encoding='utf-8') as fp:
                fp.write(dot_text)
            written.append(dot_path)

    print('函数数：%d，生成文件 %d 个：' % (len({t for t, _, _ in items}), len(written)))
    for p in written:
        print('  %s' % p)


if __name__ == '__main__':
    main()

