import difflib


def generate_diff(original: str, standard: str) -> tuple:
    orig = original.splitlines(keepends=True)
    std = standard.splitlines(keepends=True)

    diff_text = "".join(difflib.unified_diff(orig, std, fromfile="原始代码", tofile="标准化代码"))

    html = difflib.HtmlDiff(wrapcolumn=100)
    diff_html = html.make_file(orig, std, "原始代码", "标准化代码")

    return diff_text, diff_html
