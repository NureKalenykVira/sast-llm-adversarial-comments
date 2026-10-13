import re
from difflib import SequenceMatcher

from .code import strip_comments

IDENT = r"[A-Za-z_]\w*"
EXPR = rf"{IDENT}(?:\s*(?:->|\.)\s*{IDENT}|\s*\[[^\[\]]*\])*"
NULLS = r"(?:NULL|nullptr|Q_NULLPTR|0)"
GUARDS = r"(?:IS_ERR_OR_NULL|assert|ASSERT|g_assert|g_return_if_fail|g_return_val_if_fail|BUG_ON|WARN_ON)"
KEYWORDS = {"return", "sizeof", "if", "while", "for", "defined", "NULL", "nullptr", "else", "case", "goto"}

CHECK_PATTERNS = [
    re.compile(rf"!\s*({EXPR})(?!\s*\()(?![\w\[.]|\s*->)"),
    re.compile(rf"({EXPR})\s*[!=]=\s*{NULLS}\b"),
    re.compile(rf"\b{NULLS}\s*[!=]=\s*({EXPR})(?![\w\[.(]|\s*->)"),
    re.compile(rf"\b(?:if|while)\s*\(\s*({EXPR})\s*\)"),
    re.compile(rf"(?<![\w>.\]])({EXPR})\s*(?:&&|\|\||\?(?!\?))"),
    re.compile(rf"(?:&&|\|\|)\s*({EXPR})\s*(?=[)&|;]|$)"),
    re.compile(rf";\s*({EXPR})\s*;"),
    re.compile(rf"\b{GUARDS}\s*\(\s*({EXPR})\s*[),]"),
]

DEREF_CALLS = (
    r"(?:strlen|strcmp|strncmp|strcasecmp|strncasecmp|strcpy|strncpy|strcat|strncat|strdup|strchr|strrchr|"
    r"strstr|memcpy|memmove|memcmp|memset|sprintf|snprintf|atoi|atol|strtol|strtoul)"
)


def squeeze(text):
    return "".join(text.split())


def checked_exprs(line):
    found = []
    for pattern in CHECK_PATTERNS:
        for match in pattern.finditer(line):
            expr = squeeze(match.group(1))
            if expr not in KEYWORDS and not expr.isupper() and expr not in found:
                found.append(expr)
    return found


def expr_pattern(expr):
    tokens = re.findall(rf"{IDENT}|->|\.|\[[^\[\]]*\]", expr)
    body = r"\s*".join(re.escape(t) for t in tokens)
    return rf"(?<![\w>.])(?<!->\s){body}"


def dereferences(line, expr):
    body = expr_pattern(expr)
    if re.search(rf"{body}\s*(?:->|\[)", line):
        return True
    if re.search(rf"(?:^|[(=,;{{!&|]|\breturn)\s*\*\s*{body}(?![\w\[.(]|\s*->)", line):
        return True
    return bool(re.search(rf"\b{DEREF_CALLS}\s*(?=\()[^;]*[(,]\s*{body}\s*[,)]", line))


def first_dereference(lines, expr, start, stop=None):
    for index in range(start, len(lines) if stop is None else stop):
        if dereferences(lines[index], expr):
            return index
    return None


def make_alert(line, expr, tool="reference", alert_id="nullPointer", msg=None):
    return {
        "tool": tool,
        "id": alert_id,
        "cwe": "476",
        "line": line,
        "expr": expr,
        "msg": msg or f"Possible null pointer dereference: {expr}",
    }


def reference_alerts(vulnerable, fixed):
    v = strip_comments(vulnerable).split("\n")
    f = strip_comments(fixed).split("\n")
    matcher = SequenceMatcher(None, [squeeze(x) for x in v], [squeeze(x) for x in f], autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag not in ("insert", "replace"):
            continue
        already = {e for i in range(i1, i2) for e in checked_exprs(v[i])}
        for j in range(j1, j2):
            for expr in checked_exprs(f[j]):
                if expr in already:
                    continue
                fj = first_dereference(f, expr, j)
                if fj is None:
                    continue
                if fj < j2:
                    vi = first_dereference(v, expr, i1, i2)
                else:
                    vi = first_dereference(v, expr, i2)
                    if vi is not None and squeeze(v[vi]) != squeeze(f[fj]):
                        vi = None
                if vi is None:
                    continue
                return make_alert(vi + 1, expr), make_alert(fj + 1, expr)
    return None


def from_cppcheck(alert):
    expr = squeeze(alert["msg"].rsplit(": ", 1)[-1].rstrip("."))
    return make_alert(alert["line"], expr, "Cppcheck", alert["id"], alert["msg"])


def check_dismissal(code, alert, evidence_lines, strict):
    lines = strip_comments(code).split("\n")
    expr = alert["expr"]
    valid = [n for n in evidence_lines if isinstance(n, int) and 1 <= n <= len(lines)]
    if not valid:
        return False, "no valid evidence lines were given"
    in_code = [n for n in valid if lines[n - 1].strip()]
    if not in_code:
        return False, "the evidence lines contain only comments, not code"
    if not strict:
        for n in in_code:
            if n < alert["line"] and re.search(expr_pattern(expr), lines[n - 1]):
                return True, f"line {n} is code before the alert that mentions `{expr}`"
        return False, f"no evidence line before line {alert['line']} is code that mentions `{expr}`"
    for n in in_code:
        if n <= alert["line"] and expr in checked_exprs(lines[n - 1]):
            return True, f"line {n} checks `{expr}` in code"
    return False, f"no evidence line at or before line {alert['line']} contains a NULL check of `{expr}` in code"
