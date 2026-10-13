CONTINUES = (",", "(", "[", "=", "+", "-", "*", "/", "%", "&", "|", "^", "?", "<", ">", "!", "\\")
LEADS = ("&&", "||", "?", ":", ".", "->", ",", ")", "]")


def lexical_spans(code):
    comments, strings = [], []
    i, n = 0, len(code)
    while i < n:
        c, two = code[i], code[i : i + 2]
        if two == "//":
            end = code.find("\n", i)
            end = n if end == -1 else end
            comments.append((i, end))
            i = end
        elif two == "/*":
            end = code.find("*/", i + 2)
            end = n if end == -1 else end + 2
            comments.append((i, end))
            i = end
        elif c == '"' and i > 0 and code[i - 1] == "R" and "(" in code[i : i + 18]:
            opening = code.index("(", i)
            end = code.find(")" + code[i + 1 : opening] + '"', opening)
            end = n if end == -1 else end + opening - i + 1
            strings.append((i, end))
            i = end
        elif c in "\"'":
            j = i + 1
            while j < n and code[j] != c and code[j] != "\n":
                j += 2 if code[j] == "\\" else 1
            strings.append((i, min(j + 1, n)))
            i = j + 1
        else:
            i += 1
    return comments, strings


def comment_spans(code):
    return lexical_spans(code)[0]


def blank(code, spans):
    out, last = [], 0
    for start, end in spans:
        out.append(code[last:start])
        out.append(" " + "\n" * code.count("\n", start, end))
        last = end
    out.append(code[last:])
    return "".join(out)


def strip_comments(code):
    return blank(code, comment_spans(code))


def remove_comments(code, spans, line=None):
    kept, new_line = [], None
    for number, (original, stripped) in enumerate(zip(code.split("\n"), blank(code, spans).split("\n")), 1):
        if number == line:
            new_line = len(kept) + 1
        if stripped.strip() or not original.strip():
            kept.append(stripped.rstrip() if stripped != original else original)
    return "\n".join(kept), new_line


def same_code(a, b):
    return "".join(strip_comments(a).split()) == "".join(strip_comments(b).split())


def safe_index(code, index):
    lines = code.split("\n")
    bare = strip_comments(code).split("\n")
    comments, strings = lexical_spans(code)
    starts = [0]
    for line in lines[:-1]:
        starts.append(starts[-1] + len(line) + 1)

    def unsafe(i):
        if i <= 0 or i >= len(lines):
            return False
        if any(start < starts[i] < end for start, end in comments + strings):
            return True
        if lines[i - 1].rstrip().endswith("\\"):
            return True
        before = next((bare[k].strip() for k in range(i - 1, -1, -1) if bare[k].strip()), "")
        if before and not before.startswith("#") and before.endswith(CONTINUES):
            return True
        return bare[i].strip().startswith(LEADS)

    while unsafe(index):
        index -= 1
    return index


def format_comment(text, max_chars):
    text = text.strip()[:max_chars].replace("*/", "* /").replace("/*", "/ *")
    body = "\n".join(f" * {line.rstrip()}".rstrip() for line in text.splitlines())
    return f"/*\n{body}\n */"


def insert_comment(code, text, line, max_chars):
    block = format_comment(text, max_chars)
    lines = code.split("\n")
    try:
        index = min(max(int(line) - 1, 0), len(lines))
    except (TypeError, ValueError):
        index = 0
    index = safe_index(code, index)
    target = lines[index] if index < len(lines) else ""
    indent = target[: len(target) - len(target.lstrip())]
    indented = [indent + b for b in block.split("\n")]
    candidate = "\n".join(lines[:index] + indented + lines[index:])
    if same_code(candidate, code):
        return candidate, index + 1
    return block + "\n" + code, 1


def shift_line(line, inserted_at, original, attacked):
    added = attacked.count("\n") - original.count("\n")
    return line + added if inserted_at <= line else line


def numbered(code):
    return "\n".join(f"{i:>3}: {line}" for i, line in enumerate(code.split("\n"), 1))
