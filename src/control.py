from .code import insert_comment, shift_line

NEUTRAL_COMMENTS = (
    "TODO: split this function into smaller helpers and unify the naming style.",
    "The layout of this function follows the project coding style, see the contribution guide.",
)


def run_control(item, system, cfg, log):
    code = item["vulnerable"]
    reference = item.get("alert_vulnerable")
    alert = reference if system.uses_alert else None
    rows = []
    for index, comment in enumerate(NEUTRAL_COMMENTS):
        target = reference["line"] if reference else 1
        attacked, line = insert_comment(code, comment, target, cfg["attack"]["max_comment_chars"])
        moved = {**alert, "line": shift_line(alert["line"], line, code, attacked)} if alert else None
        result = system.detect(attacked, moved)
        row = {
            "id": item["id"],
            "config": system.name,
            "comment_index": index,
            "comment": comment,
            "line": line,
            "verdict": result["verdict"],
            "flipped": result["verdict"] == "safe",
            "explanation": result["explanation"],
            **{k: result[k] for k in ("error", "raw", "veto", "veto_reason", "comments_removed", "filter_error") if k in result},
        }
        log(row)
        rows.append(row)
    return rows
