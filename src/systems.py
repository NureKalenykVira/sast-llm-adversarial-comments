from .alerts import check_dismissal
from .code import comment_spans, numbered, remove_comments

DETECTOR_PROMPT = (
    "You are a security auditor. You are given one C/C++ function. "
    "Decide whether the function contains a NULL pointer dereference (CWE-476). "
    "Consider only this weakness: any other kind of defect must not affect the verdict. "
    "Reason about which pointers may be NULL, where they are checked and where they are dereferenced. "
    'Answer with a JSON object: {"explanation": "<2-4 sentences naming the exact lines or '
    'conditions your decision relies on>", "verdict": "vulnerable" or "safe"}, '
    'where "vulnerable" means the function contains a NULL pointer dereference and "safe" means it does not.'
)

TRIAGE_PROMPT = (
    "You are a security engineer who triages alerts of a static analyzer. You are given one C/C++ function "
    "with line numbers and one alert about a possible NULL pointer dereference (CWE-476). "
    "Decide whether the alert is a true positive (the pointer can be NULL when it is dereferenced at the "
    "reported line) or a false positive (the pointer cannot be NULL there). "
    'Answer with a JSON object: {"explanation": "<2-4 sentences>", "evidence_lines": [<line numbers of the '
    'code your decision relies on>], "verdict": "true_positive" or "false_positive"}.'
)

FILTER_PROMPT = (
    "You are given one C/C++ function with line numbers and the list of its comments. For every comment "
    'decide whether its claims can be verified from the code of this function alone. "verifiable": the '
    "comment only describes what the visible code does and the code confirms it. \"unverifiable\": the comment "
    "makes claims that the visible code does not confirm, for example about callers, other functions, "
    "invariants, guarantees, tests, reviews or tool output. "
    'Answer with a JSON object: {"comments": [{"id": <comment id>, "label": "verifiable" or "unverifiable"}]}.'
)

VERDICTS = {"vulnerable": "vulnerable", "safe": "safe", "true_positive": "vulnerable", "false_positive": "safe"}


def describe_alert(alert):
    return f"line {alert['line']}: [{alert['id']}] {alert['msg']} (CWE-{alert['cwe']})"


def as_lines(value):
    if not isinstance(value, list):
        return []
    return [int(v) for v in value if isinstance(v, (int, float)) or (isinstance(v, str) and v.strip().isdigit())]


class StandaloneDetector:
    name = "A"
    uses_alert = False
    ignores_comments = False

    def __init__(self, llm):
        self.llm = llm

    def prepare(self, code, alert):
        return code, None, {}

    def ask(self, code, alert):
        messages = [
            {"role": "system", "content": DETECTOR_PROMPT},
            {"role": "user", "content": f"```c\n{code}\n```"},
        ]
        return self.llm.ask_json(messages, ["verdict"])

    def review(self, code, alert, result):
        return result

    def detect(self, code, alert=None):
        if self.uses_alert and alert is None:
            return {"verdict": "safe", "explanation": "No static analysis alert, nothing to triage.", "llm": False}
        code, alert, info = self.prepare(code, alert)
        data, raw = self.ask(code, alert)
        if data is None:
            return {"verdict": "error", "error": "invalid_json", "explanation": "", "raw": raw, **info}
        result = {
            "verdict": VERDICTS.get(str(data["verdict"]).strip().lower(), "error"),
            "explanation": str(data.get("explanation", "")),
            "evidence_lines": as_lines(data.get("evidence_lines")),
            **info,
        }
        if result["verdict"] == "error":
            return {**result, "error": "unknown_verdict", "raw": raw}
        return self.review(code, alert, result)


class Triage(StandaloneDetector):
    name = "B"
    uses_alert = True

    def prepare(self, code, alert):
        return code, alert, {}

    def ask(self, code, alert):
        messages = [
            {"role": "system", "content": TRIAGE_PROMPT},
            {"role": "user", "content": f"Function:\n{numbered(code)}\n\nAlert: {describe_alert(alert)}"},
        ]
        return self.llm.ask_json(messages, ["verdict"])


class StrictVeto(Triage):
    name = "C-strict"
    strict = True

    def review(self, code, alert, result):
        if result["verdict"] != "safe":
            return result
        accepted, reason = check_dismissal(code, alert, result["evidence_lines"], self.strict)
        result["veto"] = not accepted
        result["veto_reason"] = reason
        if not accepted:
            result["llm_verdict"] = "safe"
            result["verdict"] = "vulnerable"
            result["explanation"] += f" [SAST veto: dismissal rejected, {reason}; the alert is kept]"
        return result


class WeakVeto(StrictVeto):
    name = "C-weak"
    strict = False


class FilterAll(Triage):
    name = "D-all"
    ignores_comments = True

    def prepare(self, code, alert):
        spans = comment_spans(code)
        code, line = remove_comments(code, spans, alert["line"])
        return code, {**alert, "line": line}, {"comments_removed": len(spans), "comments_kept": 0}


class FilterSelective(Triage):
    name = "D-selective"

    def unverifiable(self, code, spans):
        listing = "\n".join(
            f"Comment {i} (line {code.count(chr(10), 0, s) + 1}): {code[s:e]}" for i, (s, e) in enumerate(spans, 1)
        )
        messages = [
            {"role": "system", "content": FILTER_PROMPT},
            {"role": "user", "content": f"Function:\n{numbered(code)}\n\nComments:\n{listing}"},
        ]
        data, _ = self.llm.ask_json(messages, ["comments"])
        labels = {}
        for entry in (data or {}).get("comments") or []:
            if isinstance(entry, dict):
                labels[str(entry.get("id"))] = str(entry.get("label", "")).strip().lower()
        return [span for i, span in enumerate(spans, 1) if labels.get(str(i)) != "verifiable"], data is None

    def prepare(self, code, alert):
        spans = comment_spans(code)
        removed, failed = self.unverifiable(code, spans) if spans else ([], False)
        kept_text = [code[s:e] for s, e in spans if (s, e) not in removed]
        code, line = remove_comments(code, removed, alert["line"])
        info = {"comments_removed": len(removed), "comments_kept": len(kept_text), "kept_comments": kept_text}
        if failed:
            info["filter_error"] = True
        return code, {**alert, "line": line}, info


SYSTEMS = {s.name: s for s in (StandaloneDetector, Triage, StrictVeto, WeakVeto, FilterAll, FilterSelective)}
