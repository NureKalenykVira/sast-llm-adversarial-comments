import json
import random

from . import sast
from .alerts import from_cppcheck, reference_alerts
from .config import resolve

FIELDS = ("cve_id", "cwe_ids", "repo_name", "commit_hash", "file_path", "func_name")


def write_jsonl(path, rows):
    with open(resolve(path), "w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_items(path, limit=None):
    with open(resolve(path), encoding="utf-8") as f:
        items = [json.loads(line) for line in f if line.strip()]
    return items[:limit] if limit else items


def extract_pairs(cfg):
    d = cfg["data"]
    with open(resolve(d["megavul_path"]), encoding="utf-8") as f:
        records = json.load(f)
    seen, pairs = set(), []
    for r in records:
        if not r.get("is_vul") or d["cwe"] not in (r.get("cwe_ids") or []):
            continue
        vulnerable, fixed = r.get("func_before"), r.get("func")
        if not vulnerable or not fixed or vulnerable == fixed or vulnerable in seen:
            continue
        seen.add(vulnerable)
        pairs.append({**{k: r.get(k) for k in FIELDS}, "vulnerable": vulnerable, "fixed": fixed})
    pairs.sort(key=lambda p: (p["cve_id"] or "", p["func_name"] or "", p["vulnerable"]))
    write_jsonl(d["pairs_path"], pairs)
    return pairs


def cppcheck_alert(cfg, code, file_path):
    alerts = [a for a in sast.scan(cfg, code, file_path) if sast.is_null_alert(a) and a["line"]]
    return from_cppcheck(alerts[0]) if alerts else None


def prepare(cfg):
    d = cfg["data"]
    pairs = load_items(d["pairs_path"]) if resolve(d["pairs_path"]).exists() else extract_pairs(cfg)
    in_range = [p for p in pairs if d["min_lines"] <= len(p["vulnerable"].splitlines()) <= d["max_lines"]]

    candidates = []
    for p in in_range:
        found = reference_alerts(p["vulnerable"], p["fixed"])
        if found:
            candidates.append({**p, "alert_vulnerable": found[0], "alert_fixed": found[1]})
    sample = random.Random(cfg["seed"]).sample(candidates, min(d["n_main"], len(candidates)))
    for i, item in enumerate(sample):
        item["id"] = f"{d['cwe']}-{i:03d}"
    write_jsonl(d["main_path"], sample)
    write_jsonl(d["pilot_path"], sample[: d["n_pilot"]])
    stats = {
        "pairs": len(pairs),
        "pairs_in_line_range": len(in_range),
        "with_reference_alert": len(candidates),
        "main_sample": len(sample),
        "pilot_sample": min(d["n_pilot"], len(sample)),
    }

    try:
        sast.cppcheck_exe(cfg)
    except FileNotFoundError as error:
        stats["cppcheck_subset"] = f"skipped: {error}"
        return stats
    subset = []
    for p in in_range:
        alert = cppcheck_alert(cfg, p["vulnerable"], p["file_path"])
        if alert and cppcheck_alert(cfg, p["fixed"], p["file_path"]) is None:
            subset.append({**p, "alert_vulnerable": alert, "alert_fixed": None, "id": f"CPPCHECK-{len(subset):03d}"})
    write_jsonl(d["cppcheck_path"], subset)
    stats["cppcheck_subset"] = len(subset)
    return stats
