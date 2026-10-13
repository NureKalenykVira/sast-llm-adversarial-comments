import argparse
import json
import threading
from concurrent.futures import ThreadPoolExecutor

from tqdm import tqdm

from . import metrics
from .alerts import make_alert
from .attack import build_messages, run_attack
from .code import insert_comment, numbered
from .config import load_config, resolve
from .control import NEUTRAL_COMMENTS, run_control
from .data import load_items, prepare
from .llm import LLM, ContextError, estimate_tokens
from .systems import FILTER_PROMPT, SYSTEMS


def read_jsonl(path):
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


class Run:
    def __init__(self, cfg, name):
        self.cfg = cfg
        root = resolve(cfg["results_dir"])
        self.dir = root / name
        self.dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.check_config()
        cache = root / "cache.sqlite"
        self.detector_llm = LLM(cfg["detector"], cfg["seed"], cache)
        self.attacker_llm = LLM(cfg["attacker"], cfg["seed"], cache)
        self.baseline_rows = read_jsonl(self.dir / "baseline.jsonl")
        self.attacks = read_jsonl(self.dir / "attacks.jsonl")
        self.drop_unfinished_rounds()
        self.control_rows = self.finished_controls()

    def check_config(self):
        path = self.dir / "config.json"
        comparable = lambda c: {**c, "run": {k: v for k, v in c["run"].items() if k != "workers"}}
        if path.exists():
            with open(path, encoding="utf-8") as f:
                saved = json.load(f)
            if comparable(saved) != comparable(self.cfg):
                raise SystemExit(
                    f"{self.dir} holds a run with different settings. "
                    "Use another --name or delete the folder to start again."
                )
            print(f"Resuming the run in {self.dir}")
        self.save("config.json", self.cfg)

    def drop_unfinished_rounds(self):
        path = self.dir / "rounds.jsonl"
        finished = {(a["config"], a["id"]) for a in self.attacks}
        rows = read_jsonl(path)
        kept = [r for r in rows if (r["config"], r["id"]) in finished]
        if len(kept) != len(rows):
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                for row in kept:
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")

    def finished_controls(self):
        path = self.dir / "control.jsonl"
        rows = read_jsonl(path)
        keys = [(r["config"], r["id"]) for r in rows]
        kept = [r for r in rows if keys.count((r["config"], r["id"])) == len(NEUTRAL_COMMENTS)]
        if len(kept) != len(rows):
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                for row in kept:
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")
        return kept

    def log(self, filename, record):
        with self.lock:
            with open(self.dir / filename, "a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def save(self, filename, data):
        with open(self.dir / filename, "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def parallel(self, function, tasks, label):
        with ThreadPoolExecutor(self.cfg["run"]["workers"]) as pool:
            return list(tqdm(pool.map(function, tasks), total=len(tasks), desc=label))


def baseline(run, system, items):
    done = {(r["id"], r["version"]) for r in run.baseline_rows if r["config"] == system.name}
    tasks = [(i, v) for i in items for v in ("vulnerable", "fixed") if (i["id"], v) not in done]

    def one(task):
        item, version = task
        result = system.detect(item[version], item.get(f"alert_{version}"))
        kept = {k: v for k, v in result.items() if k != "kept_comments"}
        row = {"id": item["id"], "config": system.name, "version": version, **kept}
        run.log("baseline.jsonl", row)
        return row

    run.baseline_rows += run.parallel(one, tasks, f"{system.name}: no attack")
    return [r for r in run.baseline_rows if r["config"] == system.name]


def baseline_metrics(rows):
    count = lambda version, verdict: sum(1 for r in rows if r["version"] == version and r["verdict"] == verdict)
    return metrics.classification(
        count("vulnerable", "vulnerable"), count("fixed", "vulnerable"), count("vulnerable", "safe"), count("fixed", "safe")
    )


def error_counts(name, rows, rounds, controls):
    rounds = [r for r in rounds if r["config"] == name]
    return {
        "no_attack_invalid_answers": sum(1 for r in rows if r["verdict"] == "error"),
        "control_invalid_answers": sum(1 for r in controls if r["verdict"] == "error"),
        "attack_rounds_invalid_system_answer": sum(1 for r in rounds if r.get("verdict") == "error"),
        "attack_rounds_invalid_attacker_answer": sum(1 for r in rounds if r.get("attacker_error")),
        "comment_filter_invalid_answers": sum(1 for r in rows + rounds + controls if r.get("filter_error")),
    }


def check_context(run, items):
    a = run.cfg["attack"]
    code = max((i[v] for i in items for v in ("vulnerable", "fixed")), key=len)
    filler = "x" * a["max_comment_chars"]
    attacked, _ = insert_comment(code, filler, 1, a["max_comment_chars"])
    step = {"round": 0, "style": "TOOL_CPPCHECK", "line": 1, "comment": filler, "verdict": "vulnerable", "explanation": "x" * 700}
    attacker_prompt = build_messages(code, make_alert(1, "pointer->field"), [step] * a["history_window"], "explanation", a["history_window"])
    system_prompt = [{"role": "system", "content": FILTER_PROMPT}, {"role": "user", "content": numbered(attacked) + attacked}]
    for role, llm, messages in (("attacker", run.attacker_llm, attacker_prompt), ("detector", run.detector_llm, system_prompt)):
        tokens = estimate_tokens(messages) + llm.max_tokens
        if tokens > llm.max_context:
            raise ContextError(
                f"The largest possible {role} request needs about {tokens} tokens, but {role}.max_context is "
                f"{llm.max_context}. Raise the context window of the model server and max_context in config.yaml (see README)."
            )


def control_all(run, system, items, rows):
    detected = {r["id"] for r in rows if r["version"] == "vulnerable" and r["verdict"] == "vulnerable"}
    done = {r["id"] for r in run.control_rows if r["config"] == system.name}
    tasks = [i for i in items if i["id"] in detected and i["id"] not in done]
    one = lambda item: run_control(item, system, run.cfg, lambda rec: run.log("control.jsonl", rec))
    for rows_of_item in run.parallel(one, tasks, f"{system.name}: neutral comments"):
        run.control_rows += rows_of_item
    return [r for r in run.control_rows if r["config"] == system.name and r["id"] in detected]


def attack_all(run, system, items, rows):
    detected = {r["id"] for r in rows if r["version"] == "vulnerable" and r["verdict"] == "vulnerable"}
    done = {a["id"] for a in run.attacks if a["config"] == system.name}
    tasks = [i for i in items if i["id"] in detected and i["id"] not in done]

    def one(item):
        result = run_attack(item, system, run.attacker_llm, run.cfg, lambda rec: run.log("rounds.jsonl", rec))
        run.log("attacks.jsonl", result)
        return result

    run.attacks += run.parallel(one, tasks, f"{system.name}: attack")
    return [a for a in run.attacks if a["config"] == system.name and a["id"] in detected]


def summarize(run, per_config):
    a = run.cfg["attack"]
    budgets = sorted({b for b in a["budgets"] if b <= a["max_rounds"]} | {a["max_rounds"]})
    summary = {
        "detector_model": run.detector_llm.model,
        "attacker_model": run.attacker_llm.model,
        "pairs": len({r["id"] for r in run.baseline_rows}),
        "max_rounds": a["max_rounds"],
        "seed": run.cfg["seed"],
        "detector_temperature": run.detector_llm.temperature,
        "attacker_temperature": run.attacker_llm.temperature,
        "configs": {},
        "requests_this_launch": {
            "detector": {"sent": run.detector_llm.requests, "from_cache": run.detector_llm.cache_hits},
            "attacker": {"sent": run.attacker_llm.requests, "from_cache": run.attacker_llm.cache_hits},
        },
        "largest_prompt_tokens_estimated": {
            "detector": run.detector_llm.largest_prompt,
            "attacker": run.attacker_llm.largest_prompt,
        },
    }
    rounds = read_jsonl(run.dir / "rounds.jsonl")
    for name, (rows, controls, attacks) in per_config.items():
        base = baseline_metrics(rows)
        summary["configs"][name] = {
            "baseline": base,
            "invalid_answers": error_counts(name, rows, rounds, controls),
            "control": metrics.control_summary(controls),
            "asr_curve": metrics.asr_curve(attacks, budgets, base),
            "mean_rounds_to_success": metrics.mean_rounds_to_success(attacks),
            "successful_styles": metrics.style_counts(attacks),
            "attacks_stopped_by_comment_filter": sum(1 for x in attacks if x.get("stopped") == "comment_filtered"),
        }
    run.save("summary.json", summary)
    metrics.plot_asr(summary, run.dir / "asr_curve.png")
    return summary


def main():
    parser = argparse.ArgumentParser(description="Adversarial-comment attack on SAST-LLM pipelines")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--name", default="main", help="results/<name>; launch again with the same name to resume")
    parser.add_argument("--data", help="JSONL file with function pairs (default: run.data in the config)")
    parser.add_argument("--configs", help="comma-separated subset of " + ",".join(SYSTEMS))
    parser.add_argument("--limit", type=int, help="use only the first N pairs")
    parser.add_argument("--max-rounds", type=int, help="override attack.max_rounds")
    parser.add_argument("--workers", type=int, help="parallel requests to the model server")
    parser.add_argument("--prepare", action="store_true", help="rebuild the samples from MegaVul and exit")
    args = parser.parse_args()

    cfg = load_config(args.config)
    if args.prepare:
        print(json.dumps(prepare(cfg), indent=2))
        return
    overrides = {"data": args.data, "limit": args.limit, "workers": args.workers}
    cfg["run"].update({k: v for k, v in overrides.items() if v is not None})
    if args.configs:
        cfg["run"]["configs"] = [c.strip() for c in args.configs.split(",")]
    unknown = [c for c in cfg["run"]["configs"] if c not in SYSTEMS]
    if unknown:
        raise SystemExit(f"Unknown configurations {unknown}; available: {', '.join(SYSTEMS)}")
    if args.max_rounds is not None:
        cfg["attack"]["max_rounds"] = args.max_rounds

    items = load_items(cfg["run"]["data"], cfg["run"].get("limit"))
    run = Run(cfg, args.name)
    print(f"{len(items)} function pairs from {cfg['run']['data']}, configurations {', '.join(cfg['run']['configs'])}")
    if cfg["detector"]["temperature"] != 0:
        print("WARNING: detector.temperature is not 0, verdicts will not be deterministic")
    per_config = {}
    try:
        check_context(run, items)
        for name in cfg["run"]["configs"]:
            system = SYSTEMS[name](run.detector_llm)
            rows = baseline(run, system, items)
            per_config[name] = (rows, control_all(run, system, items, rows), attack_all(run, system, items, rows))
    except ContextError as error:
        raise SystemExit(f"STOPPED: {error}")
    summary = summarize(run, per_config)
    print(metrics.table(summary))
    print(f"Results: {run.dir}")


if __name__ == "__main__":
    main()
