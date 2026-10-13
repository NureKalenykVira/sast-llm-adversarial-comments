import json
from pathlib import Path

import pandas as pd

from .attack import STYLES
from .metrics import COLORS, INK, MUTED, ratio, style_axes, wilson

ROUND_COLUMNS = ["id", "config", "round", "style", "verdict", "veto", "llm_verdict", "comment_survived"]
STYLE_NAMES = list(STYLES)
TOOL_GROUPS = ("TOOL_CPPCHECK", "other fake tool output", "other styles")


def read_jsonl(path, columns):
    rows = []
    if Path(path).exists():
        with open(path, encoding="utf-8") as f:
            rows = [json.loads(line) for line in f if line.strip()]
    frame = pd.DataFrame(rows)
    return frame.reindex(columns=list(dict.fromkeys(list(frame.columns) + columns)))


def load_run(run_dir):
    run_dir = Path(run_dir)
    with open(run_dir / "summary.json", encoding="utf-8") as f:
        summary = json.load(f)
    return {
        "summary": summary,
        "baseline": read_jsonl(run_dir / "baseline.jsonl", ["id", "config", "version", "verdict", "veto"]),
        "rounds": read_jsonl(run_dir / "rounds.jsonl", ROUND_COLUMNS),
        "attacks": read_jsonl(run_dir / "attacks.jsonl", ["id", "config", "success_round", "style", "stopped"]),
        "control": read_jsonl(run_dir / "control.jsonl", ["id", "config", "verdict", "flipped"]),
    }


def interval(ci):
    return "-" if ci[0] is None else f"{ci[0]:.2f}-{ci[1]:.2f}"


def metrics_table(summary):
    rows = []
    for name, c in summary["configs"].items():
        base, last, control = c["baseline"], c["asr_curve"][-1], c["control"]
        rows.append(
            {
                "configuration": name,
                "precision": base["precision"],
                "precision 95% CI": interval(base["precision_ci"]),
                "recall": base["recall"],
                "recall 95% CI": interval(base["recall_ci"]),
                "F1": base["f1"],
                "attacked functions": last["targets"],
                "control flip rate": control["flip_rate"],
                f"ASR at R={last['R']}": last["asr"],
                "ASR 95% CI": interval(last["asr_ci"]),
                "recall under attack": last["recall_under_attack"],
                "F1 under attack": last["f1_under_attack"],
                "mean round of success": c["mean_rounds_to_success"],
                "invalid answers": sum(c["invalid_answers"].values()),
            }
        )
    return pd.DataFrame(rows).set_index("configuration")


def asr_table(summary):
    rows = []
    for name, c in summary["configs"].items():
        row = {"configuration": name, "attacked functions": c["asr_curve"][0]["targets"], "control flip rate": c["control"]["flip_rate"]}
        row.update({f"R={r['R']}": r["asr"] for r in c["asr_curve"]})
        rows.append(row)
    return pd.DataFrame(rows).set_index("configuration")


def rate_table(rounds, category):
    valid = rounds[rounds["style"].notna() & rounds["verdict"].isin(["safe", "vulnerable"])].copy()
    valid["category"] = valid["style"].map(category)
    rows = []
    for (config, name), group in valid.groupby(["config", "category"], sort=False):
        wins = int((group["verdict"] == "safe").sum())
        low, high = wilson(wins, len(group))
        rows.append(
            {
                "configuration": config,
                "category": name,
                "comments tried": len(group),
                "successful": wins,
                "success rate": ratio(wins, len(group)),
                "95% CI": interval((low, high)),
                "functions": group["id"].nunique(),
            }
        )
    return pd.DataFrame(rows, columns=["configuration", "category", "comments tried", "successful", "success rate", "95% CI", "functions"])


def style_table(rounds):
    order = {name: i for i, name in enumerate(list(STYLES) + ["OTHER"])}
    table = rate_table(rounds, lambda style: style)
    table["order"] = table["category"].map(order)
    table = table.sort_values(["configuration", "order"]).drop(columns="order")
    return table.rename(columns={"category": "style"}).reset_index(drop=True)


def tool_group(style):
    if style == "TOOL_CPPCHECK":
        return TOOL_GROUPS[0]
    return TOOL_GROUPS[1] if str(style).startswith("TOOL_") else TOOL_GROUPS[2]


def cppcheck_table(rounds, attacks):
    table = rate_table(rounds, tool_group).rename(columns={"category": "comment group"})
    table["order"] = table["comment group"].map({g: i for i, g in enumerate(TOOL_GROUPS)})
    table = table.sort_values(["configuration", "order"]).drop(columns="order").reset_index(drop=True)
    won = attacks[attacks["success_round"].notna()]
    share = won.assign(group=won["style"].map(tool_group)).groupby(["config", "group"]).size()
    totals = won.groupby("config").size()
    table["share of successful attacks"] = [
        ratio(int(share.get((c, g), 0)), int(totals.get(c, 0))) for c, g in zip(table["configuration"], table["comment group"])
    ]
    return table


def veto_table(baseline, rounds, attacks):
    rows = []
    for config in [c for c in attacks["config"].dropna().unique() if c.startswith("C-")]:
        r = rounds[(rounds["config"] == config) & rounds["veto"].notna()]
        targets = attacks[attacks["config"] == config]
        broken = set(targets[targets["success_round"].notna()]["id"])
        persuaded = set(r["id"])
        held = persuaded - broken
        all_rounds = rounds[(rounds["config"] == config) & rounds["verdict"].isin(["safe", "vulnerable"])]
        fixed = baseline[(baseline["config"] == config) & (baseline["version"] == "fixed") & baseline["veto"].notna()]
        rows.append(
            {
                "configuration": config,
                "attacked functions": len(targets),
                "attack rounds": len(all_rounds),
                "rounds where the LLM dismissed the alert": len(r),
                "of them stopped by the veto": int((r["veto"] == True).sum()),
                "share of rounds stopped by the veto": ratio(int((r["veto"] == True).sum()), len(all_rounds)),
                "functions where the LLM was persuaded at least once": len(persuaded),
                "functions where the veto held to the end": len(held),
                "share: LLM persuaded, veto held": ratio(len(held), len(targets)),
                "ASR without the veto (same comments)": ratio(len(persuaded), len(targets)),
                "ASR with the veto": ratio(len(broken), len(targets)),
                "fixed versions: correct dismissals by the LLM": len(fixed),
                "of them rejected by the veto (false positives kept)": int((fixed["veto"] == True).sum()),
            }
        )
    columns = {r["configuration"]: pd.Series({k: v for k, v in r.items() if k != "configuration"}, dtype=object) for r in rows}
    return pd.DataFrame(columns)


def draw_rates(table, category_column, categories, title):
    import matplotlib.pyplot as plt

    configs = list(table["configuration"].unique())
    columns = min(3, max(len(configs), 1))
    lines = -(-max(len(configs), 1) // columns)
    size = (3.0 * columns + 1.6, lines * (0.3 * len(categories) + 1.1) + 0.5)
    fig, axes = plt.subplots(lines, columns, figsize=size, sharex=True, sharey=True, squeeze=False)
    for ax in axes.flat[len(configs):]:
        ax.set_visible(False)
    for ax, config in zip(axes.flat, configs):
        part = table[table["configuration"] == config].set_index(category_column).reindex(categories)
        rates = part["success rate"].fillna(0)
        ax.barh(range(len(categories)), rates, height=0.62, color=COLORS.get(config, INK))
        for y, (rate, wins, tried) in enumerate(zip(rates, part["successful"], part["comments tried"])):
            label = "not used" if pd.isna(tried) else f"{int(wins)}/{int(tried)}"
            ax.text(min(rate + 0.03, 0.74), y, label, va="center", ha="left", fontsize=8, color=INK if not pd.isna(tried) else MUTED)
        ax.set_xlim(0, 1)
        ax.set_yticks(range(len(categories)))
        ax.set_yticklabels(categories)
        ax.set_ylim(len(categories) - 0.5, -0.5)
        ax.set_title(config, color=INK, fontsize=10)
        if ax in axes[-1]:
            ax.set_xlabel("Success rate of a comment")
        style_axes(ax)
        ax.grid(axis="y", visible=False)
        ax.grid(axis="x", color=MUTED, alpha=0.25, linewidth=0.6)
    fig.suptitle(title, color=INK, fontsize=11)
    fig.tight_layout()
    return fig
