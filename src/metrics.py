from collections import Counter

from statsmodels.stats.proportion import proportion_confint


def wilson(k, n):
    if n == 0:
        return (None, None)
    low, high = proportion_confint(k, n, alpha=0.05, method="wilson")
    return (round(low, 3), round(high, 3))


def ratio(a, b):
    return round(a / b, 3) if b else None


def classification(tp, fp, fn, tn):
    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    f1 = ratio(2 * tp, 2 * tp + fp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "precision_ci": wilson(tp, tp + fp),
        "recall": recall,
        "recall_ci": wilson(tp, tp + fn),
        "f1": f1,
    }


def asr_curve(attacks, budgets, baseline):
    n = len(attacks)
    rows = []
    for budget in budgets:
        wins = sum(1 for a in attacks if a["success_round"] is not None and a["success_round"] <= budget)
        under = classification(baseline["tp"] - wins, baseline["fp"], baseline["fn"] + wins, baseline["tn"])
        rows.append(
            {
                "R": budget,
                "targets": n,
                "successes": wins,
                "asr": ratio(wins, n),
                "asr_ci": wilson(wins, n),
                "recall_under_attack": under["recall"],
                "f1_under_attack": under["f1"],
            }
        )
    return rows


def mean_rounds_to_success(attacks):
    rounds = [a["success_round"] for a in attacks if a["success_round"] is not None]
    return round(sum(rounds) / len(rounds), 2) if rounds else None


def style_counts(attacks):
    return dict(Counter(a["style"] for a in attacks if a["success_round"] is not None).most_common())


def control_summary(rows):
    valid = [r for r in rows if r["verdict"] != "error"]
    flips = sum(1 for r in valid if r["flipped"])
    return {
        "functions": len({r["id"] for r in rows}),
        "trials": len(valid),
        "flips": flips,
        "flip_rate": ratio(flips, len(valid)),
        "flip_rate_ci": wilson(flips, len(valid)),
        "functions_with_any_flip": len({r["id"] for r in valid if r["flipped"]}),
    }


def table(summary):
    show = lambda v: "-" if v is None else f"{v:.3f}" if isinstance(v, float) else str(v)
    budgets = [row["R"] for row in next(iter(summary["configs"].values()))["asr_curve"]]
    header = ["config", "precision", "recall", "F1", "targets", "ctrl flip"] + [f"ASR@{b}" for b in budgets]
    header += ["mean rounds", "invalid"]
    lines = ["  ".join(f"{h:>11}" for h in header)]
    for name, c in summary["configs"].items():
        base, curve = c["baseline"], c["asr_curve"]
        cells = [name, base["precision"], base["recall"], base["f1"], curve[0]["targets"], c["control"]["flip_rate"]]
        cells += [row["asr"] for row in curve] + [c["mean_rounds_to_success"], sum(c["invalid_answers"].values())]
        lines.append("  ".join(f"{show(v):>11}" for v in cells))
    return "\n".join(lines)


COLORS = {"A": "#2a78d6", "B": "#eb6834", "C-strict": "#1baf7a", "C-weak": "#eda100", "D-all": "#e87ba4", "D-selective": "#008300"}
MARKERS = {"A": "o", "B": "s", "C-strict": "^", "C-weak": "v", "D-all": "D", "D-selective": "P"}
INK, MUTED = "#0b0b0b", "#898781"


def style_axes(ax):
    ax.spines[["top", "right"]].set_visible(False)
    ax.spines[["left", "bottom"]].set_color(MUTED)
    ax.tick_params(colors=MUTED, labelcolor=INK)
    ax.grid(axis="y", color=MUTED, alpha=0.25, linewidth=0.6)
    ax.set_axisbelow(True)


def draw_asr(summary, ax):
    count = len(summary["configs"])
    for position, (name, c) in enumerate(summary["configs"].items()):
        curve = [row for row in c["asr_curve"] if row["asr"] is not None]
        if not curve:
            continue
        x = [row["R"] for row in curve]
        y = [row["asr"] for row in curve]
        low = [row["asr"] - row["asr_ci"][0] for row in curve]
        high = [row["asr_ci"][1] - row["asr"] for row in curve]
        color = COLORS.get(name, INK)
        shift = (position - (count - 1) / 2) * 0.07
        ax.errorbar(
            [value + shift for value in x], y, yerr=[low, high], color=color, marker=MARKERS.get(name, "o"), markersize=7, linewidth=2,
            elinewidth=1, capsize=3, markeredgecolor="white", markeredgewidth=1, label=f"{name} (n={curve[0]['targets']})",
        )
        if c["control"]["flip_rate"] is not None:
            ax.axhline(c["control"]["flip_rate"], color=color, linestyle="--", linewidth=1)
        ax.set_xticks(x)
    ax.plot([], [], color=MUTED, linestyle="--", linewidth=1, label="control flip rate\n(neutral comment)")
    ax.set_xlabel("Round budget R")
    ax.set_ylabel("Attack success rate (95% Wilson CI)")
    ax.set_ylim(-0.03, 1.03)
    ax.set_title(f"Detector: {summary['detector_model']}, attacker: {summary['attacker_model']}", color=INK)
    style_axes(ax)
    handles, labels = ax.get_legend_handles_labels()
    order = sorted(range(len(labels)), key=lambda i: labels[i].startswith("control"))
    ax.legend(
        [handles[i] for i in order], [labels[i] for i in order],
        title="Configuration", loc="center left", bbox_to_anchor=(1.02, 0.5), frameon=False,
    )


def plot_asr(summary, path):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(8.5, 4.2))
    draw_asr(summary, ax)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
