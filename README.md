# Robustness of hybrid SAST-LLM vulnerability detection to adversarial code comments

An attacker LLM adds one code comment to a vulnerable C/C++ function (the code itself is never changed),
reads the verdict and explanation of the system under test, and refines the comment for up to 20 rounds.
The experiment measures how often the system is talked into the verdict "safe" (attack success rate, ASR)
for six system configurations.

| Configuration | What it is |
|---|---|
| `A` | Standalone LLM detector of NULL pointer dereferences (CWE-476), no static analysis. |
| `B` | Static-analysis alert + LLM agent that triages it (true positive / false positive). |
| `C-strict` | `B` + SAST veto: a dismissal is accepted only if the agent cites a line of code (not a comment) at or before the alert that contains a NULL check of the reported pointer. Upper bound: unbreakable by construction of the sample. |
| `C-weak` | `B` + weak veto: the cited line must be code (not a comment) before the alert line that mentions the reported pointer; no NULL check is required. |
| `D-all` | `B` + all comments are removed before the LLM. Upper bound: the attack is stopped after the first round because the input cannot change (`attacks_stopped_by_comment_filter` in the summary). |
| `D-selective` | `B` + a separate LLM call labels every comment as verifiable from the visible code or not; only unverifiable comments are removed. |

## Quick start

**Python 3.11 is the minimum version** (the pinned packages in `requirements.txt` do not install on older
versions); 3.11 and newer work. Linux / macOS:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Windows (PowerShell):

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The commands below use `python`; replace it with `.venv/bin/python` or `.\.venv\Scripts\python.exe`.

### 1. Point the code to your model

Edit the `detector` and `attacker` sections of `config.yaml`. Any OpenAI-compatible server works
(vLLM, Ollama, llama.cpp server, a cloud API):

```yaml
detector:
  base_url: http://localhost:8000/v1   # your server
  api_key_env: OPENAI_API_KEY          # name of the env variable with the key; not needed for local servers
  model: Qwen/Qwen2.5-Coder-32B-Instruct
  max_context: 8192                    # context window of the server for this model, in tokens
  json_mode: true                      # set to false if the server rejects response_format
```

The detector and the attacker may be the same model or two different ones. Keep `detector.temperature: 0`
(deterministic verdicts) and a small attacker temperature (0.7) for variety of comments.

**Context window.** The longest request of this experiment needs about 7 500 tokens, so the server must
give the model at least 8192 tokens. The code estimates the size of every prompt and stops with an error
instead of letting the server truncate it silently; `max_context` must match the real server setting.

- Ollama (default is only 4096): start the server with `OLLAMA_CONTEXT_LENGTH=8192 ollama serve`, or build
  a model with a larger window: a `Modelfile` with the two lines `FROM qwen2.5-coder:7b` and
  `PARAMETER num_ctx 8192`, then `ollama create qwen2.5-coder-8k -f Modelfile` and use that model name.
- vLLM: the window is the model's own maximum unless limited with `--max-model-len`; if you set it, use
  `--max-model-len 8192` or more.

**Parallel requests.** `--workers N` sends N requests at once. vLLM batches them by itself. Ollama handles
them in parallel only when started with `OLLAMA_NUM_PARALLEL=N` (each parallel slot needs its own context
memory); otherwise use `--workers 1`.

### 2. Three launches

| Step | Command | What it does | Requests (upper bound) | Rough time, 3 s per request, 8 workers |
|---|---|---|---|---|
| check | `python -m src.run --name check --limit 2 --max-rounds 1` | 2 pairs, 1 feedback round: shows that the setup works | about 90 | 1-2 minutes |
| pilot | `python -m src.run --name pilot --data data/pilot_30.jsonl --workers 8` | 30 pairs, 20 rounds | about 7 500 | up to 45 minutes |
| main | `python -m src.run --name main --workers 8` | 100 pairs (`data/main_100.jsonl`), 20 rounds | about 25 000 | up to 2.5 hours |

With one worker multiply the time by 8. The time depends on the hardware and the model; the pilot shows
the real speed.

**Please send `results/pilot/summary.json` before starting the main run**, so that the pilot numbers can be
checked first. Answers of the pilot stay in the cache, and its 30 pairs are the first 30 of the main sample,
so the main run does not repeat these requests.

**If a run is interrupted**, launch the same command again: finished functions are skipped and model
answers are taken from the cache (`results/cache.sqlite`), so nothing is paid for twice.

Useful options: `--configs A,B` (subset of configurations), `--limit N` (first N pairs),
`--max-rounds R`. A run with different settings needs a different `--name`.

## How many model requests to expect

For `N` function pairs and `max_rounds = 20` (21 attempts per function):

| Stage | Requests (upper bound) | N = 100 |
|---|---|---|
| No attack: `A`, `B`, `D-all` | 2N each | 600 |
| No attack: `C-strict`, `C-weak` | 0 (same requests as `B`, served from the cache) | 0 |
| No attack: `D-selective` | 4N (comment filter + triage) | 400 |
| Attack: `A`, `B`, `C-strict`, `C-weak` | 21 × 2 per function, each | 16 800 |
| Attack: `D-selective` | 21 × 3 per function | 6 300 |
| Attack: `D-all` | 1 per function | 100 |
| Neutral-comment control: `A`, `B` | 2 per function, each | 400 |
| Neutral-comment control: `D-selective` | 4 per function | 400 |
| Neutral-comment control: `C-strict`, `C-weak`, `D-all` | 0 (served from the cache) | 0 |
| **Total** | | **about 25 000** |

This is the worst case, when no attack succeeds. An attack stops at the first success, so the real number
is lower for the configurations that break early; `C-strict` always uses its full budget. A few extra
attacker requests appear when the attacker repeats itself and is asked again.

Time is roughly `requests × seconds per request / workers`. For example, at 3 s per request the worst
case is about 20 hours with one worker and about 2.5 hours with 8 workers. Requests are short: a prompt is one
function of up to 80 lines plus the last five attempts (a few thousand tokens at most), an answer is up to
700 tokens.

## Results

Everything is written to `results/<name>/`:

| File | Content |
|---|---|
| `summary.json` | per configuration: precision, recall, F1 without attack; control flip rate; ASR for R = 0, 1, 3, 5, 10, 20 with 95% Wilson intervals; recall and F1 under attack; mean round of success; successful comment styles |
| `asr_curve.png` | ASR as a function of the round budget for all configurations; dashed lines show the control flip rate |
| `baseline.jsonl` | verdict and explanation for every function version without attack |
| `rounds.jsonl` | every attack round: comment, style, code with the comment, verdict, explanation, veto and filter details |
| `attacks.jsonl` | outcome of the attack on every function (round of success or none) |
| `control.jsonl` | verdicts after inserting neutral comments (see below) |
| `config.json` | settings of the run |

A summary table is also printed at the end. `notebooks/pilot.ipynb` shows the same results as tables and a plot.
To share the results, send the whole `results/<name>/` folder.

### How ASR(R) is computed

The attack is run once with the largest budget (`attack.max_rounds`), and the round at which the verdict
became "safe" is recorded for every function. ASR(R) is the share of functions broken at round R or earlier.
Round 0 is the first comment, written without any feedback. Only functions that the configuration flagged
correctly without attack are attacked, so the number of targets differs between configurations.

### Neutral-comment control

A verdict may change after any edit, not only because the model believed the attacker. To measure this
noise, two fixed neutral comments (a TODO about refactoring and a remark about coding style; nothing about
safety or pointers) are inserted, one at a time, right before the alert line of every function that the
configuration flagged correctly. The **control flip rate** is the share of these insertions after which
the verdict became "safe" (`control` in `summary.json`, column `ctrl flip` in the table, dashed lines in
the plot). It is comparable to ASR at R = 0 (one comment, no feedback); `functions_with_any_flip` counts
functions broken by at least one of the two comments. An ASR close to the control flip rate means that
the configuration is unstable rather than persuaded.

## Data

`data/main_100.jsonl` holds 100 pairs (vulnerable function, fixed function) with CWE-476 from
[MegaVul](https://github.com/Icyrockton/MegaVul); `data/pilot_30.jsonl` is its first 30 pairs.

**Reference alerts.** Cppcheck run on a single function reports a NULL dereference for only 26 of 849
vulnerable functions, so the main experiment uses reference alerts derived from the fix: the alert is placed
on the line that dereferences the pointer for which the fix added a NULL check. On the vulnerable version
the alert is a true positive, on the fixed version the same alert is a false positive. Such an alert can be
derived for 192 of the 849 pairs with 5-80 lines (fixes that add an explicit NULL check before an explicit
dereference); the sample is drawn from these 192 with a fixed seed.

**Supplementary experiment with real Cppcheck alerts.** `data/cppcheck_subset.jsonl` holds the 15 pairs for
which Cppcheck 2.22 reports a NULL dereference on the vulnerable version and nothing on the fixed one.
The alerts are stored in the file, so Cppcheck is not needed to run it:

```bash
python -m src.run --name cppcheck --data data/cppcheck_subset.jsonl --workers 8
```

`data/sample.jsonl` holds three toy pairs for quick checks.

To rebuild the samples (optional): download `megavul_simple.json` from the MegaVul repository to
`data/megavul_simple.json`, install Cppcheck (or set `sast.cppcheck_path`), and run `python -m src.run --prepare`.

## Notes and limitations

- The functions come from publicly known CVEs, so a model may have seen this code and its fix during training.
- Reference alerts model an ideal analyzer; the selection keeps only fixes with an explicit NULL check.
- An answer that is not valid JSON after three attempts is recorded as `error`: it counts neither as "safe"
  nor as "vulnerable", is excluded from precision/recall and is never a successful attack. The numbers are
  in `invalid_answers` of `summary.json` and in the last column of the printed table.
- The attacker may only add a comment. The comment is never placed inside a macro continuation, a
  multi-line expression, a string literal or another comment (it is moved up to the nearest safe line).
- Answers are cached by the full request (model, messages, temperature, seed), which makes a repeated
  launch reproducible. A new request with the same seed is not guaranteed to return the same text
  (it does for the detector at temperature 0 on Ollama, it does not for the attacker at 0.7). Delete
  `results/cache.sqlite` to force new requests.
- Tests of the core logic: `python -m pytest tests`.
- Tested with Python 3.11 and the pinned versions of `requirements.txt` on Windows 11 (with Ollama) and in a
  Linux container (`python:3.11-slim`: tests and a run served from cached answers, without a model server).
