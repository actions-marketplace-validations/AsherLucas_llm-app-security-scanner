# llm-app-security-scanner

**Early-stage tool, v0.3.0.** It does **not** yet qualify for any six-month
open-source maintainer programme, and it has no stars, downloads, users, or
benchmarks to claim. This README describes what it does honestly, including
its limits.

A static security scanner for LLM / agent repositories, designed as a CI gate.
It looks for the patterns that most often turn an agent into a liability:
a shell the agent can be talked into running, a file operation an attacker
can steer, a secret left in code, and untrusted text fed straight into a
prompt as if it were an instruction.

## 5-minute quickstart

```bash
pip install -e .
llm-scan scan path/to/your/repo
llm-scan scan path/to/your/repo --format sarif > report.sarif
llm-scan adversarial --cases examples/adversarial/cases.yaml
```

Exit codes: `0` = gate passed, `1` = gate failed (high severity +
high confidence findings by default), `2` = usage/config error.
Run `llm-scan scan --help` for `--fail-on`, `--fail-on-any`, and `--exclude`.

## What it scans (v1: Python only)

| Check | What it flags | Attack story |
|---|---|---|
| `SHELL001` | `os.system` / `os.popen`, `subprocess` with `shell=True`, especially on tainted input | An agent reads a web page that says “run this command”. If the agent builds a shell string from that text, the page author gets a shell. |
| `PY003` | `subprocess` `run` / `call` / `check_call` / `check_output` / `Popen` with a tainted command or argv, even without `shell=True` | No shell is needed for damage: whoever controls the command string or an argv entry controls which program runs. Use an allowlisted command mapping and a literal argv list. |
| `TOOL001` / `TOOL002` | Agent tool execution mentioning a shell; `allow_shell=True` or a raw `shell`/`bash` tool | A tool list is a permission list. Giving an agent a raw shell tool is giving it every command, not one capability. |
| `FILE001` | File delete / write to a tainted (user- or input-controlled) path | A prompt-injected agent is asked to “save the report” to a path the attacker chose, and overwrites or deletes something else. |
| `SECRET001` | Known-format secret literals: OpenAI-style keys, AWS keys, GitHub tokens, Slack tokens | A key committed to a repo is public the moment the repo is public. Rotate it; do not just delete the line. |
| `SECRET002` | Generic `api_key` / `password` / `token` assignments with literal values | Same story, lower confidence — the check cannot tell a real secret from a test placeholder, so it does not block the gate by default. |
| `AGENT001` | Untrusted input (web fetch, `input()`, request data, argv) flowing into an LLM/agent call without a sanitiser | **Indirect prompt injection:** an agent reads a doc, issue, or web page, and the page contains hidden instructions. If that text is pasted into the prompt unsanitised, the page author is now writing your system prompt. |

## The gate, and why it is deliberately narrow

By default the gate fails **only on high severity + high confidence**
findings. A medium-confidence heuristic (for example a generic secret-looking
assignment, or a shell call with a non-literal command) is reported but does
not block a merge — otherwise false positives teach teams to ignore the
scanner, which is worse than no scanner.

Suppress a reviewed finding in `.llm-scan-suppress` (repo root, one per line):

```
# CHECK_ID:glob  or  CHECK_ID:file:line
SECRET001:examples/vulnerable/*
TOOL002:src/agent.py:42
```

Suppression is a review decision, not a fix. Re-check suppressed findings
when the code around them changes.

## Adversarial pack

`examples/adversarial/cases.yaml` holds direct and indirect injection
payloads. `llm-scan adversarial` runs them against a **stub** agent only:
a naive stub that follows prompt text, and a sanitising stub that treats
external text as data. This demonstrates the *class* of risk; it does **not**
prove any real model would fall for a payload. Never use this pack to claim
a real model is vulnerable, and never run payloads against a third-party
system you do not own.

## False-positive measurement (local only, aggregate only)

Measured on 2026-10-29 by scanning the sibling project in this same workspace
(`prompt-eval-harness`, a Python library/CLI, scanned locally — no
third-party system was probed):

- Files scanned: see the run output in `docs/false-positive-note.md`.
- The scanner is a heuristic tool: it will flag some safe code and miss
  some unsafe code. The gate design (high-confidence only) is the mitigation
  for the first failure mode; manual review is the mitigation for the second.
- Do not quote a single “accuracy” number from a handful of local files.
  The honest statement is: on the local example repos, the vulnerable
  example fails the gate and the fixed example passes it (both covered by
  tests), and on a real, benign codebase the gate should stay quiet
  except where a human should look.

## CI

This repo now has real workflows in `.github/workflows/`:

- `ci.yml` — on push/PR, runs the test suite on Python 3.11 and 3.12,
  checks that the vulnerable example fails the gate (exit 1) and the
  fixed example passes (exit 0), runs the adversarial pack, and runs
  the scanner on its own production code (`src/`) as a dogfood check,
  keeping the SARIF as an artifact. The whole repo is deliberately
  *not* the dogfood gate: `tests/` contain intentional secret-literal
  fixtures and `examples/vulnerable/` is deliberately vulnerable.
- `publish.yml` — publishes to PyPI on version tags via Trusted
  Publishing (OIDC, no stored token). It is prepared, not yet used:
  no release has been tagged and nothing has been uploaded to PyPI
  yet; a PyPI account with 2FA and a pending Trusted Publisher for
  this repo/workflow are still required first.

See also `docs/ci-workflow-example.yml` for a documented GitHub Actions
workflow you can copy for your own repo, including uploading SARIF to
GitHub code scanning.

An `action.yml` wrapper is included at the repo root for use as
`uses: AsherLucas/llm-app-security-scanner@v0.3.0` once a release exists.

## Limits (read before trusting it)

- Python only in v1. Other languages are not scanned.
- Static heuristics only: no data-flow across files, no real LLM calls, no
  guarantee. A clean scan is not proof of safety.
- The sanitiser list is name-based (`sanitize`, `validate`, `allowlist`,
  …). A real sanitiser with another name will be missed, and a function
  *named* sanitize that does nothing will be trusted. Review the code.
- PY003 uses the same single-file taint tracking as the other checks:
  it flags input assigned from `input()`, a web fetch, or request data
  in the same file, but not a bare function parameter, not an inline
  `sys.argv[1]` / `request.form["x"]` passed without assignment, not a
  `from subprocess import run` alias (only `subprocess.<fn>` is seen),
  and not the `args=` keyword form. A clean PY003 scan is not proof
  that no subprocess call is attacker-controlled.
- Secrets detection is pattern-based; it will miss secrets in other
  formats and flag some test placeholders.

## Licence

MIT. See `LICENSE`.
