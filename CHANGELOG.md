# Changelog

## [0.3.0] — 2026-10-30

### Added

- New check PY003: Python `subprocess` calls (`run`/`call`/`check_call`/`check_output`/`Popen`) whose command or argv carries tracked-tainted input, even without `shell=True` — the attacker still controls which program runs or which arguments it receives. Tainted + `shell=True` stays under SHELL001 only, so the same call is not flagged twice. Covered by regression tests and by the vulnerable/fixed examples.
- README version references corrected to v0.3.0 (previously still said v0.1.0).

## [0.2.0] — 2026-10-29

### Added

- JS/TS checks: JS001 eval(), JS002 child_process exec/execSync/spawnSync, JS003 new Function(), with examples/js/vulnerable.js and a regression test.

## Unreleased
- New check PY003: Python `subprocess` calls (`run`/`call`/`check_call`/
  `check_output`/`Popen`) whose command or argv carries tracked-tainted
  input, even without `shell=True` — the attacker still controls which
  program runs or which arguments it receives. Tainted + `shell=True`
  stays under SHELL001 only, so the same call is not flagged twice.
  Covered by regression tests and by the vulnerable/fixed examples.
- Real CI in `.github/workflows/ci.yml`: pytest on Python 3.11/3.12,
  vulnerable example must fail the gate, fixed example must pass,
  adversarial pack, and a dogfood scan of `src/` with SARIF artifact.
- PyPI publish workflow prepared (`.github/workflows/publish.yml`,
  Trusted Publishing, tag-triggered); no release tagged, nothing
  uploaded to PyPI yet.
- Fixed a real packaging bug found by the clean-install CI check:
  PyYAML is now a declared dependency, not an assumed one — the
  adversarial command previously failed with "PyYAML is required"
  in a clean venv, so 1 of 15 tests failed before this fix.
- `action.yml` now installs from the action's own checkout, so it
  works for external repos, not just this repo.
- `pyproject.toml`: SPDX MIT licence, project URLs, Python 3.11/3.12
  classifiers (the old MIT classifier was dropped, as it breaks the
  build under PEP 639 with a licence expression).

## 0.1.0 — 2026-10-29
- Initial release: Python-only static scanner (library + CLI).
- Checks: SHELL001, TOOL001, TOOL002, FILE001, SECRET001, SECRET002, AGENT001.
- CI gate: high severity + high confidence by default, suppression file, SARIF output.
- Adversarial pack (stub agent only) with direct + indirect injection cases.
- Examples: deliberately vulnerable vs fixed agent code.
- Docs: quickstart, check catalogue with attack stories, CI guide.
- Deliberately out of v1: non-Python languages, hosted dashboard, LLM-as-judge,
  deep red-teaming (see garak / Promptfoo for that), and a `.github/workflows/`
  file in the initial push (see docs/ci-workflow-example.yml instead).
