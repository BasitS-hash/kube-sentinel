# Contributing to kube-sentinel

Thanks for your interest in improving kube-sentinel! This guide covers the
local workflow and the conventions the project follows.

## Getting started

```bash
git clone https://github.com/BasitS-hash/kube-sentinel.git
cd kube-sentinel
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Quality gates

All of these must pass before a PR is merged (CI enforces them on Python 3.11
and 3.12):

```bash
ruff check src tests          # lint
ruff format --check src tests # formatting
mypy                          # static types
pytest --cov=kube_sentinel --cov-fail-under=85
bandit -r src                 # SAST
```

We use **test-driven development**: write the failing test first, then the
minimal implementation. Coverage on the rule engine must stay above 85%.

## Adding a rule

Rules are data. To add one:

1. Pick the right pack in `src/kube_sentinel/rules/` (`workload.py`, `rbac.py`,
   or `networking.py`), or create a new module and import it from
   `rules/base.py::_ensure_loaded`.
2. Write a pure `check(resource) -> Iterator[str]` function that yields one
   message per violation.
3. Register it with `build_rule(...)`, giving it:
   - a unique, stable ID (`KS-<AREA>-NNN`),
   - a severity, a title, and a concrete remediation,
   - compliance mappings (`cis`, `pss`, `nsa_cisa`, `mitre_attack`),
   - an `applies_to` set of kinds where relevant.
4. Add unit tests with **both** a positive (fires) and a negative (clean) case.
5. If the rule should appear in the demo, extend `examples/insecure` and ensure
   `examples/hardened` still scans clean.

Keep findings actionable: every finding must tell the user *what* is wrong and
*how* to fix it.

## Coding conventions

- Python 3.11+, full type annotations, PEP 8 (enforced by ruff + ruff format).
- Prefer small, focused modules and immutable (`frozen=True`) data.
- No `print` debugging in committed code; the CLI uses `rich` consoles.
- Validate external input at boundaries; never trust manifest content.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):
`feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`, `ci:`, `perf:`.

## Reporting bugs and requesting features

Open an issue using the provided templates. For security issues, follow
[SECURITY.md](SECURITY.md) instead of filing a public issue.

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
