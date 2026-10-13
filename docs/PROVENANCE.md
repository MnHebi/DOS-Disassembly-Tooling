# Source provenance ledger

No CEO source was copied verbatim into this bootstrap. All other code in `src/ddt/` is a fresh, generic starter implementation, and tests synthesize their own fixtures.

For each future imported algorithm record:

| New path / function | Original path / function | Original SHA-256 | Adaptation | Independent equivalence check | Licensing notes |
|---|---|---|---|---|---|
| `src/ddt/strings.py::extract` | `analysis/scripts/structured_analysis.py::ascii_strings` | `65dea023ee649f8a498085cc3b7bbfca15180f786eaabd8753acc58b97aa137f` | Used as a printable-run scan; generalized to arbitrary input, configurable minimum length, bounded result count and versioned JSON. CEO NUL-termination/pool specifics dropped. | `tests/test_strings.py` checks offsets, text and counts against literal byte fixtures with hand-derived expectations | No LICENSE file found in the CEO checkout; the reused logic is a trivial printable-run scan, reimplemented minimally rather than copied |

Do not treat an implementation as copied or validated merely because its structure resembles prior CEO code. Preserve original source and accepted evidence untouched.
