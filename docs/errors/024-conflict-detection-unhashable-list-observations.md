# ERR-024 — Evidence conflict detection crashed on list-valued observations

- **Date:** 2026-07-22
- **Component:** policy-engine (`policies/engine/conflict.py`)
- **Severity:** high
- **Status:** resolved
- **Author:** Claude (session implementing the Week 1 gap-analysis closure)

## What happened

While implementing evidence conflict detection (Week 1 brief, task 6), the
first real end-to-end test against the live stack — `POST /verdicts/recompute`
against the actual committed evidence — returned a 500 Internal Server Error
instead of the expected verdict list.

## Exact error / symptom

```
File "/work/policies/engine/conflict.py", line 49, in detect_conflict
    values = {_get_field(row, field) for row in evidence_rows}
              ^^^^^^^^^^^^^^^^^^^^^^
TypeError: unhashable type: 'list'
```

## Environment

- OS / shell: Docker container (`auditor-api`), Python 3.12
- Relevant files: `policies/engine/conflict.py`, `policies/catalog/scan_tests.py`
  (SA-IOT-003's `observations.open_ports` field)

## Root cause

`detect_conflict()` built a Python `set()` of every evidence row's value for
the field a control's conditions key on, to detect disagreement. This works
for scalar values (booleans, strings) but `SA-IOT-003` keys on
`observations.open_ports`, which is a **list** — and lists are unhashable,
so `set()` construction raises immediately. This was never caught in unit
tests because the synthetic fixtures used in `test_conflict.py` only ever
used a boolean-valued control (`SA-IOT-004`/`mqtt_tls`), never a list-valued
one — the real committed device-insecure evidence (two genuinely
conflicting `TEST-NET-PORTSCAN` records, Telnet open in one and not the
other) was the first input that actually exercised this path.

## The fix

Replaced the `set()`-based uniqueness check with a plain list plus
`!=`-comparison against the first non-`None` value, which works for any
comparable type, hashable or not:

```python
values = [_get_field(row, field) for row in evidence_rows]
values = [v for v in values if v is not None]
if any(v != values[0] for v in values[1:]):
    conflicting_fields.append(field)
```

## How to prevent it next time

Added a regression test using a real list-valued field
(`test_detect_conflict_handles_unhashable_list_valued_fields` in
`policies/engine/test_conflict.py`) so a future refactor back to `set()`
fails immediately. More generally: when unit-testing against synthetic
fixtures, deliberately include at least one non-scalar (list/dict) field
shape drawn from a real `scan_tests.py` observation, not just booleans —
this is the second time in this project a real device's actual output shape
caught something synthetic fixtures didn't (see also the NOT_APPLICABLE bug,
[ERR-025]).

## References

Caught via the project's own "verify for real, not just unit-tested"
convention — running `POST /verdicts/recompute` against the live dev
database immediately after the unit tests passed.
