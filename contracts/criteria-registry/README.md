# Criteria-key registry

One file per canonical criteria key, at `keys/<key>.json`, validated against
`criteria-key.schema.json` by `tools/check_criteria_registry.py`.

**Read the entry before you write a transform that emits its key.** If the key has no
entry, write one first. Fill in what you can evidence and write `"unknown"` (or the enum's
unknown member) for what you cannot; an unknown field keeps the key at V0, which is honest.
A guessed field is not.

## Why it exists

Token-Service reads `transformedResponse[key]` by exact, case-sensitive match and compares it
to a requirement. Nothing defined what a key meant, so keys drifted: `isMFAEnabled` has five
meanings across eight integrations, `requiredCoveragePercentage` is a boolean at two vendors
and a percentage at ten, and `isEPPConfigured` is a percentage at fourteen and a boolean at
six. Categories have one definition (Integration-Service's `IntegrationCategories`); criteria
keys now have this one.

## The rules an entry carries

- **`notMeasured` is pinned for every key:** `null`, with
  `additionalInfo.dataCollection.status == "error"`. Not `False`, not `0`. `null` is the only
  value that fails closed under every comparator, and the envelope is the only channel the
  evaluator's not-evaluated gate reads. This replaces the older advice to return
  `{"criteriaKey": False}` on failure.
- **`valueType` is enforced** for every key that is not `contested`: a transform may emit the
  declared type or `null`, nothing else. A bool is not a number.
- **`contested`** means production already answers the key with incompatible meanings or
  types. The entry lists every position and an open decision with a named owner. Do not add a
  new implementation under a contested key; `integrationPolicy: listed` freezes the set
  wherever the meaning is contested.
- **`validation.level` is the minimum across implementations.** One V0 implementation holds
  the whole key at V0.
- **A change of meaning is a new revision**, and needs a V3 validation record, a shadow diff of
  old against new verdicts, and a deprecation window. A key's `valueType`, `unit`, `polarity`
  and `notMeasured` never change once `active`; changing them means a new key. A deprecated
  name is never reused.

## Who enforces what

| Where | What it checks |
|---|---|
| Transformations CI, `tools/check_criteria_registry.py` | Entries validate; every criterion-shaped key a transform emits on the no-evidence bodies is registered; a registered, uncontested key is emitted as its declared type or `null`. Ratchet: `contracts/criteria-registry-allowlist.json`, may only shrink. |
| Integration-Service definition write path (proposed) | Every RTA row's `criteriaKey` is registered (any shape, so it also covers keys the shape rule misses); when the entry says `integrationPolicy: listed`, the row's SRN is in `allowedIntegrations`. |
| Token-Service requirement write path (proposed) | Every requirement's key is registered (no case variants); the operand type matches `valueType`. |

## Commands

```bash
python tools/check_criteria_registry.py --schema-only   # entries only, no RestrictedPython
python tools/check_criteria_registry.py --self-test
python tools/check_criteria_registry.py                 # needs RestrictedPython
```

Never edit the allowlist by hand. Registering a key, or stopping a file from emitting it, is
how an instance leaves; the next run reports it STALE and the entry is deleted.
