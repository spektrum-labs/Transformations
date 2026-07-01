# OFAC Screening Service

Self-hosted OFAC sanctions screening for the Spektrum platform. OFAC publishes the
**SDN** and **Consolidated** lists only as bulk XML (there is no free per-name
query API), so screening hosts the data locally and runs name matching in-process.

## Why "advanced" schema

OFAC ships two XML shapes. The modern **advanced** export
(`SDN_ADVANCED.XML` / `CONS_ADVANCED.XML`) is namespaced and nests names under
`DistinctParty / Profile / Identity / Alias / DocumentedName / DocumentedNamePart /
NamePartValue`, with the entity type carried as an id on `Profile/@PartySubTypeID`
resolved via `ReferenceValueSets`. The **legacy** `sdnEntry` path returns **0
records** against the advanced export — see `app/parser.parse_legacy_sdn` and the
regression test in `tests/test_parser.py`. Screening uses
`app/parser.parse_advanced`.

## Components

| Module | Responsibility |
|--------|----------------|
| `app/sync.py` | Hourly sync: conditional GET (ETag/Last-Modified), sha256 fingerprint, temp→`os.replace` atomic promote, parse + min-record validation *before* overwrite, timestamped archive, per-fetch provenance manifest. |
| `app/parser.py` | Namespaced advanced-schema parser (+ legacy parser retained for the regression). |
| `app/matcher.py` | Normalized RapidFuzz `token_set_ratio` matching over primary + alias names; entity-type filter; `PartyStore` with mtime hot-reload (no restart on new data). |
| `app/receipts.py` | L4 receipts: canonical JSON + HTML with `content_hash` (sha256 of the deterministic claim, excludes `receipt_id`/`created_at`) and a ready-to-attach `evidence_item` (`source: automated`, `proofLevel: "4"`). |
| `app/main.py` | FastAPI app: `lifespan` load, `POST /screen`, `GET /health`. |

## Running

```bash
pip install -r requirements.txt

# Hourly sync (cron): downloads + validates + promotes advanced lists
OFAC_DATA_DIR=./data python run_sync.py

# API
OFAC_DATA_DIR=./data uvicorn app.main:app --port 8090
```

### `POST /screen`

```json
{ "name": "Ivan Ivanov", "entity_type": "Individual", "match_threshold": 85 }
```

Returns `status` (`clear` | `potential_match`), the potential matches, an L4
`receipt` (JSON + HTML) and an `evidence_item`. A `potential_match` is **surfaced
for human adjudication** — it is never an auto-confirmed hit.

## Tests

```bash
python -m pytest        # advanced-schema parser, matcher, receipts, sync, API
```

Tests run against a small synthetic advanced-XML fixture — no ~100 MB download.
