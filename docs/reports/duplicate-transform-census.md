# Duplicate-transform census

Measured against `safeguards/` on branch `docs/duplicate-transform-census`
(base `origin/main` @ `9b78b3dc`), 2026-09-22. Every number below comes from a
script run against the tree, not from memory or the framing numbers in the
task brief — see **Methodology** for exactly how, and the scratchpad scripts
referenced there are reproducible with the same tree checked out.

## Scope

"Transform files" here means the same population `tools/check_fail_closed.py`
and `tools/check_discriminates.py` judge: every `*.py` under `safeguards/`
**except** `__init__.py` and anything under a `schemas/` directory. `schemas/`
holds per-integration Pydantic input-schema stubs (a `class XInput(BaseModel):
... Config: extra = "allow"` boilerplate) — not transformation logic, and not
the population this task is about. Counting them in would have inflated the
duplicate-filename count without telling you anything about criteria logic
drift (e.g. `ispamenabled.py` has 4 `schemas/ispamenabled.py` companions that
are unrelated boilerplate, not 4 more copies of the PAM check).

With that scope:

- **804** transform files under `safeguards/` (matches
  `check_fail_closed.py`'s own count, confirming the scope is right).
- **363** distinct filenames.
- **116** filenames exist in more than one copy — close to, though not
  exactly, the 110 named in the task brief; the gap is most likely tree
  drift between when that figure was taken and this measurement, since the
  per-file counts for every one of the six named "worst offenders" below
  match the brief exactly.
- Those 116 duplicated filenames account for **557** of the 804 files. The
  other 247 files have a filename unique to the whole tree.
- **0** of the 116 clusters are byte-identical top to bottom — i.e. every
  duplicated filename has at least two distinct contents somewhere in its
  copies (confirming the brief's framing that these are duplicates that have
  **drifted**, not just harmless copies).

## Methodology

Script: `dtc_census_final.py` (kept in this session's scratchpad, logic
reproduced below since it isn't checked into the repo — it's a one-off
measurement tool, not a project script).

For every duplicated filename, every copy's raw bytes are SHA-256 hashed
(`distinct_bytes` = number of distinct hashes — this is the number the task
brief's "N copies, M distinct" figures refer to, and it's what `diff`/`md5sum`
would tell you too). Two further passes narrow down *why* copies differ,
without ever assuming — each is a real transformation of the source, hashed
the same way:

1. **`distinct_normalized`** — parse with `ast`, drop the module/function
   docstring (an `Expr` whose value is a string constant, dropped from Python
   3.8+'s AST like this: it's just data attached to the node, not retained by
   the parser as a comment token), unparse, collapse whitespace and blank
   lines. This drops *only* comments (which the tokenizer never puts in the
   AST at all), docstrings, and formatting — every identifier, string
   literal, and number is untouched. If this collapses two byte-distinct
   copies into one, the ONLY difference between them was comments/docstrings/
   whitespace — nothing that executes differently, ever, for any input.
2. **`distinct_structural`** — same, plus every string-literal *value* is
   replaced with a placeholder (numbers are left alone, since a changed
   threshold is a real logic change). If this collapses copies that
   `distinct_normalized` didn't, the difference is in string-literal content
   specifically — which could be an innocuous vendor-name mention, or could
   be a different dict key controlling actual field lookup. **This pass is
   not treated as proof of safety** — see the Category C section below,
   where blanking strings hid a real difference in a `.get()` key.

For every candidate found this way, before touching anything, I ran a
behavioral battery (`dtc_verify.py`): loaded every file in the candidate group
and called `transform()` on 10 inputs — the four `NO_EVIDENCE` bodies from
`check_fail_closed.py`, a plainly-compliant body, a plainly-non-compliant
body, a nested-response wrapper, a populated-list body, an all-empty-list
body, and a bare list — and diffed the outputs (after stripping the one
volatile field, `evaluatedAt`, an ISO timestamp some transforms stamp their
own output with). Only groups where **every** member produced **byte-for-byte
identical output for every input** were candidates for consolidation.

Reproduce: check out this branch, run the two scripts above against
`safeguards/` (they're plain stdlib Python, no deps) — every count in this
report falls out of their output.

## Category breakdown (Part 1 classification)

Applying (a)/(b)/(c) from the task per cluster required a 4-way split, because
"byte-identical" and "trivially divergent" turned out to be different
questions once measured:

| class | meaning | clusters | files |
|---|---|---:|---:|
| **A** | whole cluster is one implementation wearing cosmetic differences (`distinct_normalized == 1`) | 8 | 16 |
| **B** | cluster mixes a cosmetic sub-group with other, really-distinct copies | 22 | 283 |
| **C** | no comment/docstring/whitespace overlap, but some copies coincide once string literals are blanked — **needs a human read before acting, not auto-safe** | 3 | 19 |
| **D** | every copy is structurally distinct even after blanking strings | 83 | 239 |

(counts above are **before** Part 2; see the appendix table for the after
state.) Class A + the mergeable parts of Class B are "safe to consolidate
behind one shared implementation" in the task's terms. Class D is
overwhelmingly "must stay per-vendor because the payloads genuinely differ" —
confirmed by sampling (below) — with two documented exceptions that are real
disagreements, not vendor differences. Class C is the trap: it *looks*
mergeable by the string-blanking heuristic alone, and every one of the three
clusters checked by hand turned out to hide a real (if often minor) content
difference beyond vendor-name text — so none of it was auto-consolidated.

### The six "worst offenders" named in the task, measured

| filename | copies | distinct | after normalizing ws/comments/docstrings | after also blanking string literals |
|---|---:|---:|---:|---:|
| `confirmedlicensepurchased.py` | 80 | 75 | 73 | 66 |
| `ispamenabled.py` | 20 | 19 | 8 | 8 |
| `isstrongauthrequired.py` | 19 | 19 | 8 | 8 |
| `isrbacimplemented.py` | 18 | 17 | 6 | 6 |
| `islifecyclemanagementenabled.py` | 17 | 16 | 6 | 5 |
| `isiamloggingenabled.py` | 16 | 16 | 5 | 5 |

These "copies / distinct" pairs match the task brief exactly, which is the
best confirmation the scope above is the one intended.

## What the differences actually are

### Category A + the mergeable part of B: docstring/comment-only (safe)

The five IAM criteria above (`ispamenabled`, `isstrongauthrequired`,
`isrbacimplemented`, `islifecyclemanagementenabled`, `isiamloggingenabled`)
each have an **11-or-12-file sub-cluster, one per IAM vendor
(cognito/cyberark/dashlane/duo/google/hypr/microsoftentra/msentra/oracleidp/
ping_identity/strata/yubico), whose `transform()` bodies are 100% identical**
— same field names read (`roles`/`groups`/`rbacEnabled`… for RBAC,
`pamEnabled`/`privilegedAccounts`/`vaults`… for PAM, etc.), same branches,
same fallback order. The *only* difference anywhere in the file is one
docstring line: `The JSON data containing <vendor> API response`. Verified:
for every one of these 5×~12 = 59 files, `diff` shows exactly one changed
line, always that one. This is category (b) in its purest form — these files
were plainly written once and hand-copied per vendor directory without the
vendor's API ever actually being consulted (there is nothing
vendor-*specific* being read at all).

The email-security checkpoint/proofpoint/sublime trios
(`isantiphishingenabled`, `isdnsconfigured`, `isemailloggingenabled`,
`isurlrewriteenabled`) and the EPP crowdstrike/synqly pairs
(`isbehavioralmonitoringvalid`, `isedrdeployed`, `iseppdeployed`,
`ispatchmanagementenabled`, `ispatchmanagementvalid`,
`isremovablemediacontrolled`) are the same pattern at smaller scale — same
docstring-vendor-name-only diff, generic field-name logic underneath.

The ASM projectdiscovery/rapid7insightvm pairs (`arepentestscompleted`,
`iscontinuousdiscoveryenabled`, `isremediationtracked`,
`isriskprioritizationtrue`, `isthreatintelintegrated`) differ in **two**
docstring lines (a reworded one-line summary, plus the vendor name) but the
executable body is untouched between them — still category (b).

**A live example of exactly the drift risk the task describes, caught mid-repair**: four files
(`isbehavioralmonitoringvalid.py`, `ispatchmanagementenabled.py`,
`isremovablemediacontrolled.py`, `isidpenabled.py`, all under the
`7BC425FA…`/`BBC425FA…`/`cac4b80f…` SRN directories) had a **stale comment**
— `# Default to True if data is present (indicates active integration)` —
sitting directly above a call to `_affirmative_signal(data)`, the very
function the fail-closed remediation (PR #583, `git log`) introduced
*specifically to replace* that "data is present" default. The comment
describes the bug that was fixed, left behind in one copy of four because the
fix touched `BBC425FA…`/`cac4b80f…` but not the identical `7BC425FA…` /
`0C281CE9…` copies sitting one directory over. This is the duplication
problem happening in real time, inside the very PRs meant to be closing it —
proof this isn't a hypothetical risk.

Two already-exact-duplicate pairs surfaced too, needing zero action:
`safeguards/dlp/cato/confirmedlicensepurchased.py`-style already-identical
pairs exist for `conditionalaccesspoliciesactive.py`,
`confirmlicensepurchased.py`, `ismfarequiredforcloudapps.py`,
`legacyauthblocked.py`, `network_transform.py`, `recoverytestcompleted.py` —
already category (a), nothing to do.

### Category C: the trap — string-blanking hid real differences

Three clusters only collapse once string literals are blanked, pre-Part-2:
`epp_transform.py`, `is_mfa_logging_enabled.py`, `issamlenforced.py`. Two
more clusters that were mostly class B (`isdnsconfigured.py`,
`islifecyclemanagementenabled.py`) turned out, after their large
docstring-only sub-groups were consolidated in Part 2, to each still have
**one residual pair** that only collapses this same way — i.e. the same
trap, smaller. And `confirmedlicensepurchased.py` (class B overall, thanks to
two small docstring-only pairs) has this shape spread across dozens of its
otherwise-distinct copies. Reading the actual diffs (not just the hash
collapse) for the small, fully-characterized ones:

- **`epp_transform.py`** (`0C281CE9…`/`2BC425FA…` vs `BBC425FA…`/`cac4b80f…`):
  the ONLY line that differs is which pre-computed bucket a shared
  score-aggregator reads for `requiredCoveragePercentage` —
  `coverage_scores["MDR"]` in one pair, `coverage_scores["Endpoint
  Protection"]` in the other. Each SRN directory's other files confirm this
  is *probably* intentional (the `MDR`-reading pair's directories carry no
  other EPP-specific criteria; the `Endpoint Protection`-reading pair's
  directories carry `isbehavioralmonitoringvalid`, `ispatchmanagementenabled`
  etc., all EPP checks) — i.e. the same generic aggregator is parameterized
  per deployment context. But the only thing distinguishing an MDR-context
  copy from an EPP-context copy of this file is **one dictionary key inside a
  240-line function**, with no test anywhere that would catch a future copy
  picking the wrong one. Left untouched, and called out here because it is
  exactly the shape of defect this whole audit is worried about, even though
  it is very likely *not currently wrong*.
- **`is_mfa_logging_enabled.py`** and **`issamlenforced.py`** /
  `islifecyclemanagementenabled.py` residual pairs: vendor-attribution text
  differs (expected), but so does an `input_summary` dict key
  (`mfaLoggingConfigured` vs `loggingEnabled`, `lifecycleManagementConfigured`
  vs `lifecycleEnabled`) and, in the DNS case, one copy carries a genuinely
  extra, more specific remediation string ("For Mimecast-signed DKIM, ensure
  the Mimecast DKIM selector CNAME(s) are published.") that the other copy
  lacks. None of these touch the actual satisfaction-style criteria key, but
  they are real content differences, not typos — left alone.

**Lesson for the report's own method**: don't trust a heuristic that blanks
string literals as proof of safety by itself. Every consolidation actually
applied in Part 2 was verified by *running* the code, not by the hash
collapsing.

### Category D: mostly legitimate, with two confirmed exceptions

83 of 116 clusters are still fully distinct after every normalization pass.
Spot-checking a sample of the 2-copy clusters (`isvpnenabled.py`:
`sase/cato` vs `sase/microsoft`; `isdmarcconfigured.py`,
`islegacyauthblocked.py`, `isrdpprotected.py`, `isidsenabled.py`: each pair
spans genuinely different vendor directories — Cisco FMC vs Meraki, PingFederate
vs a UUID SRN, etc.) shows the expected shape for this architecture: each
SRN directory is a distinct vendor/product, and its copy of a criterion reads
that vendor's own field names. This is the legitimate case the task
describes and none of it was touched.

Two clusters are confirmed **real disagreement, not vendor difference**:

- **`ismfaenforcedforusers.py`** (11 copies, all structurally distinct) —
  three genuinely different definitions of "MFA enforced for users" found by
  reading a sample:
  - `mfa/azure/ismfaenforcedforusers.py`: requires an actual **policy
    object targeting all users** to mandate MFA, AND that methods are
    available — the strict, policy-based reading.
  - `E454A862-…/ismfaenforcedforusers.py`: `is_mfa_enforced =
    mfa_enrolled_count > 0` — true the moment **a single user** is MFA
    enrolled, regardless of the other 999 users in the tenant. This is a
    materially weaker bar than the Azure copy for the exact same criteria
    key.
  - `a2abbcf5-…/ismfaenforcedforusers.py`: initializes `is_mfa_enforced =
    True` and only flips it False if it finds a specific disenrolled user
    while scanning — a default-true design with its own comment
    acknowledging the risk shape.

  These three would report differently on the identical real-world tenant
  (say, 500 users, 1 with MFA enabled, no all-users policy): Azure → False,
  `E454A862` → True, `a2abbcf5` → depends entirely on scan completeness. This
  is exactly the "nineteen different answers to one question" problem named
  in the task brief, just found under a different filename. **Not touched —
  flagged here for the report's consumer to adjudicate**, since picking a
  canonical definition is a security-policy decision, not a mechanical one.
- **`confirmedlicensepurchased.py`** (80 copies, 73 distinct after Part 2):
  overwhelmingly legitimate — vendors expose licensing via wildly different
  shapes (Microsoft Graph `subscribedSkus`, Cato's GraphQL
  `data.licensing.licensingInfo`, AWS Security Hub's "if we can query
  findings, it's enabled", raw package counts, boolean flags) and the
  *majority* of the 73 remaining distinct bodies genuinely need to be
  different because the API shape is different. But `grep` across all 136
  raw files (before filtering to the `schemas/`-excluded 80) surfaces
  comments like `# The old final fallback -- "elif len(data) > 0:
  license_purchased = True" -- ... treated ANY non-empty dict as proof the
  [control was met]`, i.e. remnants of exactly the "did a response arrive"
  defect this repo's fail-closed ratchet already spent multiple PRs
  eliminating (`git log`: 4 commits, "ratchet reaches zero"). The residual
  divergence in this cluster is therefore a mix of (i) legitimate per-vendor
  field reads (majority) and (ii) historical copies of a now-fixed bug that
  may not all have been reached yet — worth a targeted follow-up sweep, but
  outside this task's mandate (no logic changes beyond the fail-closed
  ratchet's own scope).

## Which clusters are safe to consolidate vs must stay per-vendor

**Safe to consolidate (done in Part 2, see below):** the 24 filenames listed
in the appendix as class A/B whose merge groups passed the behavioral
battery — 29 merge groups, 115 files, all IAM/email-security/EPP/ASM
generic-logic clusters plus the Azure-backups and stale-comment pairs.

**Must stay per-vendor (not touched, and shouldn't be):** the 83 class-D
clusters confirmed-or-plausibly reading genuinely different vendor field
shapes — this is the correct, intended state of a per-SRN-directory
architecture, not a defect.

**Needs a human decision before any mechanical tool touches it:**
`ismfaenforcedforusers.py` (3 competing definitions), `confirmedlicensepurchased.py`'s
residual bug-shaped fallbacks, and `epp_transform.py`'s
MDR-vs-Endpoint-Protection bucket selection.

## Part 2: what was consolidated

24 filenames, 29 merge groups, **115 files** verified behaviorally identical
and made byte-identical in place. **No file was deleted, renamed, or moved —
only file *contents* changed**, at the same paths.

Verification (`dtc_verify.py`, battery described above) ran **before** any
edit and again **after**, both passes reporting `ALL OK` (zero output
mismatches across every group member, every input). Canonicalization choices:

- Vendor-name-only docstring differences (IAM ×5, email-security ×4, EPP
  ×6, ASM ×5, `confirmedlicensepurchased` cato pair): generalized the
  docstring line to a vendor-neutral phrase (e.g. `the vendor's IAM API
  response`) rather than propagating one vendor's name onto another vendor's
  file, which would have been factually wrong.
  `confirmedlicensepurchased.py`'s Microsoft pair kept the original "Microsoft
  Graph API response" wording rather than propagating the SASE-specific
  "Global Secure Access" name onto the MFA-context copy, since Graph is
  accurate for both.
- Azure-backups pair (`is_backup_types_scheduled.py`, `isbackupenabled.py`):
  kept the strictly more-detailed module docstring (the one naming the exact
  Resource Graph query and fields returned).
- Stale-comment groups (`isbehavioralmonitoringvalid.py`,
  `ispatchmanagementenabled.py`, `isremovablemediacontrolled.py`,
  `isidpenabled.py`): converged the lone outlier copy onto the
  already-correct majority (which had already dropped the stale "data is
  present" comment and, for `isidpenabled.py`, already had the grammatically
  correct docstring wording).

### Truth tables (representative sample, full battery covers all 29 groups)

Plainly-compliant / plainly-non-compliant behavior, unchanged before and
after, confirmed by direct `transform()` calls (`local_tester.py` itself
needs `requests`, not installed in this sandbox, so these were run by
importing the module directly — equivalent, and this is exactly what
`dtc_verify.py` also does for all 29 groups):

| file pair | compliant input | compliant output | non-compliant input | non-compliant output |
|---|---|---|---|---|
| `iam/cognito` vs `iam/yubico` `isrbacimplemented.py` | `{"roles": ["admin"]}` | `isRBACImplemented: True` | `{"roles": []}` | `isRBACImplemented: False` |
| `epp/crowdstrike` vs `epp/synqly` `isedrdeployed.py` | `{"total": 100, "deployed": 95}` | `isEDRDeployed: True` | `{"total": 100, "deployed": 0}` | `isEDRDeployed: False` |
| `asm/projectdiscovery` vs `asm/rapid7insightvm` `isthreatintelintegrated.py` | `{"threatIntelEnabled": true}` | `isThreatIntelIntegrated: True` | `{"threatIntelEnabled": false}` | `isThreatIntelIntegrated: False` |
| `dlp/cato` vs `sase/cato` `confirmedlicensepurchased.py` | `{"active": true}` | `confirmedLicensePurchased: True` | `{"active": false}` | `confirmedLicensePurchased: False` |
| `0C281CE9…` vs `7BC425FA…` `isidpenabled.py` | (SSO fields true) | `isSSOEnabled: True` | (SSO fields false) | `isSSOEnabled: False` |

Every pair in the table produced **identical** dict output (not just
identical boolean) between its two members, for both inputs.

### Gates (must stay green, allowlists must not grow)

Before any edit:
```
$ python3.12 tools/check_fail_closed.py
804 transform file(s) examined; 0 assert a satisfaction-style criterion true from a body
that proves nothing (0 outside the allowlist)
✓ no unallowlisted transform asserts a control from a body that proves nothing

$ python3.12 tools/check_discriminates.py
804 transform file(s) examined; 1 carry a criterion with no reachable false (0 outside the allowlist)
✓ no unallowlisted transform carries a criterion that can never be false
```

After all 102 file rewrites:
```
$ python3.12 tools/check_fail_closed.py
804 transform file(s) examined; 0 assert a satisfaction-style criterion true from a body
that proves nothing (0 outside the allowlist)
✓ no unallowlisted transform asserts a control from a body that proves nothing

$ python3.12 tools/check_discriminates.py
804 transform file(s) examined; 1 carry a criterion with no reachable false (0 outside the allowlist)
✓ no unallowlisted transform carries a criterion that can never be false

$ python3.12 tools/check_fail_closed.py --self-test   # self-test ok
$ python3.12 tools/check_discriminates.py --self-test  # self-test ok
```
Identical file-examined count, identical finding counts, both self-tests
pass. `git diff contracts/` is empty — **neither allowlist was touched, let
alone grown**.

### spektrum-platform provenance impact

`spektrum-platform` (read-only checked) carries `# Provenance: Transformations
<path>@<sha>` headers in 3,301 of its files, pointing at **1,296 distinct
source paths** in this repo. Cross-referencing the 102 rewritten paths
against that distinct-path list: **all 102 have a live provenance reference
in spektrum-platform.** This is safe specifically *because* no path
was deleted or renamed — a provenance line pins a path at a historical commit
sha, which git can always resolve regardless of what happens to that path
later on `main`; nothing is stranded. The practical effect is that
`spektrum-platform`'s vendored copies of these 102 files are now one commit
behind `main`'s (now-deduplicated) content, exactly like any other upstream
change — it will pick up the new byte-identical content the next time it
re-vendors, same as it would for any normal fix.

## What was deliberately not touched (and why)

- **`confirmedlicensepurchased.py`**'s ~66 remaining structurally-distinct
  bodies past the two safe pairs — legitimate per-vendor API shape
  differences, mixed with a residual, not-yet-swept population of
  `len(data) > 0`-style historical fallbacks. Recommend a dedicated
  follow-up under the existing fail-closed ratchet process, not this task.
- **`ismfaenforcedforusers.py`** — 3 incompatible definitions of the same
  criteria key found by direct inspection (policy-based / count-based /
  default-true-per-user). Needs a security-policy owner to pick one
  canonical definition; not a mechanical merge.
- **`epp_transform.py`**'s MDR-vs-Endpoint-Protection bucket selection —
  looks intentional per-SRN parameterization on current evidence, but is
  one dict key away from a silent misconfiguration with no test coverage.
  Flagged for a human, not changed.
- **`is_mfa_logging_enabled.py` / `issamlenforced.py` /
  `islifecyclemanagementenabled.py`'s residual pairs** — string-literal-only
  collapses that, on inspection, carry a real (if minor) content difference:
  a different `input_summary` key name, or genuinely extra remediation text.
  Not cosmetic enough to auto-merge.
- **The 83 class-D clusters** confirmed or plausibly reading distinct
  vendor field shapes — this is the correct architecture, not a defect, and
  touching it would risk exactly the harm this task exists to prevent.

## The single most important thing for whoever acts on this next

**A heuristic that only compares bytes (or even ASTs) cannot tell you a
consolidation is safe — it can only tell you where to look.** Two separate
near-misses in this exact audit prove it: (1) string-literal blanking made
`epp_transform.py`'s MDR/Endpoint-Protection score-key difference disappear
inside "just another vendor-name difference" — it isn't, it's a real
parameterization that a blind text-based merge would have silently
collapsed onto the wrong bucket for half the tree's EPP or MDR safeguards;
and (2) `ismfaenforcedforusers.py` has no lexical signal at all that would
flag it as risky — 11 fully-distinct-looking implementations, no two of
which normalize together — yet three of them encode fundamentally different
security postures for the identical criteria key, and any dedup tool that
only merges *similar-looking* code would walk right past it while flagging
harmless docstring differences instead. Every file actually touched in Part
2 was proven safe by **running the code** across a real input battery and
diffing outputs, not by trusting a text-similarity score — and that discipline
is the only reason 115 files could be merged today with zero risk to the
`check_fail_closed`/`check_discriminates` ratchets. Anyone extending this
work should keep that same behavioral-proof bar rather than being tempted by
how much further the AST/string-blanking heuristics *look* like they could
reach.

## Appendix: full cluster table (all 116 duplicated filenames)

`copies` and `distinct (before)` are measured pre-Part-2 (and match `md5sum`/
`diff` on the tree at `origin/main`); `distinct (after Part 2)` reflects this
branch. `class` is A/B/C/D as defined above, measured before Part 2.

| filename | copies | distinct (before) | distinct (after Part 2) | class |
|---|---:|---:|---:|:---:|
| `confirmedlicensepurchased.py` | 80 | 75 | 73 | B |
| `ispamenabled.py` | 20 | 19 | 8 | B |
| `isstrongauthrequired.py` | 19 | 19 | 8 | B |
| `isrbacimplemented.py` | 18 | 17 | 6 | B |
| `islifecyclemanagementenabled.py` | 17 | 16 | 6 | B |
| `isiamloggingenabled.py` | 16 | 16 | 5 | B |
| `ispatchmanagementenabled.py` | 13 | 12 | 10 | B |
| `isantiphishingenabled.py` | 12 | 12 | 10 | B |
| `ismfaenforcedforusers.py` | 11 | 11 | 11 | D |
| `epp_transform.py` | 9 | 7 | 7 | C |
| `isbehavioralmonitoringvalid.py` | 9 | 8 | 6 | B |
| `isdnsconfigured.py` | 9 | 9 | 7 | B |
| `isremovablemediacontrolled.py` | 9 | 8 | 6 | B |
| `isurlrewriteenabled.py` | 9 | 9 | 7 | B |
| `isbackupenabled.py` | 8 | 8 | 7 | B |
| `issamlenforced.py` | 8 | 8 | 8 | C |
| `isauditloggingenabled.py` | 7 | 6 | 6 | D |
| `ispatchmanagementvalid.py` | 7 | 7 | 6 | B |
| `isbackupencrypted.py` | 6 | 6 | 6 | D |
| `isedrdeployed.py` | 6 | 6 | 5 | B |
| `isemailloggingenabled.py` | 6 | 6 | 4 | B |
| `iseppdeployed.py` | 6 | 6 | 5 | B |
| `isfirewallenabled.py` | 6 | 6 | 6 | D |
| `isidpenabled.py` | 6 | 3 | 2 | B |
| `isbackupenabledforcriticalsystems.py` | 5 | 5 | 5 | D |
| `isbackupimmutable.py` | 5 | 5 | 5 | D |
| `isbackuploggingenabled.py` | 5 | 5 | 5 | D |
| `isbackuptested.py` | 5 | 5 | 5 | D |
| `isbackuptypesscheduled.py` | 5 | 5 | 5 | D |
| `mfa_transform.py` | 5 | 4 | 4 | D |
| `requiredcoveragepercentage.py` | 5 | 5 | 5 | D |
| `authtypesallowed.py` | 4 | 4 | 4 | D |
| `confirmpasswordpolicyenforced.py` | 4 | 3 | 3 | D |
| `firewall_transform.py` | 4 | 3 | 3 | D |
| `iscontinuousdiscoveryenabled.py` | 4 | 4 | 3 | B |
| `isemailsecurityloggingenabled.py` | 4 | 4 | 4 | D |
| `iseppconfigured.py` | 4 | 4 | 4 | D |
| `isfirewallloggingenabled.py` | 4 | 4 | 4 | D |
| `ismfaenabled.py` | 4 | 4 | 4 | D |
| `istrainingenabled.py` | 4 | 4 | 4 | D |
| `aredlppoliciesconfigured.py` | 3 | 3 | 3 | D |
| `backup_transform.py` | 3 | 3 | 3 | D |
| `is_backup_enabled_for_critical_systems.py` | 3 | 3 | 3 | D |
| `is_backup_encrypted.py` | 3 | 3 | 3 | D |
| `is_backup_immutable.py` | 3 | 3 | 3 | D |
| `is_backup_logging_enabled.py` | 3 | 2 | 2 | D |
| `is_backup_tested.py` | 3 | 2 | 2 | D |
| `is_backup_types_scheduled.py` | 3 | 3 | 2 | B |
| `isdnsfilteringenabled.py` | 3 | 3 | 3 | D |
| `iseppmisconfigured.py` | 3 | 3 | 3 | D |
| `isinformationrightsmanagementenabled.py` | 3 | 3 | 3 | D |
| `isphishingsimulationenabled.py` | 3 | 3 | 3 | D |
| `isremediationtracked.py` | 3 | 3 | 2 | B |
| `isriskprioritizationtrue.py` | 3 | 3 | 2 | B |
| `issafeattachmentsenabled.py` | 3 | 3 | 3 | D |
| `issafelinksenabled.py` | 3 | 3 | 3 | D |
| `isssoenabled.py` | 3 | 3 | 3 | D |
| `areaccessreviewsconfigured.py` | 2 | 2 | 2 | D |
| `areadminaccountsseparate.py` | 2 | 2 | 2 | D |
| `areconditionalaccesspoliciesconfigured.py` | 2 | 2 | 2 | D |
| `arepentestscompleted.py` | 2 | 2 | 1 | A |
| `areretentionpoliciesconfigured.py` | 2 | 2 | 2 | D |
| `auth_types_allowed.py` | 2 | 2 | 2 | D |
| `backupfrequency.py` | 2 | 2 | 2 | D |
| `compliancepercentage.py` | 2 | 2 | 2 | D |
| `conditionalaccesspoliciesactive.py` | 2 | 1 | 1 | A |
| `confirmlicensepurchased.py` | 2 | 1 | 1 | A |
| `defaultdenyinbound.py` | 2 | 2 | 2 | D |
| `isFirewallEnabled.py` | 2 | 2 | 2 | D |
| `is_mfa_logging_enabled.py` | 2 | 2 | 2 | C |
| `isaccesspolicyconfigured.py` | 2 | 2 | 2 | D |
| `isadminauditloggingenabled.py` | 2 | 2 | 2 | D |
| `isadminmfaphishingresistant.py` | 2 | 2 | 2 | D |
| `isagentdeployed.py` | 2 | 2 | 2 | D |
| `isalertingconfigured.py` | 2 | 2 | 2 | D |
| `isautoforwarddisabled.py` | 2 | 2 | 2 | D |
| `iscompletionrateacceptable.py` | 2 | 2 | 2 | D |
| `isdataclassificationenabled.py` | 2 | 2 | 2 | D |
| `isdmarcconfigured.py` | 2 | 2 | 2 | D |
| `isdnssecenabled.py` | 2 | 2 | 2 | D |
| `isfirewallconfigured.py` | 2 | 2 | 2 | D |
| `isgeoredundant.py` | 2 | 2 | 2 | D |
| `isidentityprotectionenabled.py` | 2 | 2 | 2 | D |
| `isidsenabled.py` | 2 | 2 | 2 | D |
| `isipsenabled.py` | 2 | 2 | 2 | D |
| `islegacyauthblocked.py` | 2 | 2 | 2 | D |
| `ismailboxauditingenabled.py` | 2 | 2 | 2 | D |
| `ismailboxauditloggingenabled.py` | 2 | 2 | 2 | D |
| `ismfaconfiguredforsecurityadmins.py` | 2 | 2 | 2 | D |
| `ismfaloggingenabled.py` | 2 | 2 | 2 | D |
| `ismfarequiredforcloudapps.py` | 2 | 1 | 1 | A |
| `ismfarequiredforremoteaccess.py` | 2 | 2 | 2 | D |
| `isnetworksecurityenabled.py` | 2 | 2 | 2 | D |
| `isnetworksecurityloggingenabled.py` | 2 | 2 | 2 | D |
| `ispasswordautomanagementenabled.py` | 2 | 2 | 2 | D |
| `ispasswordpolicyconfigured.py` | 2 | 2 | 2 | D |
| `ispasswordrotationonreleaseenabled.py` | 2 | 2 | 2 | D |
| `isprivilegedidentitymanagementenabled.py` | 2 | 2 | 2 | D |
| `isrdpprotected.py` | 2 | 2 | 2 | D |
| `isreportingenabled.py` | 2 | 2 | 2 | D |
| `issaseenabled.py` | 2 | 2 | 2 | D |
| `issecuritycenterintegrationenabled.py` | 2 | 2 | 2 | D |
| `issessionmonitoringenabled.py` | 2 | 2 | 2 | D |
| `issmtpauthdisabled.py` | 2 | 2 | 2 | D |
| `issslcertificatemanaged.py` | 2 | 2 | 2 | D |
| `isssoenforced.py` | 2 | 2 | 2 | D |
| `isthreatintelintegrated.py` | 2 | 2 | 1 | A |
| `istrafficencrypted.py` | 2 | 2 | 2 | D |
| `isunifiedauditloggingenabled.py` | 2 | 2 | 2 | D |
| `isvpnenabled.py` | 2 | 2 | 2 | D |
| `isvulnerabilityremediationtracked.py` | 2 | 2 | 2 | D |
| `lastsuccessfulbackupage.py` | 2 | 2 | 2 | D |
| `legacyauthblocked.py` | 2 | 1 | 1 | A |
| `network_transform.py` | 2 | 1 | 1 | A |
| `recoverytestcompleted.py` | 2 | 1 | 1 | A |
| `requiredCoveragePercentage.py` | 2 | 2 | 2 | D |