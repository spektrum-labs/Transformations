---
name: docs-sync
description: Bring docs2/ back in sync with the code after changes — run the drift check, re-verify affected claims against the diff, edit the docs, re-validate diagrams and links, and bump the verification pin. Use after merging code changes, when CI's docs-drift job reports staleness, or before a release.
---

# docs-sync — keep docs2/ true to the code

docs2/ is the ground-truth documentation set. Its contract: **every factual
claim cites `path:line` and is verified against the commit pinned in
docs2/README.md** (the `` `develop @ <sha>` `` marker). This skill closes the
gap between that pin and the current code.

## Procedure

1. **Find the drift.** Run:
   ```bash
   python3 scripts/docs_drift_check.py
   ```
   It compares the pin to HEAD using two signals: docs that cite changed
   files, and docs whose `.docmap.yml` territory contains changed files.
   If it prints `OK`, only the pin bump (step 5) is needed.

2. **Understand the code change, not the doc.** For each affected doc, read
   the actual diff of the files it cites (`git diff <pin> HEAD -- <file>`) and
   the surrounding code. Never update a doc from the diff message or PR
   description alone — the code is the ground truth, commit messages are not.

3. **Update the doc surgically.** Fix only what the change invalidated:
   - the claim itself, if behavior changed;
   - the `path:line` citation, if code moved (re-read the file to get real
     line numbers — never guess or arithmetic-shift them);
   - any mermaid diagram depicting the changed flow;
   - the Gotchas section, if the change fixes or introduces one;
   - 14-known-issues.md, if the change resolves a listed issue (mark it
     resolved with the fixing commit — do not silently delete the row).
   Keep the doc's template (one-sentence → five-minute version → mechanism →
   gotchas) and voice intact. If new behavior deserves new documentation,
   add it to the doc that owns the territory per docs2/.docmap.yml, and add
   a `.docmap.yml` entry if the territory itself is new.

4. **Re-validate mechanically.** All three must pass:
   ```bash
   # every mermaid block must render (extract fenced blocks, run mmdc on each)
   npx -y @mermaid-js/mermaid-cli -i <block.mmd> -o /tmp/out.svg --quiet
   # links, anchors, nav, and site build
   mkdocs build 2>&1 | grep -v 'screenshots/'   # only pending-screenshot warnings are acceptable
   # drift is closed
   python3 scripts/docs_drift_check.py --base <new-pin>
   ```
   Mermaid rules: never quote sequenceDiagram participant aliases; no `;`
   inside sequence messages; quote node labels containing spaces/parens/
   slashes/colons.

5. **Bump the pin.** Update the `` `develop @ <sha>` `` marker and date in
   docs2/README.md AND in the header line of every doc you touched (leave
   untouched docs at their last-verified pin — the header is per-doc honest).

6. **Commit** the doc changes separately from code changes, message prefixed
   `docs:`, describing which claims changed and why.

## Rules

- Keep the formatting standard the set follows: scannable over prose. Outside
  `<details>` blocks no paragraph exceeds 3 sentences; enumerating prose is
  bullets with **bold lead-ins**; flows are numbered steps; enumerables are
  tables; gotchas/invariants/asides are GitHub-alert callouts (`> [!WARNING]`,
  `> [!IMPORTANT]`, `> [!NOTE]`, `> [!TIP]`, `> [!CAUTION]` — these render on
  GitHub and as boxes in MkDocs); heavy detail folds into `<details>`; where a
  paragraph describes structure or a flow, prefer a small mermaid diagram
  re-expressing the cited facts.
- A claim you cannot re-verify in code does not go in a doc — move it to the
  doc's Open questions section, marked `(unverified)`.
- Never soften a gotcha to make a diff smaller.
- Screenshot placeholders (`![Screenshot needed: ...](screenshots/<slug>.png)`)
  and docs2/screenshots/README.md must stay reconciled: renaming or adding a
  placeholder means updating the manifest table and checklist.
- If the drift is too large to fix confidently (e.g. a subsystem rewrite),
  say so and mark the affected doc's header `Status: stale — <area> rewritten
  in <commit>` rather than guessing.
