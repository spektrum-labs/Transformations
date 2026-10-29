"""
Transformation: asm_nuclei_transform
Vendor: Project Discovery (Nuclei)
Category: Attack Surface Management

Evaluates nuclei vulnerability scan results to determine whether
critical or high severity findings are present for a scanned domain.

A capped scan (more hosts discovered than scanned, the ASM host cap) that found no critical or high
finding returns None for both keys with the coverage reason in dataCollection.errors: zero findings on a
partial estate is not proof of no findings in scope, so Token-Service reads it as Unevaluated, never a pass. A capped scan
that did find a critical or high finding still fails, with the coverage named in failReasons. Each row reads

Unresponsive surface (29 Oct 2026): the Integration Service lists hosts whose scan batches time out or
error under ``unresponsiveHosts`` (asm_scan_reuse section 11), each with its consecutive failed scans
(``consecutiveTimeouts``) and whether a continuation already retried it (``retried``). A host that has
failed on two consecutive scans, or that failed again on its retry, is not unscanned surface: it does not
answer the scanner, and the Integration Service stops retrying it inside the window. When every host the
scan did not cover is such a host, the scan is complete for the hosts that answer: the keys are evaluated on
them and the unresponsive hosts are named in passReasons and inputSummary. A first failure the continuation
will still retry keeps the partial rule (None), naming the hosts that will be retried. A host-capped scan,
or one whose missing hosts are not all unresponsive, keeps the partial rule as before.
one key from a single-severity scan (noCriticalFindings from the critical scan, noHighFindings from the high
scan), so a response is only ever read for the key whose severity it scanned.

A scan the Integration Service has no result for (status "error" with a reason such as asm_scan_in_progress or
asm_scan_retry_backoff) returns None for both keys, and the reason is passed on as dataCollection.errorCode, so
a scan that is still running is not mistaken for a failed one. Every error path returns None with the reason
in dataCollection.errors, never False: any other reason, no reason, a malformed reason, an input that failed
validation, a scan with zero or failed hosts, and an exception inside the transform.
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "asm_nuclei_transform",
                "vendor": "Project Discovery",
                "category": "Attack Surface Management"
            }
        }
    }


def to_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


CHRONIC_AFTER_FAILURES = 2  # asm_scan_reuse.CHRONIC_AFTER_FAILURES: failed scans after which a host is written off
NAMED_HOSTS = 10            # how many unresponsive hosts a reason line names


def is_true(value):
    return value is True or str(value).strip().lower() == "true"


def unresponsive_hosts(data):
    """(written_off, pending): the hosts the Integration Service lists as unresponsive, split into those
    it has stopped retrying inside the window (failed on CHRONIC_AFTER_FAILURES consecutive scans, or
    retried by a continuation and failed again) and those a continuation will still retry."""
    written_off = []
    pending = []
    for host in data.get("unresponsiveHosts") or []:
        if not isinstance(host, dict):
            continue
        name = str(host.get("domain") or "unknown")
        failures = to_int(host.get("consecutiveTimeouts")) or 0
        if failures >= CHRONIC_AFTER_FAILURES or is_true(host.get("retried")):
            written_off.append(name)
        else:
            pending.append(name)
    return written_off, pending


def unresponsive_surface(data, written_off, pending):
    """True when the scan covered every discovered host that answers: the only hosts it did not scan
    are written-off unresponsive ones. Such a scan is complete for the surface that exists."""
    if pending or not written_off:
        return False
    scanned = to_int(data.get("domainsScanned"))
    discovered = to_int(data.get("totalDiscovered"))
    if scanned is None or discovered is None or scanned <= 0:
        return False
    return scanned + len(written_off) >= discovered


def named(hosts):
    shown = ", ".join(hosts[:NAMED_HOSTS])
    return shown + (" and " + str(len(hosts) - NAMED_HOSTS) + " more" if len(hosts) > NAMED_HOSTS else "")


def capped_note(data):
    """The reason a zero would be partial (more hosts discovered than scanned), else None."""
    scanned = to_int(data.get("domainsScanned"))
    discovered = to_int(data.get("totalDiscovered"))
    flagged = data.get("domainsCapped") is True or str(data.get("domainsCapped")).strip().lower() == "true"
    short = scanned is not None and discovered is not None and 0 < scanned < discovered
    if not (flagged or short):
        return None
    domain = data.get("primaryDomain") or data.get("domain") or "unknown"
    return ("Only " + str(scanned) + " of " + str(discovered) + " discovered host(s) of " + str(domain)
            + " were scanned")


# --- scan reason ----------------------------------------------------------------------------------------
# The Integration Service answers a scan it has no result for as {"status": "error", "reason": "<code>",
# "message": ...}: asm_scan_in_progress (a scan is still running), asm_scan_retry_backoff (the last scan
# produced nothing usable, so no new scan was started), asm_scan_shared_no_result and
# asm_scan_max_duration_exceeded. The code is passed on as dataCollection.errorCode, so a reader can tell a scan
# that is still running from a broken integration. An error reply measured nothing, so the criterion is None
# (Not evaluated), never False, whatever the reason: an asm_scan_ code, any other code, no reason, or a reason
# that is not a plain code (that one is dropped, and the text stays generic).
SCAN_REASON_MAX_LENGTH = 60
SCAN_REASON_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789_"
SCAN_REASON_TEXT = {
    "asm_scan_in_progress": "the scan is still running; its result is read on the next evaluation",
    "asm_scan_retry_backoff": "the last scan produced no usable result, so a new scan has not started yet",
    "asm_scan_shared_no_result": "the scan that was already running produced no usable result",
    "asm_scan_max_duration_exceeded": "the scan ran past its time limit",
}


def scan_reason(data):
    """The reason code of a scan reply that is not a result: a plain lower-case code of at most 60 characters,
    else None (a successful scan, no reason, or a reason that is not a plain code)."""
    if not isinstance(data, dict) or data.get("status") == "success":
        return None
    reason = data.get("reason")
    if not isinstance(reason, str):
        return None
    reason = reason.strip().lower()
    if not reason or len(reason) > SCAN_REASON_MAX_LENGTH:
        return None
    for ch in reason:
        if ch not in SCAN_REASON_CHARS:
            return None
    return reason


def scan_status_problem(status, domain, reason):
    """The error text for a scan reply that is not a result."""
    if reason is None:
        return "Nuclei scan status: " + str(status) + " for " + str(domain)
    if reason.startswith("asm_scan_"):
        return ("Nuclei scan not evaluated (" + reason + "): "
                + SCAN_REASON_TEXT.get(reason, "the scan did not produce a result"))
    return "Nuclei scan status: " + str(status) + " (" + reason + ") for " + str(domain)


def with_error_code(response, error_code):
    """Label a reply with the reason code the Integration Service gave, when it gave one."""
    if error_code:
        response["additionalInfo"]["dataCollection"]["errorCode"] = error_code
    return response
# --- end scan reason -------------------------------------------------------------------------------------


# --- evidenceItems (gap disputes) -----------------------------------------------------------------------
# Each offending finding becomes {fingerprint, kind, label, severity}. The fingerprint is the identity of the
# thing found, so a rescan with different counts or timestamps yields the same value and a new finding a new one:
#   fingerprint = sha256_hex(template-id + "|" + scheme://host[:port] + path)
# When a finding carries a matcher-name the template part is template-id + "#" + matcher-name, so two matchers of
# one template on one URL stay distinct; without a matcher-name the form above is unchanged.
# Normalisation of the finding's matched-at (host as a fallback): scheme and host lower-cased; userinfo, query
# string and fragment removed; the default port (80 for http, 443 for https) and a trailing dot on the host
# removed; trailing slashes removed from the path, so the root path is "" and https://h/ equals https://h; the
# path keeps its case and its percent-encoding. A value with no scheme gets the scheme "unknown". The sandbox
# allows no hashlib, so SHA-256 is implemented here; this block is identical in every ProjectDiscovery file and
# test_evidence_items.py checks it against hashlib.
SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]


def rotr32(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


def sha256_hex(text):
    data = list(str(text).encode("utf-8"))
    bit_length = len(data) * 8
    data = data + [0x80]
    while len(data) % 64 != 56:
        data = data + [0]
    data = data + [(bit_length >> (8 * (7 - i))) & 0xff for i in range(8)]
    h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    for start in range(0, len(data), 64):
        w = [(data[start + 4 * i] << 24) | (data[start + 4 * i + 1] << 16) | (data[start + 4 * i + 2] << 8)
             | data[start + 4 * i + 3] for i in range(16)]
        for i in range(16, 64):
            s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w = w + [(w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff]
        a, b, c, d, e, f, g, hh = h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
        for i in range(64):
            t1 = (hh + (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) + ((e & f) ^ ((e ^ 0xffffffff) & g))
                  + SHA256_K[i] + w[i]) & 0xffffffff
            t2 = ((rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & 0xffffffff
            hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xffffffff, c, b, a, (t1 + t2) & 0xffffffff
        h = [(h[0] + a) & 0xffffffff, (h[1] + b) & 0xffffffff, (h[2] + c) & 0xffffffff, (h[3] + d) & 0xffffffff,
             (h[4] + e) & 0xffffffff, (h[5] + f) & 0xffffffff, (h[6] + g) & 0xffffffff, (h[7] + hh) & 0xffffffff]
    digits = "0123456789abcdef"
    return "".join(["".join([digits[(word >> shift) & 15] for shift in (28, 24, 20, 16, 12, 8, 4, 0)]) for word in h])


def normalise_location(raw):
    """(scheme, host, path) of a nuclei matched-at / host value, normalised as described above."""
    text = str(raw or "").strip().split("#")[0].split("?")[0]
    scheme = "unknown"
    if "://" in text:
        scheme, text = text.split("://", 1)
        scheme = scheme.strip().lower() or "unknown"
    slash = text.find("/")
    authority = text if slash < 0 else text[:slash]
    path = "" if slash < 0 else text[slash:]
    authority = authority.split("@")[-1].strip().lower()
    port = ""
    if authority.startswith("["):
        close = authority.find("]")
        if close >= 0:
            port = authority[close + 2:] if authority[close + 1:close + 2] == ":" else ""
            authority = authority[:close + 1]
    elif ":" in authority:
        authority, port = authority.rsplit(":", 1)
    authority = authority.rstrip(".")
    if port and not ((scheme == "http" and port == "80") or (scheme == "https" and port == "443")):
        authority = authority + ":" + port
    return scheme, authority or "unknown", path.rstrip("/")


def evidence_item(finding):
    """One evidenceItems entry for an offending nuclei finding (see the block comment above)."""
    info = finding.get("info") if isinstance(finding.get("info"), dict) else {}
    template_id = str(finding.get("template-id") or info.get("name") or "unknown").strip()
    scheme, host, path = normalise_location(finding.get("matched-at") or finding.get("host"))
    sev = info.get("severity") or finding.get("severity")
    matcher = str(finding.get("matcher-name") or "").strip()
    if matcher:
        template_id = template_id + "#" + matcher
    return {"fingerprint": sha256_hex(template_id + "|" + scheme + "://" + host + path), "kind": "asm_finding",
            "label": template_id + " at " + host + path, "severity": str(sev or "").strip().lower()}


def evidence_items(findings):
    """Unique evidenceItems for the offending findings, ordered by fingerprint so scan order never matters."""
    seen = {}
    for finding in findings:
        if isinstance(finding, dict):
            item = evidence_item(finding)
            seen[item["fingerprint"]] = item
    return [seen[key] for key in sorted(seen.keys())]
# --- end evidenceItems -----------------------------------------------------------------------------------


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            reason = "Input validation failed: the scan response did not match its schema, so the findings are unknown"
            return create_response(
                result={"noCriticalFindings": None, "noHighFindings": None},
                validation=validation,
                api_errors=[reason],
                fail_reasons=[reason]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        # Extract scan metadata
        scan_status = data.get("status", "unknown")
        domain = data.get("primaryDomain") or data.get("domain") or "unknown"
        total_findings = data.get("total", 0)
        findings = data.get("findings", [])
        stderr = data.get("stderr", "")

        # Check for scan errors. A reply that carries a reason is labelled with it (dataCollection.errorCode);
        # an asm_scan_ reason (still running, waiting to retry, ...) measured nothing, so both keys are None.
        if scan_status != "success":
            reason_code = scan_reason(data)
            if reason_code is None:
                problem = f"Nuclei scan status: {scan_status}"
                scan_fail_reason = f"Scan did not complete successfully for {domain}"
            else:
                problem = scan_status_problem(scan_status, domain, reason_code)
                scan_fail_reason = problem
            return with_error_code(
                create_response(
                    result={"noCriticalFindings": None, "noHighFindings": None},
                    validation=validation,
                    api_errors=[problem],
                    fail_reasons=[scan_fail_reason],
                    input_summary={"domain": domain, "status": scan_status, "stderr": stderr}
                ),
                reason_code
            )

        # A "success" that scanned nothing, or where a domain's scan errored, proves nothing:
        # zero findings there must not read as "no critical/high findings".
        domain_results = data.get("domainResults") or []
        failed_domains = [r.get("domain", "unknown") for r in domain_results
                          if isinstance(r, dict) and r.get("status") not in ("success", "unresponsive")]
        scan_errors = data.get("errors") or []
        domains_scanned = None
        if "domainsScanned" in data:
            try:
                domains_scanned = int(str(data.get("domainsScanned")).strip())
            except (TypeError, ValueError):
                domains_scanned = 0

        # Count findings by severity (before the guard below, so a finding seen on a partial scan still fails)
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        info_count = 0
        critical_findings = []
        high_findings = []

        for finding in findings:
            severity = ""
            # Nuclei findings store severity in info.severity
            info = finding.get("info", {})
            if isinstance(info, dict):
                severity = str(info.get("severity", "")).lower()
            # Fallback: check top-level severity field
            if not severity and isinstance(finding, dict):
                severity = str(finding.get("severity", "")).lower()

            if severity == "critical":
                critical_count += 1
                critical_findings.append(finding)
                finding_name = info.get("name", "Unknown") if isinstance(info, dict) else "Unknown"
                additional_findings.append(f"CRITICAL: {finding_name}")
            elif severity == "high":
                high_count += 1
                high_findings.append(finding)
                finding_name = info.get("name", "Unknown") if isinstance(info, dict) else "Unknown"
                additional_findings.append(f"HIGH: {finding_name}")
            elif severity == "medium":
                medium_count += 1
            elif severity == "low":
                low_count += 1
            elif severity == "info":
                info_count += 1

        if domains_scanned is not None and domains_scanned <= 0:
            reason = f"Nuclei scanned zero domains for {domain}"
        elif failed_domains or scan_errors:
            reason = (f"Nuclei scan failed for {max(len(failed_domains), len(scan_errors))} "
                      f"domain(s) of {domain}")
        else:
            reason = None
        if reason:
            # A failed host can hide findings, so a clean answer is unknown (None). It cannot remove a finding
            # actually seen on another host: a key with a finding keeps its measured False.
            if domains_scanned is not None and domains_scanned <= 0:
                critical_count = 0
                high_count = 0
            return create_response(
                result={"noCriticalFindings": False if critical_count else None,
                        "noHighFindings": False if high_count else None},
                validation=validation,
                api_errors=[reason],
                fail_reasons=[reason],
                input_summary={"domain": domain, "status": scan_status, "domainsScanned": domains_scanned,
                               "failedDomains": failed_domains[:20], "errorCount": len(scan_errors),
                               "criticalCount": critical_count, "highCount": high_count}
            )

        no_critical = critical_count == 0
        no_high = high_count == 0

        capped = capped_note(data)
        written_off, pending = unresponsive_hosts(data)
        complete_for_surface = bool(capped) and unresponsive_surface(data, written_off, pending)
        coverage_note = None
        if complete_for_surface:
            # The hosts not scanned do not answer the scanner on repeated attempts: they are unresponsive
            # surface, not unscanned surface, so the keys are evaluated on the hosts that answered.
            coverage_note = (str(len(written_off)) + " of " + str(to_int(data.get("totalDiscovered")))
                             + " discovered host(s) of " + str(domain) + " did not answer repeated scans and "
                             + "are counted as unresponsive surface, not as unscanned: " + named(written_off))
            capped = None
        if capped and no_critical and no_high:
            reason = capped + "; zero critical or high findings on a partial scan is not proof of no findings in scope"
            if pending:
                reason += ("; " + str(len(pending)) + " host(s) did not answer this scan and will be retried: "
                           + named(pending))
            return create_response(
                result={"noCriticalFindings": None, "noHighFindings": None, "domain": domain},
                validation=validation,
                api_errors=[reason],
                fail_reasons=[reason],
                input_summary={"domain": domain, "scanStatus": scan_status, "totalFindings": total_findings,
                               "domainsScanned": to_int(data.get("domainsScanned")),
                               "totalDiscovered": to_int(data.get("totalDiscovered")),
                               "unresponsiveHostsPending": pending[:20], "unresponsiveHosts": written_off[:20],
                               "criticalCount": critical_count, "highCount": high_count}
            )

        # Build pass/fail reasons
        if no_critical:
            pass_reasons.append(f"No critical severity findings for {domain}")
        else:
            fail_reasons.append(f"{critical_count} critical severity finding(s) detected for {domain}")
            recommendations.append("Remediate all critical vulnerabilities immediately")

        if no_high:
            pass_reasons.append(f"No high severity findings for {domain}")
        else:
            fail_reasons.append(f"{high_count} high severity finding(s) detected for {domain}")
            recommendations.append("Prioritize remediation of high severity vulnerabilities")

        if capped:
            fail_reasons.append(capped)
        if coverage_note:
            pass_reasons.append(coverage_note)

        if medium_count > 0 or low_count > 0:
            pass_reasons.append(f"Additional findings: {medium_count} medium, {low_count} low, {info_count} info")

        result = {
                "noCriticalFindings": no_critical,
                "noHighFindings": no_high,
                "criticalCount": critical_count,
                "highCount": high_count,
                "mediumCount": medium_count,
                "lowCount": low_count,
                "infoCount": info_count,
                "totalFindings": total_findings,
                "domain": domain
            }
        if coverage_note:
            result["domainsScanned"] = to_int(data.get("domainsScanned"))
            result["totalDiscovered"] = to_int(data.get("totalDiscovered"))
            result["unresponsiveHosts"] = written_off[:20]
        # Per criterion: each key lists only the findings that make that key fail, and only when it fails.
        by_key = {}
        if critical_findings:
            by_key["noCriticalFindings"] = evidence_items(critical_findings)
        if high_findings:
            by_key["noHighFindings"] = evidence_items(high_findings)
        if by_key:
            result["evidenceItemsByKey"] = by_key

        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "domain": domain,
                "scanStatus": scan_status,
                "totalFindings": total_findings,
                "findingsArrayLength": len(findings),
                "criticalCount": critical_count,
                "highCount": high_count,
                "mediumCount": medium_count,
                "lowCount": low_count,
                "infoCount": info_count
            }
        )

    except Exception as e:
        reason = f"Transformation error, so the findings are unknown: {str(e)}"
        return create_response(
            result={"noCriticalFindings": None, "noHighFindings": None},
            validation={"status": "error", "errors": [], "warnings": []},
            api_errors=[reason],
            transformation_errors=[str(e)],
            fail_reasons=[reason]
        )
