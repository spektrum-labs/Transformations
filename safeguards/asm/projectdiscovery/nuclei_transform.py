"""
Transformation: asm_nuclei_transform
Vendor: Project Discovery (Nuclei)
Category: Attack Surface Management

Evaluates nuclei vulnerability scan results to determine whether
critical or high severity findings are present for a scanned domain.

A capped scan (more hosts discovered than scanned, the ASM host cap) that found no critical or high
finding returns None for both keys with the coverage reason in dataCollection.errors: zero findings on a
partial estate is not a clean estate, so Token-Service reads it as Unevaluated, never a pass. A capped scan
that did find a critical or high finding still fails, with the coverage named in failReasons. Each row reads
one key from a single-severity scan (noCriticalFindings from the critical scan, noHighFindings from the high
scan), so a response is only ever read for the key whose severity it scanned.
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


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"noCriticalFindings": False, "noHighFindings": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
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

        # Check for scan errors
        if scan_status != "success":
            return create_response(
                result={"noCriticalFindings": False, "noHighFindings": False},
                validation=validation,
                api_errors=[f"Nuclei scan status: {scan_status}"],
                fail_reasons=[f"Scan did not complete successfully for {domain}"],
                input_summary={"domain": domain, "status": scan_status, "stderr": stderr}
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
        if domains_scanned is not None and domains_scanned <= 0:
            reason = f"Nuclei scanned zero domains for {domain}"
        elif failed_domains or scan_errors:
            reason = (f"Nuclei scan failed for {max(len(failed_domains), len(scan_errors))} "
                      f"domain(s) of {domain}")
        else:
            reason = None
        if reason:
            return create_response(
                result={"noCriticalFindings": False, "noHighFindings": False},
                validation=validation,
                api_errors=[reason],
                fail_reasons=[reason],
                input_summary={"domain": domain, "status": scan_status, "domainsScanned": domains_scanned,
                               "failedDomains": failed_domains[:20], "errorCount": len(scan_errors)}
            )

        # Count findings by severity
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        info_count = 0

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
                finding_name = info.get("name", "Unknown") if isinstance(info, dict) else "Unknown"
                additional_findings.append(f"CRITICAL: {finding_name}")
            elif severity == "high":
                high_count += 1
                finding_name = info.get("name", "Unknown") if isinstance(info, dict) else "Unknown"
                additional_findings.append(f"HIGH: {finding_name}")
            elif severity == "medium":
                medium_count += 1
            elif severity == "low":
                low_count += 1
            elif severity == "info":
                info_count += 1

        no_critical = critical_count == 0
        no_high = high_count == 0

        capped = capped_note(data)
        if capped and no_critical and no_high:
            reason = capped + "; zero critical or high findings on a partial scan is not a clean estate"
            return create_response(
                result={"noCriticalFindings": None, "noHighFindings": None, "domain": domain},
                validation=validation,
                api_errors=[reason],
                fail_reasons=[reason],
                input_summary={"domain": domain, "scanStatus": scan_status, "totalFindings": total_findings,
                               "domainsScanned": to_int(data.get("domainsScanned")),
                               "totalDiscovered": to_int(data.get("totalDiscovered")),
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

        if medium_count > 0 or low_count > 0:
            pass_reasons.append(f"Additional findings: {medium_count} medium, {low_count} low, {info_count} info")

        return create_response(
            result={
                "noCriticalFindings": no_critical,
                "noHighFindings": no_high,
                "criticalCount": critical_count,
                "highCount": high_count,
                "mediumCount": medium_count,
                "lowCount": low_count,
                "infoCount": info_count,
                "totalFindings": total_findings,
                "domain": domain
            },
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
        return create_response(
            result={"noCriticalFindings": False, "noHighFindings": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
