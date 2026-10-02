"""
Transformation: isASMEnabled
Vendor: Project Discovery (Nuclei, run by Spektrum)  |  Category: Attack Surface Management
Evaluates: Whether external attack surface discovery and scanning ran for the passport domain.

Input: the runParallelASMScan response the noCriticalFindings workflow already fetches (subfinder discovery of the
passport domain, then nuclei critical-severity templates across up to 25 discovered hosts). No extra scan.
Fails closed: a scan that did not complete, scanned zero hosts, or reports a failed host or an error returns
False with the reason in dataCollection.errors.
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for step in range(3):
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
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
                "transformationId": "isASMEnabled",
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


def scan_problem(data):
    """None when the scan completed across at least one host with no failed host and no error; else the reason."""
    if not isinstance(data, dict):
        return "No scan data"
    domain = data.get("primaryDomain") or data.get("domain") or "unknown"
    status = data.get("status", "unknown")
    if status != "success":
        return "Nuclei scan status: " + str(status) + " for " + str(domain)
    scanned = to_int(data.get("domainsScanned"))
    if scanned is None or scanned <= 0:
        return "Nuclei scanned zero hosts for " + str(domain)
    failed = [r.get("domain", "unknown") for r in (data.get("domainResults") or [])
              if isinstance(r, dict) and r.get("status") not in ("success", "unresponsive")]
    errors = data.get("errors") or []
    if failed or errors:
        return "Nuclei scan failed for " + str(max(len(failed), len(errors))) + " host(s) of " + str(domain)
    return None


def finding_severity(finding):
    info = finding.get("info") if isinstance(finding, dict) else None
    sev = info.get("severity") if isinstance(info, dict) else None
    if not sev and isinstance(finding, dict):
        sev = finding.get("severity")
    return str(sev or "").lower()


def finding_tags(finding):
    info = finding.get("info") if isinstance(finding, dict) else None
    tags = info.get("tags") if isinstance(info, dict) else None
    if isinstance(tags, str):
        tags = tags.split(",")
    if not isinstance(tags, list):
        return []
    return [str(t).strip().lower() for t in tags]


def finding_name(finding):
    info = finding.get("info") if isinstance(finding, dict) else None
    name = info.get("name") if isinstance(info, dict) else None
    return str(name or finding.get("template-id") or "Unknown") if isinstance(finding, dict) else "Unknown"


def transform(input):
    criteriaKey = "isASMEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation,
                                   fail_reasons=["Input validation failed"])
        problem = scan_problem(data)
        domain = (data.get("primaryDomain") or data.get("domain") or "unknown") if isinstance(data, dict) else "unknown"
        summary = {"domain": domain,
                   "domainsScanned": to_int(data.get("domainsScanned")) if isinstance(data, dict) else None,
                   "templatesScanned": to_int(data.get("templatesScanned")) if isinstance(data, dict) else None}
        if problem:
            return create_response(result={criteriaKey: False}, validation=validation, api_errors=[problem],
                                   fail_reasons=[problem], input_summary=summary)
        findings = [f for f in (data.get("findings") or []) if isinstance(f, dict)]
        discovered = to_int(data.get("totalDiscovered"))
        scanned = to_int(data.get("domainsScanned"))
        extra = {"hostsDiscovered": discovered, "hostsScanned": scanned,
                 "templatesScanned": to_int(data.get("templatesScanned")), "scannedAt": data.get("timestamp")}
        return create_response(
            result=dict([(criteriaKey, True)] + list(extra.items())), validation=validation,
            pass_reasons=["Subdomain discovery and nuclei scan completed for " + str(domain) + ": "
                          + str(scanned) + " host(s) scanned of " + str(discovered) + " discovered"],
            input_summary=summary)
    except Exception as e:
        return create_response(result={criteriaKey: False},
                               validation={"status": "error", "errors": [], "warnings": []},
                               transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
