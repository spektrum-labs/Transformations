"""
Transformation: isEncryptionEnforced
Vendor: ThreatDown (Malwarebytes Nebula)  |  Category: Endpoint Security
Method: getDriveEncryptionSummary (GET /nebula/v1/drive-encryption/summary)

Evidence: the documented Drive Encryption summary (Nebula OpenAPI): total_machines,
total_drives, encrypted, failed, suspended, and endpoint_status {full, partial, none, unknown}.

ThreatDown Drive Encryption is centralised BitLocker management ("Overview of Drive Encryption
in Nebula", 2026-08-05). Per "Requirements for Drive Encryption in Nebula" (2026-07-21) it covers
Windows 10 (1607+) / 11 Pro, Enterprise and Education WORKSTATIONS only, fixed drives only, and
needs an Advanced, Elite or Ultimate subscription. "Drive Encryption page in Nebula" defines the
endpoint status: Fully Encrypted (every drive encrypted), Partially Encrypted, Not Encrypted,
Unknown (no volume data; treated as non-compliant).

Rule: true when total_machines > 0, endpoint_status.full equals total_machines, partial, none and
unknown are all 0, and no drive is failed or suspended (a suspended BitLocker drive is not
protected). Counts that are missing or not numbers fail the check.

Platform coverage: Windows workstations only. macOS, Linux and Windows servers are outside
ThreatDown Drive Encryption; they are neither counted nor failed, and this check says nothing
about them. An account without Drive Encryption reports no machines and fails (not proven).

Proves: every Windows workstation ThreatDown Drive Encryption reports on is fully BitLocker-
encrypted with protection active.
Does not prove: encryption on macOS (FileVault), Linux or servers; encryption managed outside
ThreatDown; or that every Windows workstation is enrolled in Drive Encryption.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
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
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEncryptionEnforced", "vendor": "ThreatDown", "category": "Endpoint Security"}
        }
    }


def api_error_message(data):
    if isinstance(data, dict) and (data.get("error") is True or str(data.get("error")).lower() == "true"):
        return str(data.get("errorMessage") or data.get("message") or "ThreatDown API returned an error")
    return None


def count(value):
    """Non-negative int, or None. api-response-files stores scalars as strings."""
    if isinstance(value, bool):
        return None
    try:
        number = int(str(value).strip())
    except Exception:
        return None
    return number if number >= 0 else None


def transform(input):
    criteriaKey = "isEncryptionEnforced"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation,
                                   fail_reasons=["Input validation failed"])

        error = api_error_message(data)
        status = data.get("endpoint_status") if isinstance(data, dict) else None
        if error or not isinstance(status, dict) or "total_machines" not in data:
            reason = error or "Drive encryption summary not recognised - no total_machines / endpoint_status"
            return create_response(result={criteriaKey: False}, validation=validation,
                                   api_errors=[reason], fail_reasons=[reason],
                                   recommendations=["Verify GET /nebula/v1/drive-encryption/summary is reachable with the accountid header"])

        figures = {
            "totalMachines": count(data.get("total_machines")),
            "fullyEncrypted": count(status.get("full")),
            "partiallyEncrypted": count(status.get("partial")),
            "notEncrypted": count(status.get("none")),
            "unknownStatus": count(status.get("unknown")),
            "failedDrives": count(data.get("failed")),
            "suspendedDrives": count(data.get("suspended")),
        }
        unreadable = [k for k, v in figures.items() if v is None]
        problems = []
        if unreadable:
            problems.append("unreadable counts: " + ", ".join(unreadable))
        else:
            if figures["totalMachines"] == 0:
                problems.append("ThreatDown Drive Encryption reports no machines")
            elif figures["fullyEncrypted"] != figures["totalMachines"]:
                problems.append(f"{figures['fullyEncrypted']} of {figures['totalMachines']} machines fully encrypted")
            for key in ("partiallyEncrypted", "notEncrypted", "unknownStatus", "failedDrives", "suspendedDrives"):
                if figures[key]:
                    problems.append(f"{key}={figures[key]}")
        value = len(problems) == 0

        summary = dict(figures)
        summary["scope"] = "Windows workstations managed by ThreatDown Drive Encryption"
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if value:
            pass_reasons.append(f"All {figures['totalMachines']} Windows workstation(s) in ThreatDown Drive Encryption are fully BitLocker-encrypted, none failed or suspended")
        else:
            fail_reasons.append("Drive encryption not proven: " + "; ".join(problems))
            if figures["totalMachines"] == 0:
                recommendations.append("Enable ThreatDown Drive Encryption in a policy (Advanced/Elite/Ultimate), or provide encryption evidence from the tool that manages BitLocker/FileVault")
            else:
                recommendations.append("Resolve partially encrypted, unencrypted, unknown, failed or suspended drives on the Monitor > Drive Encryption page")

        return create_response(result={criteriaKey: value, **summary}, validation=validation,
                               pass_reasons=pass_reasons, fail_reasons=fail_reasons,
                               recommendations=recommendations, input_summary={criteriaKey: value, **summary})
    except Exception as e:
        return create_response(result={criteriaKey: False},
                               validation={"status": "error", "errors": [], "warnings": []},
                               transformation_errors=[str(e)], fail_reasons=[f"Transformation error: {str(e)}"])
