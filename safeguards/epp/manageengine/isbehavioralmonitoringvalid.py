"""
Transformation: isBehavioralMonitoringValid
Vendor: ManageEngine Endpoint Central  |  Category: EPP
Evaluates: Whether vulnerability scanning and threat detection are actively monitoring endpoints.
Source: GET /dcapi/threats/vulnerabilities
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBehavioralMonitoringValid", "vendor": "ManageEngine", "category": "EPP"}
        }
    }


def evaluate(data):
    """Check if vulnerability management and threat scanning are active."""
    try:
        vulnerabilities = []
        if isinstance(data, list):
            vulnerabilities = data
        elif isinstance(data, dict):
            vulnerabilities = (
                data.get("vulnerabilities", []) or
                data.get("vulnerability_details", []) or
                data.get("vulnerabilityDetails", []) or
                data.get("data", []) or
                data.get("results", []) or
                []
            )

        if not isinstance(vulnerabilities, list):
            vulnerabilities = [vulnerabilities] if vulnerabilities else []

        total_vulnerabilities = len(vulnerabilities)
        critical_count = 0
        high_count = 0

        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            severity = str(vuln.get("severity", vuln.get("risk_level", vuln.get("riskLevel", "")))).lower()
            if severity in ("critical", "5"):
                critical_count = critical_count + 1
            elif severity in ("high", "4"):
                high_count = high_count + 1

        # Also check aggregate summary fields
        if not total_vulnerabilities:
            total_vulnerabilities = int(data.get("total_vulnerabilities", data.get("totalVulnerabilities", data.get("total", 0))))
            critical_count = int(data.get("critical", data.get("critical_count", 0)))
            high_count = int(data.get("high", data.get("high_count", 0)))

        # Check if vulnerability scanning module is active
        scan_status = data.get("scan_status", data.get("scanStatus", data.get("status", "")))
        last_scan = data.get("last_scan_time", data.get("lastScanTime", data.get("last_scanned", "")))

        # Vulnerability monitoring is considered valid if:
        # 1. Vulnerabilities are being tracked (scan results exist)
        # 2. OR scan status indicates active scanning
        is_valid = (total_vulnerabilities > 0) or (str(scan_status).lower() in ("active", "enabled", "completed", "success"))

        # If we got a successful API response with data structure, scanning is active
        if not is_valid and isinstance(data, dict) and len(data) > 0:
            # A successful response from the threats endpoint means the module is enabled
            if data.get("vulnerabilities") is not None or data.get("total_vulnerabilities") is not None:
                is_valid = True

        return {
            "isBehavioralMonitoringValid": is_valid,
            "totalVulnerabilities": total_vulnerabilities,
            "criticalVulnerabilities": critical_count,
            "highVulnerabilities": high_count,
            "lastScan": str(last_scan)
        }
    except Exception as e:
        return {"isBehavioralMonitoringValid": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBehavioralMonitoringValid"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append("Vulnerability scanning and threat monitoring is active")
            if extra_fields.get("totalVulnerabilities"):
                pass_reasons.append(f"Tracking {extra_fields['totalVulnerabilities']} vulnerabilities")
            if extra_fields.get("criticalVulnerabilities"):
                pass_reasons.append(f"{extra_fields['criticalVulnerabilities']} critical vulnerabilities detected")
            if extra_fields.get("highVulnerabilities"):
                pass_reasons.append(f"{extra_fields['highVulnerabilities']} high vulnerabilities detected")
        else:
            fail_reasons.append("No vulnerability scanning or threat monitoring activity detected")
            recommendations.append("Enable Vulnerability Management module in Endpoint Central")
            recommendations.append("Configure scheduled vulnerability scans under Threats & Patches > Vulnerability Manager")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
