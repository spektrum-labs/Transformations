# isfirewallloggingenabled.py - Sophos Firewall Management API (Central Firewall Reporting)
import json
from datetime import datetime

APPROVED_MARKER = "approved"


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"]
    data = input_data
    if isinstance(data, dict):
        for key in ["response", "result", "apiResponse", "Output"]:
            if key in data and isinstance(data.get(key), dict):
                data = data[key]
    return data


def create_response(result, pass_reasons=None, fail_reasons=None, input_summary=None, transformation_errors=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": []},
            "transformation": {"status": "error" if transformation_errors else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "transformationId": "isFirewallLoggingEnabled", "vendor": "Sophos", "category": "Firewall"}
        }
    }


def transform(input):
    criteriaKey = "isFirewallLoggingEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data = extract_input(input)
        items = data.get("items", []) if isinstance(data, dict) else []
        if not isinstance(items, list):
            items = []

        total = len(items)
        reporting_approved = 0
        for fw in items:
            if not isinstance(fw, dict):
                continue
            status = fw.get("status", {})
            reporting_status = status.get("reportingStatus", "") if isinstance(status, dict) else ""
            if isinstance(reporting_status, str) and APPROVED_MARKER in reporting_status.lower():
                reporting_approved += 1

        is_logging_enabled = total > 0 and reporting_approved == total

        pass_reasons, fail_reasons = [], []
        if is_logging_enabled:
            pass_reasons.append(f"All {total} Sophos firewall device(s) have Central Firewall Reporting approved (reportingStatus contains 'approved')")
        elif reporting_approved > 0:
            fail_reasons.append(f"Only {reporting_approved} of {total} firewall device(s) have reporting approved")
        else:
            fail_reasons.append("No firewall devices have Central Firewall Reporting approved")

        return create_response(
            result={criteriaKey: is_logging_enabled, "totalFirewalls": total, "reportingApproved": reporting_approved},
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            input_summary={"totalFirewalls": total, "reportingApproved": reporting_approved}
        )
    except Exception as e:
        return create_response(result={criteriaKey: False}, transformation_errors=[str(e)])
