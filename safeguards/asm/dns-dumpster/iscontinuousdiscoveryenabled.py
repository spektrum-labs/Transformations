"""
Transformation: isContinuousDiscoveryEnabled
Vendor: Dns Dumpster
Category: Attack Surface Management

Evaluates isContinuousDiscoveryEnabled for DNS Dumpster (ASM)
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
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isContinuousDiscoveryEnabled", "vendor": "Dns Dumpster", "category": "Attack Surface Management"}
        }
    }


def transform(input):
    criteriaKey = "isContinuousDiscoveryEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # ── EVALUATION LOGIC ──
        dns_records = data.get("dns", data.get("a", []))
        mx_records = data.get("mx", [])
        ns_records = data.get("ns", [])
        txt_records = data.get("txt", [])

        if not isinstance(dns_records, list):
            dns_records = []

        subdomain_count = len(dns_records)
        record_types = []
        if dns_records:
            record_types.append("A")
        if mx_records:
            record_types.append("MX")
        if ns_records:
            record_types.append("NS")
        if txt_records:
            record_types.append("TXT")

        result = subdomain_count >= 1
        # ── END EVALUATION LOGIC ──

        return create_response(

            result={
            "isContinuousDiscoveryEnabled": result,
            "subdomainCount": subdomain_count,
            "recordTypes": record_types
        },

            validation=validation

        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
