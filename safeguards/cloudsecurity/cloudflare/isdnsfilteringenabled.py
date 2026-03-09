"""
Transformation: isDNSFilteringEnabled
Vendor: Cloudflare
Category: Cloud Security / DNS Filtering

Checks if DNS filtering is enabled in Cloudflare.
Validates DNS records exist and checks for proxy-enabled records indicating filtering.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
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
                "transformationId": "isDNSFilteringEnabled",
                "vendor": "Cloudflare",
                "category": "Cloud Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isDNSFilteringEnabled"

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

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        dns_filtering_enabled = False
        total_records = 0
        proxied_records = 0

        # Cloudflare API returns results in 'result' array
        records = data if isinstance(data, list) else []
        if isinstance(data, dict):
            records = data.get('result', [])
            if not isinstance(records, list):
                records = []
            # Check success flag
            if data.get('success') and not records:
                dns_filtering_enabled = data.get('success', False)

        total_records = len(records)

        if total_records > 0:
            dns_filtering_enabled = True
            proxied_records = len([r for r in records if isinstance(r, dict) and r.get('proxied', False)])

        if dns_filtering_enabled:
            reason = f"DNS filtering is enabled ({total_records} DNS record(s)"
            if proxied_records > 0:
                reason += f", {proxied_records} proxied through Cloudflare)"
            else:
                reason += ")"
            pass_reasons.append(reason)

            if proxied_records == 0 and total_records > 0:
                additional_findings.append("No DNS records are proxied through Cloudflare - consider enabling proxy for filtering")
        else:
            fail_reasons.append("DNS filtering is not enabled - no DNS records found")
            recommendations.append("Configure DNS records in Cloudflare and enable proxy for DNS filtering")

        return create_response(
            result={
                criteriaKey: dns_filtering_enabled,
                "totalRecords": total_records,
                "proxiedRecords": proxied_records
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalRecords": total_records,
                "proxiedRecords": proxied_records
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
