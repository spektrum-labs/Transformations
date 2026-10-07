"""
Transformation: confirmedLicensePurchased (from endpoint product assignments)
Vendor: Sophos Central - MDR
Category: Licensing
Method: getEndpoints (GET /endpoint/v1/endpoints)

Confirms an active Sophos MDR licence from evidence in the tenant, not from whether a
response arrived. Sophos only assigns the MDR products ("mtr" = Managed Threat Response,
"xdr") to endpoints on a licensed MDR subscription, and marks such endpoints mdrManaged.
The licence is confirmed when at least one endpoint carries that evidence; an empty or
unreadable endpoint list confirms nothing.
"""

import json
from datetime import datetime


def transform(input):
    criteriaKey = "confirmedLicensePurchased"
    mdr_product_codes = ("mtr", "xdr")

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
                    "transformationId": "confirmedLicensePurchased",
                    "vendor": "Sophos Central",
                    "category": "Licensing"
                }
            }
        }

    def endpoint_items(data):
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("items", "endpoints", "data"):
                value = data.get(key)
                if isinstance(value, list):
                    return value
        return None

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

        items = endpoint_items(data)
        if not items:
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["No endpoint records were returned, so an MDR licence could not be confirmed"],
                recommendations=["Check that the Sophos Central credential can read endpoints"],
                input_summary={"totalEndpoints": 0, "mdrEndpoints": 0}
            )

        mdr_endpoints = 0
        codes_seen = []
        for endpoint in items:
            if not isinstance(endpoint, dict):
                continue
            codes = [p.get("code") for p in (endpoint.get("assignedProducts") or []) if isinstance(p, dict)]
            for code in codes:
                if code and code not in codes_seen:
                    codes_seen.append(code)
            managed = str(endpoint.get("mdrManaged")).strip().lower() == "true"
            if managed or any(code in mdr_product_codes for code in codes):
                mdr_endpoints = mdr_endpoints + 1

        licensed = mdr_endpoints > 0
        summary = {"totalEndpoints": len(items), "mdrEndpoints": mdr_endpoints, "productCodes": sorted(codes_seen)}

        if licensed:
            return create_response(
                result={criteriaKey: True},
                validation=validation,
                pass_reasons=[f"Sophos MDR licence confirmed: {mdr_endpoints} of {len(items)} endpoints carry the MDR product (mtr/xdr) or are MDR-managed"],
                input_summary=summary
            )
        return create_response(
            result={criteriaKey: False},
            validation=validation,
            fail_reasons=[f"None of the {len(items)} endpoints carry the Sophos MDR product (mtr/xdr) or are MDR-managed"],
            recommendations=["Confirm the Sophos MDR subscription is active and assigned to endpoints"],
            input_summary=summary
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
