"""
Transformation: confirmedLicensePurchased
Vendor: Abnormal Security Inbound Email
Method: listThreats  (GET {serverUrl}/v1/threats)

Abnormal publishes no billing or subscription endpoint. What the REST API does prove is that
the tenant has the Abnormal REST API enabled and the token is accepted: GET /v1/threats answers
with a body that carries a "threats" list (even an empty one: a tenant with no threats today is
still a licensed tenant). Nothing else counts as a pass. An error envelope (401/403), an empty body,
an unrelated payload or a transform error is an API error, not evidence that no licence exists:
the key is None (Not evaluated) with a dataCollection error, never False. The API has no
positive "off" signal, so this check never returns False.

Capability note: product active via API; tier not visible. This proves an active, API-enabled
Abnormal tenant for this token. It does not read a license tier or a seat count.
"""

import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, str):
        input_data = json.loads(input_data)
    elif isinstance(input_data, bytes):
        input_data = json.loads(input_data.decode("utf-8"))
    enriched_validation = None
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        enriched_validation = input_data["validation"]
        input_data = input_data["data"]
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
    if enriched_validation is not None:
        return data, enriched_validation
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


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
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": "confirmedLicensePurchased",
                "vendor": "Abnormal Security Inbound Email",
                "category": "emailsecurity",
            },
        },
    }


def transform(input):
    criteriaKey = "confirmedLicensePurchased"
    try:
        data, validation = extract_input(input)
        threats = data.get("threats") if isinstance(data, dict) else None
        licensed = isinstance(threats, list)
        threat_count = len(threats) if licensed else 0

        if not licensed:
            reason = ("GET /v1/threats did not return a threats list (error body, 401/403, empty or "
                      "unrelated payload), so the Abnormal subscription could not be evaluated.")
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                api_errors=[reason],
                fail_reasons=[reason],
                recommendations=[
                    "Confirm the REST API token is valid, has the Threats - Read Access box ticked and "
                    "is not expired or blocked by the IP safelist, then re-run."
                ],
                input_summary={"threatsListPresent": False},
            )

        return create_response(
            result={criteriaKey: True, "threatsOnPage": threat_count},
            validation=validation,
            pass_reasons=[
                "GET /v1/threats answered with a threats list (%d on this page), so the Abnormal REST API "
                "is enabled for this tenant and the token is accepted (product active via API; tier not visible)." % threat_count
            ],
            input_summary={"threatsListPresent": True, "threatsOnPage": threat_count},
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            api_errors=["Transformation error: " + str(e)],
            fail_reasons=["Transformation error: " + str(e)],
        )
