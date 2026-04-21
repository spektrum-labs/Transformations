"""
Transformation: confirmedLicensePurchased
Vendor: Sophos  |  Category: aprio-soc2-controls
Evaluates: Confirms the Sophos Central license is active and purchased by verifying
a valid tenant ID and idType are returned from the /whoami/v1 endpoint.
"""
import json
from datetime import datetime

CRITERIA_KEY = "confirmedLicensePurchased"
VENDOR = "Sophos"
CATEGORY = "aprio-soc2-controls"
VALID_ID_TYPES = ["tenant", "partner", "organization"]


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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": CRITERIA_KEY, "vendor": VENDOR, "category": CATEGORY}
        }
    }


def evaluate(data):
    try:
        tenant_id = data.get("id", "")
        id_type = data.get("idType", "")
        data_region = data.get("dataRegion", "")

        has_valid_id = isinstance(tenant_id, str) and len(tenant_id) > 0
        has_valid_id_type = isinstance(id_type, str) and id_type.lower() in VALID_ID_TYPES

        license_confirmed = has_valid_id and has_valid_id_type

        return {
            CRITERIA_KEY: license_confirmed,
            "tenantId": tenant_id,
            "idType": id_type,
            "dataRegion": data_region,
            "hasValidId": has_valid_id,
            "hasValidIdType": has_valid_id_type
        }
    except Exception as e:
        return {CRITERIA_KEY: False, "error": str(e)}


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={CRITERIA_KEY: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(CRITERIA_KEY, False)

        extra_fields = {k: v for k, v in eval_result.items() if k != CRITERIA_KEY and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        tenant_id = eval_result.get("tenantId", "")
        id_type = eval_result.get("idType", "")
        data_region = eval_result.get("dataRegion", "")

        if result_value:
            pass_reasons.append("Sophos Central license is confirmed active and purchased.")
            pass_reasons.append("Tenant ID is present and non-empty: " + tenant_id)
            pass_reasons.append("Identity type '" + id_type + "' is a recognized Sophos account type.")
            if data_region:
                additional_findings.append("Data region URL resolved to: " + data_region)
        else:
            if not eval_result.get("hasValidId", False):
                fail_reasons.append("Tenant ID returned from /whoami/v1 is empty or missing — license cannot be confirmed.")
                recommendations.append("Verify that the API credentials have the correct permissions and the Sophos Central subscription is active.")
            if not eval_result.get("hasValidIdType", False):
                fail_reasons.append("Identity type '" + id_type + "' is not a recognized licensed account type (expected: tenant, partner, or organization).")
                recommendations.append("Ensure the API credentials belong to a properly licensed Sophos Central tenant, partner, or organization account.")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

        return create_response(
            result={CRITERIA_KEY: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"tenantId": tenant_id, "idType": id_type, CRITERIA_KEY: result_value}
        )

    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
