"""
Transformation: confirmedLicensePurchased
Vendor: Anthropic  |  Category: Artificial Intelligence
Evaluates: Ensures the supplied credential resolves to a real Anthropic organization, confirming an active Claude Enterprise or Claude Console subscription.
API Source: getOrganization
"""
import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
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
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


METADATA = {
    "transformationId": "confirmedLicensePurchased",
    "vendor": "Anthropic",
    "category": "Artificial Intelligence",
}


def _evaluate(input):
    data, validation = extract_input(input)
    # Token-Service navigates into the response's "data" key (codeexecutor
    # navigation_keys), so this transform usually receives the bare navigated
    # value. Accept that, the returnSpec-mapped dict, and the raw API body so
    # the same file works in the live pipeline and in direct/local testing.
    if isinstance(data, list):
        data = data[0] if data and isinstance(data[0], dict) else {}
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        data = data["data"]
    if not isinstance(data, dict):
        data = {}

    org_id = data.get("id") or ""
    org_type = data.get("type") or ""
    org_name = data.get("name") or ""

    if not org_id:
        return create_response(
            result={"confirmedLicensePurchased": False, "organizationId": None, "organizationName": None},
            validation=validation,
            fail_reasons=[
                "GET /v1/organizations/me returned no organization id, so no Anthropic "
                "organization could be confirmed. This is the exact symptom of a standard "
                "inference key (sk-ant-api03-) being supplied where an Admin API key "
                "(sk-ant-admin01-) or Compliance Access Key (sk-ant-api01-) is required."
            ],
            recommendations=[
                "Replace the credential with an Admin API key created in Claude Console > Settings > "
                "Admin keys, or a Compliance Access Key created in claude.ai > Organization settings > "
                "API with the read:org_audit scope."
            ],
            input_summary={"organizationIdPresent": False, "objectType": org_type},
            metadata=METADATA,
        )

    if org_type and org_type != "organization":
        return create_response(
            result={"confirmedLicensePurchased": False, "organizationId": org_id, "organizationName": org_name},
            validation=validation,
            fail_reasons=[
                "GET /v1/organizations/me returned an object of type '" + str(org_type) +
                "' rather than 'organization', so the response could not be confirmed as an "
                "Anthropic organization record."
            ],
            recommendations=["Verify the API base URL and that no proxy is rewriting the response."],
            input_summary={"organizationIdPresent": True, "objectType": org_type},
            metadata=METADATA,
        )

    return create_response(
        result={
            "confirmedLicensePurchased": True,
            "organizationId": org_id,
            "organizationName": org_name,
        },
        validation=validation,
        pass_reasons=[
            "Anthropic organization '" + str(org_name) + "' (id: " + str(org_id) + ") returned a "
            "valid getOrganization response, confirming an active licensed organization reachable "
            "with an administrative credential."
        ],
        input_summary={"organizationIdPresent": True, "objectType": org_type or "organization"},
        metadata=METADATA,
    )


def transform(input):
    try:
        return _evaluate(input)
    except Exception as exc:  # never raise into the pipeline
        return create_response(
            result={"confirmedLicensePurchased": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(exc)],
            fail_reasons=["Transformation raised an unexpected error: " + str(exc)],
            recommendations=["Report this to the Spektrum integrations team with the raw API response."],
            metadata=METADATA,
        )
