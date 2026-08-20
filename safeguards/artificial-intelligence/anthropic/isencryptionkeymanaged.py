"""
Transformation: isEncryptionKeyManaged
Vendor: Anthropic  |  Category: Artificial Intelligence
Evaluates: Ensures every active workspace is bound to a customer-managed encryption key rather than relying solely on provider-managed encryption.
API Source: listWorkspaces
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
    "transformationId": "isEncryptionKeyManaged",
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
        items = data
    elif isinstance(data, dict):
        items = data.get("data")
        if not isinstance(items, list):
            items = data.get("workspaces")
    else:
        items = None
    if not isinstance(items, list):
        items = []

    active = [w for w in items if isinstance(w, dict) and not w.get("archived_at")]

    if not active:
        return create_response(
            result={"isEncryptionKeyManaged": False, "activeWorkspaceCount": 0,
                    "workspacesWithoutCMEK": 0, "unprotectedWorkspaces": []},
            validation=validation,
            fail_reasons=[
                "GET /v1/organizations/workspaces returned no active workspaces, so encryption key "
                "management could not be assessed."
            ],
            recommendations=["Confirm the credential is an Admin API key for a Claude Console organization."],
            input_summary={"workspacesReturned": len(items), "activeWorkspaceCount": 0},
            metadata=METADATA,
        )

    without_key = []
    with_key = []
    for workspace in active:
        name = str(workspace.get("name") or workspace.get("id") or "unnamed")
        if workspace.get("external_key_id"):
            with_key.append(name)
        else:
            without_key.append(name)

    result = not without_key

    if result:
        pass_reasons = [
            "All " + str(len(active)) + " active workspace(s) are bound to a customer-managed "
            "encryption key: " + ", ".join(sorted(with_key)) + "."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            str(len(without_key)) + " of " + str(len(active)) + " active workspace(s) have no "
            "customer-managed encryption key attached: " + ", ".join(sorted(without_key)) + "."
        ]
        recommendations = [
            "Attach a CMEK configuration to each listed workspace. Note that external_key_id is "
            "write-once: a key cannot be detached or replaced once attached, so rotate the "
            "underlying key in the cloud KMS instead."
        ]

    return create_response(
        result={
            "isEncryptionKeyManaged": result,
            "activeWorkspaceCount": len(active),
            "workspacesWithoutCMEK": len(without_key),
            "unprotectedWorkspaces": sorted(without_key),
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=[
            "This criterion is only meaningful for organizations that have CMEK enabled. For "
            "organizations that do not, it should be resolved as not applicable rather than failed."
        ],
        input_summary={"workspacesReturned": len(items), "activeWorkspaceCount": len(active)},
        metadata=METADATA,
    )


def transform(input):
    try:
        return _evaluate(input)
    except Exception as exc:  # never raise into the pipeline
        return create_response(
            result={"isEncryptionKeyManaged": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(exc)],
            fail_reasons=["Transformation raised an unexpected error: " + str(exc)],
            recommendations=["Report this to the Spektrum integrations team with the raw API response."],
            metadata=METADATA,
        )
