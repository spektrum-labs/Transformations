"""
Transformation: isGroupProvisioningManaged
Vendor: Anthropic  |  Category: Artificial Intelligence
Evaluates: Ensures access groups are provisioned from the identity provider through SCIM rather than maintained by hand inside Claude.
API Source: listComplianceGroups
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
    "transformationId": "isGroupProvisioningManaged",
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
            items = data.get("groups")
    else:
        items = None
    if not isinstance(items, list):
        items = []

    groups = [g for g in items if isinstance(g, dict)]

    if not groups:
        return create_response(
            result={"isGroupProvisioningManaged": False, "groupCount": 0,
                    "scimGroupCount": 0, "directGroups": []},
            validation=validation,
            fail_reasons=[
                "GET /v1/compliance/groups returned no groups, so identity-provider group "
                "provisioning could not be assessed. An organization with no groups has no "
                "group-based access model to evidence."
            ],
            recommendations=[
                "Confirm the key carries read:compliance_org_data or read:org_audit, and that the "
                "organization uses groups for access control."
            ],
            input_summary={"groupCount": 0},
            metadata=METADATA,
        )

    scim = [str(g.get("name") or g.get("id") or "unnamed") for g in groups
            if str(g.get("source_type", "")).lower() == "scim"]
    direct = [str(g.get("name") or g.get("id") or "unnamed") for g in groups
              if str(g.get("source_type", "")).lower() != "scim"]
    result = not direct

    if result:
        pass_reasons = [
            "All " + str(len(groups)) + " group(s) are provisioned through SCIM directory sync: " +
            ", ".join(sorted(scim)) + ". Membership is owned by the identity provider and cannot "
            "be edited inside Claude."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            str(len(direct)) + " of " + str(len(groups)) + " group(s) are maintained directly "
            "inside Claude rather than provisioned from the identity provider: " +
            ", ".join(sorted(direct)) + ". Their membership is not governed by the joiner-mover-leaver process."
        ]
        recommendations = [
            "Migrate the listed groups to SCIM provisioning in the identity provider, or document "
            "why they are managed by hand."
        ]

    return create_response(
        result={
            "isGroupProvisioningManaged": result,
            "groupCount": len(groups),
            "scimGroupCount": len(scim),
            "directGroups": sorted(direct),
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"groupCount": len(groups), "scimGroupCount": len(scim)},
        metadata=METADATA,
    )


def transform(input):
    try:
        return _evaluate(input)
    except Exception as exc:  # never raise into the pipeline
        return create_response(
            result={"isGroupProvisioningManaged": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(exc)],
            fail_reasons=["Transformation raised an unexpected error: " + str(exc)],
            recommendations=["Report this to the Spektrum integrations team with the raw API response."],
            metadata=METADATA,
        )
