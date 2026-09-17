
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
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
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


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        policies = data
    elif isinstance(data, dict):
        policies = data.get("data") or data.get("policies") or data.get("results") or []
        if not isinstance(policies, list):
            policies = []
    else:
        policies = []

    total_policies = len(policies)
    restricted_policy_names = []
    blanket_auto_approve_names = []
    unknown_policy_names = []

    for p in policies:
        if not isinstance(p, dict):
            continue
        name = p.get("name") or f"policy-{p.get('id')}"
        conditions = p.get("conditions") or []
        if not isinstance(conditions, list):
            conditions = []

        found_patch_condition = False
        is_restricted = False
        is_blanket_auto_approve = False

        for c in conditions:
            if not isinstance(c, dict):
                continue
            ctype = str(c.get("type") or c.get("conditionType") or "").lower()
            mode = str(c.get("approvalMode") or c.get("mode") or c.get("approval") or "").lower()
            if "patch" in ctype or "approval" in ctype:
                found_patch_condition = True
                if "manual" in mode or "review" in mode or "restrict" in mode:
                    is_restricted = True
                elif "auto" in mode and ("all" in mode or "blanket" in mode or mode == "auto"):
                    is_blanket_auto_approve = True

        if found_patch_condition and is_restricted:
            restricted_policy_names.append(name)
        elif found_patch_condition and is_blanket_auto_approve:
            blanket_auto_approve_names.append(name)
        else:
            unknown_policy_names.append(name)

    has_explicit_restriction = len(restricted_policy_names) > 0
    has_explicit_blanket = len(blanket_auto_approve_names) > 0

    if has_explicit_blanket:
        is_restricted_verdict = False
        fail_reasons = [
            f"Policies {blanket_auto_approve_names} carry an explicit patch-approval condition configured to auto-approve all categories without review."
        ]
        pass_reasons = []
        recommendations = [
            "Configure the patching policy's approval section to require manual review for at least one patch category (e.g. security/critical patches) instead of blanket auto-approval."
        ]
    elif has_explicit_restriction:
        is_restricted_verdict = True
        pass_reasons = [
            f"Policies {restricted_policy_names} carry an explicit patch-approval condition requiring manual review, so blanket auto-approval is not in effect."
        ]
        fail_reasons = []
        recommendations = []
    else:
        is_restricted_verdict = False
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_policies} policies returned by getPolicies expose a patch-approval condition restricting auto-approval; conditions arrays are empty or lack patch/approval entries ({unknown_policy_names[:5]} sampled), which cannot confirm any manual-review restriction is configured."
        ]
        recommendations = [
            "Add an explicit patch-approval condition to the relevant policies (e.g. Windows Workstation Policy, Windows Server Policy) that requires manual review for at least one patch category rather than relying on default auto-approval."
        ]

    result = {
        "isPatchAutoApprovalRestricted": is_restricted_verdict,
        "totalPolicies": total_policies,
        "restrictedPolicyCount": len(restricted_policy_names),
        "blanketAutoApprovePolicyCount": len(blanket_auto_approve_names),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalPolicies": total_policies,
            "restrictedPolicyNames": restricted_policy_names,
            "blanketAutoApprovePolicyNames": blanket_auto_approve_names,
        },
        metadata={
            "transformationId": "isPatchAutoApprovalRestricted",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
