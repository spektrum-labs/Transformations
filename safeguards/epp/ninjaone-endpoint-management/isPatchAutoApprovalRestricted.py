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


def find_approval_signals(obj):
    """Iteratively scan a nested structure for approval-related keys/values.
    Returns (found_blanket_auto_approve, found_restricted_signal)."""
    found_blanket = False
    found_restricted = False
    stack = [obj]
    steps = 0
    while stack and steps < 5000:
        steps = steps + 1
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                kl = str(k).lower()
                if isinstance(v, str):
                    vl = v.lower()
                    if "approv" in kl or "auto" in kl:
                        if "all" in vl and ("auto" in vl or "approv" in vl):
                            found_blanket = True
                        elif vl in ("manual", "reject", "review", "pending", "restricted"):
                            found_restricted = True
                elif isinstance(v, bool):
                    if kl in ("autoapproveall", "approveall", "autoapprove", "approveallpatches"):
                        if v:
                            found_blanket = True
                        else:
                            found_restricted = True
                if isinstance(v, dict) or isinstance(v, list):
                    stack.append(v)
        elif isinstance(cur, list):
            for item in cur:
                stack.append(item)
    return found_blanket, found_restricted


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    # getPolicies can return either a flat list of policy objects, or (in this
    # captured tenant) a columnar/empty shape. Normalize into a list of policies.
    policies = []
    if isinstance(data, list):
        policies = data
    else:
        raw_list = data.get("data") or data.get("policies") or data.get("results")
        if isinstance(raw_list, list):
            policies = raw_list
        else:
            # Columnar-empty shape seen in this tenant: {"id": [], "name": [], "nodeClass": []}
            # Treat as zero policies rather than crash.
            id_col = data.get("id")
            if isinstance(id_col, list) and len(id_col) > 0:
                # Reconstruct rows defensively if columnar data with values ever appears.
                name_col = data.get("name") or []
                nodeclass_col = data.get("nodeClass") or []
                for i in range(len(id_col)):
                    row = {"id": id_col[i]}
                    if i < len(name_col):
                        row["name"] = name_col[i]
                    if i < len(nodeclass_col):
                        row["nodeClass"] = nodeclass_col[i]
                    policies.append(row)

    total_policies = len(policies)
    blanket_policies = []
    restricted_policies = []

    for p in policies:
        if not isinstance(p, dict):
            continue
        blanket, restricted = find_approval_signals(p)
        pname = p.get("name") or p.get("id") or "unknown-policy"
        if blanket:
            blanket_policies.append(pname)
        if restricted:
            restricted_policies.append(pname)

    fail_reasons = []
    pass_reasons = []
    recommendations = []

    if total_policies == 0:
        # No policy data available to confirm restriction state.
        is_restricted = False
        fail_reasons.append(
            "No policy records were returned by getPolicies, so no evidence of "
            "restricted (non-blanket) patch auto-approval configuration could be found."
        )
        recommendations.append(
            "Confirm at least one patch management policy exists and expose its "
            "approval settings (per-severity approve/manual/reject) via the API so "
            "auto-approval restriction can be verified."
        )
    elif len(blanket_policies) > 0:
        is_restricted = False
        fail_reasons.append(
            f"{len(blanket_policies)} of {total_policies} policies show a blanket "
            f"auto-approve-all patch signal (policies: {', '.join([str(x) for x in blanket_policies])})."
        )
        recommendations.append(
            "Change the patching policy approval section so that at least one "
            "patch category (e.g. critical/security patches) requires manual "
            "review instead of being auto-approved for all categories."
        )
    elif len(restricted_policies) > 0:
        is_restricted = True
        pass_reasons.append(
            f"{len(restricted_policies)} of {total_policies} policies show a "
            f"non-blanket (manual/reject/pending) approval signal "
            f"(policies: {', '.join([str(x) for x in restricted_policies])}), indicating "
            "patch auto-approval is not set to blanket-approve-all."
        )
    else:
        # Policies exist but no explicit approval signal found either way.
        is_restricted = False
        fail_reasons.append(
            f"{total_policies} policies were returned but none exposed an "
            "identifiable approval-mode field (approval/auto-approve keys), so "
            "blanket auto-approval could not be ruled out."
        )
        recommendations.append(
            "Review each patching policy's approval section manually to confirm "
            "it does not auto-approve all patch categories without review."
        )

    result = {
        "isPatchAutoApprovalRestricted": is_restricted,
        "totalPolicies": total_policies,
        "blanketAutoApprovePolicyCount": len(blanket_policies),
        "restrictedApprovalPolicyCount": len(restricted_policies),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalPolicies": total_policies,
            "blanketAutoApprovePolicyCount": len(blanket_policies),
            "restrictedApprovalPolicyCount": len(restricted_policies),
        },
        metadata={
            "transformationId": "isPatchAutoApprovalRestricted",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
