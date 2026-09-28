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
    """Dependabot alerts enabled on every active repository, read per repository.

    Method listOrgRepositoryVulnerabilityAlerts (POST {serverUrl}/graphql, read-only
    query) returns organization.repositories.nodes[].hasVulnerabilityAlertsEnabled.
    That is the repository's effective setting, however it got there (a code security
    configuration, an org default, or a manual toggle). The REST repository object has
    no Dependabot-alerts field, and GET /orgs/{org}/code-security/configurations lists
    configuration definitions, which say nothing about which repositories they are
    applied to. The previous version read those definitions and passed.

    Fails closed on: a GraphQL errors array, a missing organization, no repositories,
    fewer nodes than totalCount (pagination did not complete), a paginator truncation
    flag, or any active repository with alerts off or unreported.
    """
    data, validation = extract_input(input)
    body = data if isinstance(data, dict) else {}

    gql_errors = body.get("errors")
    org = None
    # This is a legacy-format transform, so Token-Service drills the envelope
    # (response -> result -> apiResponse -> Output -> data) before calling it and the
    # GraphQL "data" wrapper is already gone: the body is {"organization": ...}.
    # Accept that drilled shape, and the undrilled {"data": {"organization": ...}} too.
    gdata = body.get("data")
    if isinstance(gdata, dict) and "organization" in gdata:
        org = gdata.get("organization")
    elif "organization" in body:
        org = body.get("organization")
    conn = org.get("repositories") if isinstance(org, dict) else None
    nodes = conn.get("nodes") if isinstance(conn, dict) else None
    page_info = conn.get("pageInfo") if isinstance(conn, dict) else None
    total_count = conn.get("totalCount") if isinstance(conn, dict) else None

    api_errors = []
    if isinstance(gql_errors, list) and gql_errors:
        for e in gql_errors[:5]:
            api_errors.append(str(e.get("message") if isinstance(e, dict) else e))
    if not isinstance(nodes, list):
        nodes = []
        if not api_errors:
            api_errors.append("The response has no data.organization.repositories.nodes list.")
    if isinstance(page_info, dict) and page_info.get("truncated") is True:
        api_errors.append("The paginator stopped at its page limit, so not every repository was read.")
    if isinstance(total_count, int) and len(nodes) < total_count:
        api_errors.append(f"Read {len(nodes)} of {total_count} repositories; pagination did not complete.")

    active = []
    for n in nodes:
        if not isinstance(n, dict):
            continue
        if n.get("isArchived") is True or n.get("isDisabled") is True:
            continue
        active.append(n)

    enabled = []
    disabled = []
    unknown = []
    for n in active:
        name = n.get("nameWithOwner") or n.get("name") or "unknown"
        flag = n.get("hasVulnerabilityAlertsEnabled")
        if flag is True:
            enabled.append(name)
        elif flag is False:
            disabled.append(name)
        else:
            unknown.append(name)

    is_enabled = (not api_errors) and len(active) > 0 and not disabled and not unknown

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    if api_errors:
        fail_reasons.append("Dependabot alert enablement could not be read for every repository: " + " ".join(api_errors))
        recommendations.append("Give the token read access to the organization's repositories and Dependabot alerts, then re-run.")
    elif not active:
        fail_reasons.append("No active (non-archived) repositories were returned, so Dependabot alerts cannot be confirmed on any.")
    elif is_enabled:
        pass_reasons.append(f"All {len(active)} active repositories report hasVulnerabilityAlertsEnabled=true.")
    else:
        if disabled:
            fail_reasons.append(f"{len(disabled)} of {len(active)} active repositories have Dependabot alerts off (e.g. {', '.join(disabled[:5])}).")
        if unknown:
            fail_reasons.append(f"{len(unknown)} active repositories did not report hasVulnerabilityAlertsEnabled (e.g. {', '.join(unknown[:5])}).")
        recommendations.append("Enable Dependabot alerts on every repository, for example through a code security configuration attached to all repositories.")

    result = {
        "isDependabotAlertsEnabled": is_enabled,
        "activeRepositoryCount": len(active),
        "enabledRepositoryCount": len(enabled),
        "disabledRepositoryCount": len(disabled),
        "unknownRepositoryCount": len(unknown),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "repositoriesRead": len(nodes),
            "totalCount": total_count,
            "activeRepositories": len(active),
            "disabledRepos": disabled[:20],
        },
        api_errors=api_errors,
        metadata={
            "transformationId": "isDependabotAlertsEnabled",
            "vendor": "GitHub",
            "category": "devsecops",
        },
    )
