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


def status_of(sec, name):
    """security_and_analysis.<name>.status, or None when GitHub did not report it."""
    block = sec.get(name) if isinstance(sec, dict) else None
    if isinstance(block, dict):
        return block.get("status")
    return None


def transform(input):
    """GitHub Advanced Security on every active private or internal repository.

    Reads security_and_analysis on GET /orgs/{org}/repos: the per-repository state,
    not a configuration that may or may not be applied.

    GitHub unbundled GHAS in 2025 into GitHub Code Security and GitHub Secret
    Protection. A repository on the unbundled products reports code_security and
    secret_scanning, and may report no advanced_security block at all. A repository
    counts as covered when either
      * advanced_security.status == "enabled" (the bundled product), or
      * code_security.status == "enabled" AND secret_scanning.status == "enabled"
        (both unbundled products; on a private repository secret scanning needs
        Secret Protection).
    One half alone is reported as partial and does not pass, because the criterion
    asks for code scanning and secret scanning together.

    Fails closed: no private repositories, a repository without security_and_analysis
    (the token cannot see it), or any uncovered repository.
    """
    data, validation = extract_input(input)

    if isinstance(data, list):
        repos = data
    elif isinstance(data, dict):
        repos = data.get("data") or data.get("repositories") or []
        if not isinstance(repos, list):
            repos = []
    else:
        repos = []

    private_repos = []
    for r in repos:
        if not isinstance(r, dict):
            continue
        if r.get("archived") is True or r.get("disabled") is True:
            continue
        if r.get("private") is True or r.get("visibility") in ("private", "internal"):
            private_repos.append(r)

    total_private = len(private_repos)
    covered = []
    code_only = []
    secret_only = []
    uncovered = []
    unknown = []

    for r in private_repos:
        name = r.get("full_name") or r.get("name") or "unknown"
        sec = r.get("security_and_analysis")
        if not isinstance(sec, dict) or not sec:
            unknown.append(name)
            continue
        ghas = status_of(sec, "advanced_security")
        code = status_of(sec, "code_security")
        secret = status_of(sec, "secret_scanning")
        if ghas == "enabled" or (code == "enabled" and secret == "enabled"):
            covered.append(name)
        elif code == "enabled":
            code_only.append(name)
        elif secret == "enabled":
            secret_only.append(name)
        else:
            uncovered.append(name)

    not_covered = len(code_only) + len(secret_only) + len(uncovered) + len(unknown)
    is_enabled = total_private > 0 and not_covered == 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    if total_private == 0:
        fail_reasons.append("No active private or internal repositories were returned, so GitHub Advanced Security cannot be confirmed on any.")
        recommendations.append("Check that the token can list the organization's private repositories.")
    elif is_enabled:
        pass_reasons.append(
            f"All {total_private} active private/internal repositories have GitHub Advanced Security, or both GitHub Code Security and Secret Protection, enabled (security_and_analysis per repository)."
        )
    else:
        fail_reasons.append(
            f"{len(covered)} of {total_private} active private/internal repositories have GitHub Advanced Security (or Code Security plus Secret Protection) enabled."
        )
        if uncovered:
            fail_reasons.append(f"{len(uncovered)} have neither code security nor secret scanning enabled (e.g. {', '.join(uncovered[:5])}).")
        if code_only:
            fail_reasons.append(f"{len(code_only)} have Code Security but not secret scanning (e.g. {', '.join(code_only[:5])}).")
        if secret_only:
            fail_reasons.append(f"{len(secret_only)} have secret scanning but not Code Security (e.g. {', '.join(secret_only[:5])}).")
        if unknown:
            fail_reasons.append(f"{len(unknown)} returned no security_and_analysis block; the token needs admin or security-manager visibility (e.g. {', '.join(unknown[:5])}).")
        recommendations.append(
            "Attach a code security configuration that enables Code Security and Secret Protection (or GHAS) to every private and internal repository, and confirm each repository reports them enabled."
        )

    result = {
        "isAdvancedSecurityEnabled": is_enabled,
        "totalPrivateRepositories": total_private,
        "advancedSecurityEnabledCount": len(covered),
        "codeSecurityOnlyCount": len(code_only),
        "secretProtectionOnlyCount": len(secret_only),
        "unknownStatusCount": len(unknown),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalReposSeen": len(repos),
            "totalPrivateRepositories": total_private,
            "coveredRepos": covered[:20],
            "uncoveredRepos": uncovered[:20],
            "unknownStatusRepos": unknown[:20],
        },
        metadata={
            "transformationId": "isAdvancedSecurityEnabled",
            "vendor": "GitHub",
            "category": "devsecops",
        },
    )
