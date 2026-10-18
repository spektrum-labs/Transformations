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
    """Open secret scanning alerts across the organization.

    GET /orgs/{org}/secret-scanning/alerts?state=open (hide_secret=true, so the literal
    secret is never fetched or stored). The definition pages it to completion: page-number
    paging at 100 per page, stopping on a short or empty page, up to IS's default 50 pages.

    Two guards stop a partial read from being reported as a confident number:
      * The body must be a list of alerts. An error envelope or any other shape is a
        failed read, not zero alerts.
      * Only a list that reaches the paginator's cap (50 pages x 100 = 5000 alerts) may
        have been cut off; IS sets no truncation flag on a bare-array body, so the cap is
        the only signal. Below the cap the list is complete, even at an exact multiple of
        100 (the next page came back empty). At the cap, open alerts are reported as
        "at least N" and the check FAILS: the only requirement shape is isEquals 0, and a
        lower bound of 1 or more fails it (as it fails any lessThan up to the cap), so it
        cannot pass falsely. A capped list with nothing open cannot prove zero: withheld.

    Scope: GitHub only raises these alerts on repositories with secret scanning on.
    Zero here says nothing about repositories where it is off; that is what
    isSecretScanningPushProtectionEnabled measures, per repository.
    """
    PAGE_SIZE = 100
    MAX_ALERTS = 50 * PAGE_SIZE  # IS paginate_api_call maxPages default (50) x pageSize
    data, validation = extract_input(input)
    meta = {"transformationId": "openSecretScanningAlertsCount", "vendor": "GitHub", "category": "devsecops"}

    alerts = None
    if isinstance(data, list):
        alerts = data
    elif isinstance(data, dict):
        for key in ("data", "alerts", "apiResponse"):
            if isinstance(data.get(key), list):
                alerts = data.get(key)
                break

    if alerts is None:
        return create_response(
            result={"openSecretScanningAlertsCount": None},
            validation=validation,
            fail_reasons=["The secret scanning alerts response was not a list of alerts, so open alerts cannot be counted."],
            input_summary={"responseIsList": False},
            api_errors=["Unexpected response shape from /orgs/{org}/secret-scanning/alerts."],
            metadata=meta,
        )

    open_alerts = [a for a in alerts if isinstance(a, dict) and a.get("state") == "open"]
    open_count = len(open_alerts)
    truncated = len(alerts) >= MAX_ALERTS

    if truncated and open_count == 0:
        return create_response(
            result={"openSecretScanningAlertsCount": None, "truncated": True},
            validation=validation,
            fail_reasons=[
                f"Received {len(alerts)} alerts, the paginator's {MAX_ALERTS}-alert cap, with none open, so the list may have been cut off and zero open alerts cannot be confirmed."
            ],
            recommendations=["No customer action required; this is a retrieval limit on our side."],
            input_summary={"alertsReceived": len(alerts), "maxAlerts": MAX_ALERTS, "truncated": True},
            api_errors=["Result set may be truncated at the paginator cap."],
            metadata=meta,
        )

    secret_types = {}
    repos_affected = {}
    for a in open_alerts:
        st = a.get("secret_type_display_name") or a.get("secret_type") or "unknown"
        secret_types[st] = secret_types.get(st, 0) + 1
        repo = a.get("repository")
        repo_name = None
        if isinstance(repo, dict):
            repo_name = repo.get("full_name") or repo.get("name")
        if repo_name:
            repos_affected[repo_name] = repos_affected.get(repo_name, 0) + 1

    if open_count > 0:
        top_types = sorted(secret_types.items(), key=lambda kv: kv[1], reverse=True)[:5]
        type_summary = ", ".join([f"{name}: {cnt}" for name, cnt in top_types])
        pass_reasons = []
        at_least = "At least " if truncated else ""
        fail_reasons = [
            f"{at_least}{open_count} open secret scanning alerts across {len(repos_affected)} repositories. Top secret types: {type_summary}."
        ]
        if truncated:
            fail_reasons.append(
                f"Received {len(alerts)} alerts, the paginator's {MAX_ALERTS}-alert cap, so the list may have been cut off; the count is a lower bound and the check fails either way."
            )
        recommendations = [
            "Rotate and revoke every leaked secret in the open alerts, then close the alerts.",
            "Enable secret scanning and push protection on every repository.",
        ]
    else:
        pass_reasons = ["No open secret scanning alerts on repositories where secret scanning is enabled."]
        fail_reasons = []
        recommendations = []

    return create_response(
        result={
            "openSecretScanningAlertsCount": open_count,
            "repositoriesAffectedCount": len(repos_affected),
            "secretTypeBreakdown": secret_types,
            "countIsLowerBound": truncated,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalAlertsInResponse": len(alerts), "openAlertsCounted": open_count,
                       "maxAlerts": MAX_ALERTS, "truncated": truncated},
        additional_findings=["Counts only repositories with secret scanning enabled; see isSecretScanningPushProtectionEnabled for coverage."],
        metadata=meta,
    )
