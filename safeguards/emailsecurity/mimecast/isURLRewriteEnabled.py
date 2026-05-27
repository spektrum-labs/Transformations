"""Transformation: isURLRewriteEnabled — Mimecast TTP URL Protect
Evaluates whether URL rewriting is enabled by inspecting the managed URL
rules returned by getTTPUrlManagedUrls. A non-zero meta.pagination.totalCount
confirms TTP URL Protect is active and rewriting URLs in delivered emails.
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


def transform(input):
    data, validation = extract_input(input)

    if not isinstance(data, dict):
        data = {}

    # Extract top-level sections
    fail_list = data.get("fail") or []
    meta = data.get("meta") or {}
    pagination = meta.get("pagination") or {}
    url_items = data.get("data") or []

    total_count = pagination.get("totalCount") or 0
    page_size = len(url_items)

    # Collect API-level error messages from the fail array
    api_errors = []
    for f in fail_list:
        if isinstance(f, dict):
            api_errors.append(f.get("message") or str(f))
        else:
            api_errors.append(str(f))

    # Count rewrite states across the sampled page
    rewrite_enabled_count = 0
    rewrite_disabled_count = 0
    for item in url_items:
        if isinstance(item, dict):
            if item.get("disableRewrite") is False:
                rewrite_enabled_count = rewrite_enabled_count + 1
            elif item.get("disableRewrite") is True:
                rewrite_disabled_count = rewrite_disabled_count + 1

    # Primary verdict: a non-zero totalCount confirms TTP URL Protect is active
    # and managing URLs through rewriting. An empty list means the feature has
    # no rules and is effectively not operational.
    is_url_rewrite_enabled = total_count > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_url_rewrite_enabled:
        pass_reasons.append(
            f"TTP URL Protect is active with {total_count} managed URLs configured "
            f"(meta.pagination.totalCount={total_count}). In the sampled page of "
            f"{page_size} entries, {rewrite_enabled_count} have URL rewriting enabled "
            f"(disableRewrite=false) and {rewrite_disabled_count} have rewriting "
            f"explicitly suppressed (disableRewrite=true) for trusted/permitted domains."
        )
    else:
        fail_reasons.append(
            "No managed URLs found in TTP URL Protect (meta.pagination.totalCount=0). "
            "URL rewriting does not appear to be configured or active for this account."
        )
        recommendations.append(
            "Configure TTP URL Protect managed URL rules in the Mimecast administration "
            "console under Administration > Gateway > Policies > URL Protection. "
            "Enabling URL rewriting ensures all links in delivered emails are scanned "
            "and rewritten through Mimecast's proxy before users can click them."
        )

    return create_response(
        result={
            "isURLRewriteEnabled": is_url_rewrite_enabled,
            "totalManagedUrls": total_count,
            "sampledUrlsWithRewriteEnabled": rewrite_enabled_count,
            "sampledUrlsWithRewriteDisabled": rewrite_disabled_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalManagedUrls": total_count,
            "pageSize": page_size,
            "sampledRewriteEnabled": rewrite_enabled_count,
            "sampledRewriteDisabled": rewrite_disabled_count,
            "apiFailures": len(fail_list),
        },
        api_errors=api_errors,
        metadata={
            "transformationId": "isURLRewriteEnabled",
            "vendor": "Mimecast",
            "category": "emailsecurity",
        },
    )
