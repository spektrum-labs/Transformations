"""Transformation: requiredCoveragePercentage — SentinelOne getAccounts
Computes the percentage of endpoints covered by Endpoint Security agents
relative to licensed seats. Handles unlimited-license accounts (totalLicenses=-1).
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
    data = data if isinstance(data, dict) else {}

    accounts = data.get("data") or []
    accounts = accounts if isinstance(accounts, list) else []

    total_active_agents = 0
    total_licenses = 0
    has_unlimited = False
    account_count = len(accounts)

    for account in accounts:
        active = account.get("activeAgents") or 0
        total_active_agents = total_active_agents + active

        lic = account.get("totalLicenses")
        # -1 signals unlimited license capacity
        if lic is not None and lic == -1:
            has_unlimited = True
        elif lic is not None and lic > 0:
            total_licenses = total_licenses + lic

        # Also check per-account unlimited flags
        if account.get("unlimitedComplete") or account.get("unlimitedControl") or account.get("unlimitedCore"):
            has_unlimited = True

        # Also check skus array for unlimited
        skus = account.get("skus") or []
        for sku in skus:
            if sku.get("unlimited"):
                has_unlimited = True

    # Compute coverage percentage
    if has_unlimited:
        # Unlimited license capacity — all active agents are covered
        coverage_pct = 100.0
        license_desc = "unlimited"
    elif total_licenses > 0:
        raw = (float(total_active_agents) / float(total_licenses)) * 100.0
        # Cap at 100 if over-provisioned
        if raw > 100.0:
            coverage_pct = 100.0
        else:
            coverage_pct = round(raw, 2)
        license_desc = str(total_licenses) + " licensed seats"
    else:
        coverage_pct = 0.0
        license_desc = "0 licensed seats"

    input_summary = {
        "accountCount": account_count,
        "totalActiveAgents": total_active_agents,
        "totalLicenses": total_licenses if not has_unlimited else -1,
        "hasUnlimitedLicense": has_unlimited,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if has_unlimited:
        pass_reasons.append(
            str(total_active_agents) + " active agents are enrolled across " +
            str(account_count) + " account(s) with an unlimited-capacity license "
            "(totalLicenses=-1, unlimitedComplete=true). "
            "All enrolled endpoints are covered by Endpoint Security — coverage is 100%."
        )
    elif coverage_pct >= 100.0:
        pass_reasons.append(
            str(total_active_agents) + " active agents are enrolled against " +
            license_desc + ". Coverage is " + str(coverage_pct) + "% (full coverage)."
        )
    elif coverage_pct > 0.0:
        fail_reasons.append(
            str(total_active_agents) + " active agents are enrolled against " +
            license_desc + ". Coverage is " + str(coverage_pct) + "%, which is below 100%."
        )
        recommendations.append(
            "Deploy Endpoint Security agents to the remaining " +
            str(total_licenses - total_active_agents) +
            " endpoints that have purchased licenses but are not yet enrolled."
        )
    else:
        fail_reasons.append(
            "No active agents detected (" + str(total_active_agents) +
            ") and no valid license seats found (" + license_desc +
            "). Endpoint Security coverage cannot be determined."
        )
        recommendations.append(
            "Verify that SentinelOne agents are deployed to endpoints and that "
            "a valid license is assigned to this account."
        )

    return create_response(
        result={
            "requiredCoveragePercentage": coverage_pct,
            "totalActiveAgents": total_active_agents,
            "totalLicenses": total_licenses if not has_unlimited else -1,
            "hasUnlimitedLicense": has_unlimited,
            "accountCount": account_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "requiredCoveragePercentage",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
