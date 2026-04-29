
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

    if not accounts:
        return create_response(
            result={
                "requiredCoveragePercentage": 0.0,
                "activeAgents": 0,
                "totalLicenses": 0,
                "unlimitedLicense": False,
            },
            validation=validation,
            fail_reasons=["No account records found in the API response. Cannot determine endpoint coverage."],
            recommendations=["Ensure the API token has read access to account data in SentinelOne."],
            input_summary={"accountCount": 0},
            metadata={
                "transformationId": "requiredCoveragePercentage",
                "vendor": "SentinelOne",
                "category": "epp",
            },
        )

    total_active_agents = 0
    total_licenses = 0
    is_unlimited = False
    account_count = len(accounts)

    for account in accounts:
        active = account.get("activeAgents") or 0
        total_active_agents = total_active_agents + active

        tl = account.get("totalLicenses")
        if tl is not None and tl == -1:
            is_unlimited = True
        elif tl is not None and tl > 0:
            total_licenses = total_licenses + tl

        skus = account.get("skus") or []
        for sku in skus:
            if sku.get("unlimited"):
                is_unlimited = True

        if account.get("unlimitedComplete") or account.get("unlimitedControl") or account.get("unlimitedCore"):
            is_unlimited = True

    if is_unlimited:
        coverage = 100.0
        pass_reasons = [
            f"The account holds an unlimited license (totalLicenses=-1 and/or unlimited=true on a SKU). "
            f"All {total_active_agents} active enrolled agents across {account_count} account(s) "
            f"are fully covered with no seat ceiling. Coverage is reported as 100%."
        ]
        fail_reasons = []
        recommendations = []
    elif total_licenses == 0:
        coverage = 0.0
        fail_reasons = [
            f"No licensed seats found (totalLicenses=0) across {account_count} account(s). "
            f"{total_active_agents} active agents exist but no purchased license capacity could be determined."
        ]
        pass_reasons = []
        recommendations = ["Purchase SentinelOne licenses to establish endpoint coverage capacity."]
    else:
        raw_coverage = (float(total_active_agents) / float(total_licenses)) * 100.0
        coverage = round(min(raw_coverage, 100.0), 2)
        if coverage >= 100.0:
            pass_reasons = [
                f"{total_active_agents} active agents are enrolled against {total_licenses} licensed seats "
                f"across {account_count} account(s), yielding {coverage}% endpoint security coverage."
            ]
            fail_reasons = []
            recommendations = []
        else:
            gap = total_licenses - total_active_agents
            fail_reasons = [
                f"Only {total_active_agents} of {total_licenses} licensed seats have enrolled active agents "
                f"across {account_count} account(s), yielding {coverage}% endpoint security coverage. "
                f"{gap} licensed endpoints remain without the SentinelOne agent."
            ]
            pass_reasons = []
            recommendations = [
                f"Deploy the SentinelOne agent to the remaining {gap} endpoints to reach full license coverage."
            ]

    return create_response(
        result={
            "requiredCoveragePercentage": coverage,
            "activeAgents": total_active_agents,
            "totalLicenses": (-1 if is_unlimited else total_licenses),
            "unlimitedLicense": is_unlimited,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "accountCount": account_count,
            "activeAgents": total_active_agents,
            "totalLicenses": (-1 if is_unlimited else total_licenses),
            "unlimitedLicense": is_unlimited,
        },
        metadata={
            "transformationId": "requiredCoveragePercentage",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
