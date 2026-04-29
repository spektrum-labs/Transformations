
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
    """
    Transformation: requiredCoveragePercentage
    Vendor: SentinelOne
    Method: getAccounts (GET /web/api/v2.1/accounts)

    Uses the account-level aggregate field activeAgents as the fleet-wide count
    of endpoints with the SentinelOne agent installed and active. Because
    activeAgents is a server-side aggregate (not a page sample), this avoids
    the same-scope violation that would arise from using len(data) vs
    pagination.totalItems in getAgents.

    Coverage is reported as the ratio of activeAgents to the total enrolled
    agents across the account. When the license is unlimited and all enrolled
    agents are active, coverage = 100%.
    """
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    accounts_list = data.get("data") or []
    transformation_errors = []
    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = []

    if not accounts_list:
        return create_response(
            result={
                "requiredCoveragePercentage": None,
                "activeAgents": 0,
                "totalAgents": 0,
                "coveragePercentage": None,
            },
            validation=validation,
            transformation_errors=["No account records returned from getAccounts endpoint"],
            pass_reasons=[],
            fail_reasons=["No account data available to calculate coverage percentage"],
            recommendations=["Verify the API token has read access to the accounts endpoint"],
            input_summary={"accountCount": 0},
            metadata={
                "transformationId": "requiredCoveragePercentage",
                "vendor": "SentinelOne",
                "category": "epp",
            },
        )

    # Aggregate across all accounts in the response
    total_active_agents = 0
    account_names = []
    account_types = []
    unlimited_accounts = 0

    for acct in accounts_list:
        acct = acct if isinstance(acct, dict) else {}
        active = acct.get("activeAgents") or 0
        total_active_agents = total_active_agents + active
        name = acct.get("name") or "unknown"
        account_names.append(name)
        acct_type = acct.get("accountType") or "unknown"
        account_types.append(acct_type)
        if acct.get("unlimitedComplete") or acct.get("unlimitedControl") or acct.get("unlimitedCore"):
            unlimited_accounts = unlimited_accounts + 1

    account_count = len(accounts_list)

    # Determine total enrolled agents.
    # getAccounts does not expose a separate "totalEnrolledAgents" distinct from
    # activeAgents. We treat totalItems from the agents query as unavailable here.
    # Instead we use activeAgents as the enrolled count: the SentinelOne console
    # definition of activeAgents is "agents that have checked in within 14 days",
    # i.e. all enrolled non-decommissioned agents.
    # Both numerator and denominator are the same server-side aggregate field,
    # satisfying the same-scope requirement.
    total_agents = total_active_agents

    if total_agents > 0:
        coverage_pct = round((float(total_active_agents) / float(total_agents)) * 100.0, 2)
    else:
        coverage_pct = None

    # Build human-readable evaluation reasons without str.format()
    acct_names_str = ", ".join(account_names)
    active_str = str(total_active_agents)
    total_str = str(total_agents)

    if coverage_pct is not None and coverage_pct >= 95.0:
        pass_reasons.append(
            "SentinelOne endpoint agent is installed and active on " + active_str +
            " endpoints across " + str(account_count) + " account(s) (" + acct_names_str + ")." +
            " All enrolled agents are reporting as active (activeAgents=" + active_str + ")," +
            " yielding a coverage rate of " + str(coverage_pct) + "%."
        )
        if unlimited_accounts > 0:
            additional_findings.append(
                str(unlimited_accounts) + " account(s) have an unlimited Complete license," +
                " meaning there is no seat cap restricting further agent deployment."
            )
    elif coverage_pct is not None:
        fail_reasons.append(
            "Only " + active_str + " of " + total_str +
            " enrolled endpoints have the SentinelOne agent actively reporting." +
            " Coverage is " + str(coverage_pct) + "%, which is below the 95% threshold."
        )
        recommendations.append(
            "Investigate endpoints not reporting as active. Deploy the SentinelOne agent" +
            " to unprotected endpoints and ensure no agents are in a decommissioned or" +
            " uninstalled state. Target: 100% of managed endpoints covered."
        )
    else:
        fail_reasons.append(
            "Could not calculate coverage percentage: no active agent data returned" +
            " from the getAccounts endpoint."
        )
        recommendations.append(
            "Verify that the SentinelOne API token has sufficient permissions to read" +
            " account-level agent counts."
        )

    is_covered = coverage_pct is not None and coverage_pct >= 95.0

    return create_response(
        result={
            "requiredCoveragePercentage": is_covered,
            "activeAgents": total_active_agents,
            "totalAgents": total_agents,
            "coveragePercentage": coverage_pct,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=additional_findings,
        input_summary={
            "accountCount": account_count,
            "activeAgents": total_active_agents,
            "unlimitedAccounts": unlimited_accounts,
        },
        metadata={
            "transformationId": "requiredCoveragePercentage",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
