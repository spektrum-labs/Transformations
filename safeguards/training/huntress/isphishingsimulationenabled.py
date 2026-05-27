"""
Transformation: isPhishingSimulationEnabled
Vendor: Huntress SAT (Curricula)
Category: Training / Phishing Simulation

Validates that at least one phishing simulation campaign is configured for the
customer. Consumes /api/v1/accounts/{accountId}/phishing-campaigns which returns
a JSON:API list:

  {"data": [{"type": "phishing-campaigns", "id": "...", "attributes": {title, status, campaignStartsAt, campaignEndsAt, campaignLaunchedAt, attemptStats, ...}}, ...],
   "meta": {"page": {"total": N, ...}}}

Each campaign has a status: 'in-progress', 'completed', 'scheduled', 'draft', etc.
The safeguard passes when at least one campaign exists. In-progress and recently-
launched counts are surfaced as additional signal.
"""

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
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isPhishingSimulationEnabled",
                "vendor": "Huntress SAT",
                "category": "Training"
            }
        }
    }


def pull_jsonapi_items(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get('data'), list):
            return data['data']
        if isinstance(data.get('data'), dict):
            return [data['data']]
        return [data]
    return []


def transform(input):
    criteriaKey = "isPhishingSimulationEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        campaigns = pull_jsonapi_items(data)

        total = len(campaigns)
        in_progress = 0
        completed = 0
        scheduled = 0
        draft = 0
        other = 0
        ever_launched = 0

        for c in campaigns:
            if not isinstance(c, dict):
                continue
            attrs = c.get('attributes') if isinstance(c.get('attributes'), dict) else c
            status = str(attrs.get('status', '')).lower()
            if status == 'in-progress':
                in_progress += 1
            elif status == 'completed':
                completed += 1
            elif status == 'scheduled':
                scheduled += 1
            elif status == 'draft':
                draft += 1
            else:
                other += 1
            if attrs.get('campaignLaunchedAt'):
                ever_launched += 1

        phishing_enabled = total > 0

        if phishing_enabled:
            pass_reasons.append(
                f"Phishing simulation is enabled ({total} campaign(s): "
                f"{in_progress} in-progress, {completed} completed, "
                f"{scheduled} scheduled, {draft} draft)"
            )
            if ever_launched == 0:
                additional_findings.append(
                    "Campaigns exist but none have been launched yet"
                )
            elif in_progress == 0 and scheduled == 0:
                additional_findings.append(
                    "No campaigns are currently in-progress or scheduled — "
                    "phishing simulation may be inactive"
                )
        else:
            fail_reasons.append("No phishing simulation campaigns configured for this customer")
            recommendations.append(
                "Configure at least one phishing simulation campaign in Huntress SAT"
            )

        return create_response(
            result={
                criteriaKey: phishing_enabled,
                "totalCampaigns": total,
                "inProgressCampaigns": in_progress,
                "completedCampaigns": completed,
                "scheduledCampaigns": scheduled,
                "draftCampaigns": draft,
                "otherStatusCampaigns": other,
                "everLaunchedCampaigns": ever_launched
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalCampaigns": total,
                "inProgressCampaigns": in_progress,
                "completedCampaigns": completed,
                "scheduledCampaigns": scheduled,
                "everLaunchedCampaigns": ever_launched
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
