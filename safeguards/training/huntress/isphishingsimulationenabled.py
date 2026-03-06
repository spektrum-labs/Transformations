"""
Transformation: isPhishingSimulationEnabled
Vendor: Huntress SAT (Curricula)
Category: Training / Phishing Simulation

Validates that phishing simulation campaigns are configured and being sent.
Checks the phishing_campaigns endpoint for active campaigns.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
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

        phishing_enabled = False
        total_campaigns = 0
        active_campaigns = 0

        campaigns = []

        if isinstance(data, dict):
            if 'phishing_campaigns' in data and isinstance(data['phishing_campaigns'], list):
                campaigns = data['phishing_campaigns']
            elif 'campaigns' in data and isinstance(data['campaigns'], list):
                campaigns = data['campaigns']
            elif 'data' in data and isinstance(data['data'], list):
                campaigns = data['data']
        elif isinstance(data, list):
            campaigns = data

        total_campaigns = len(campaigns)

        if total_campaigns > 0:
            for campaign in campaigns:
                if isinstance(campaign, dict):
                    status = str(campaign.get('status', '')).lower()
                    state = str(campaign.get('state', '')).lower()
                    is_active = campaign.get('active', campaign.get('is_active', None))

                    if status in ('active', 'in_progress', 'sending', 'scheduled', 'running') or \
                       state in ('active', 'in_progress', 'sending', 'scheduled', 'running') or \
                       is_active is True:
                        active_campaigns += 1
                    elif not status and not state and is_active is None:
                        # No status field means likely active
                        active_campaigns += 1

            if active_campaigns > 0:
                phishing_enabled = True
            else:
                # Campaigns exist but none active - still counts as enabled
                phishing_enabled = True
                additional_findings.append(f"All {total_campaigns} phishing campaigns may be completed or inactive")

        if phishing_enabled:
            reason = f"Phishing simulation is enabled ({total_campaigns} campaign(s) found"
            if active_campaigns > 0:
                reason += f", {active_campaigns} active)"
            else:
                reason += ")"
            pass_reasons.append(reason)
        else:
            fail_reasons.append("No phishing simulation campaigns found")
            recommendations.append("Configure phishing simulation campaigns in Huntress SAT")

        return create_response(
            result={
                criteriaKey: phishing_enabled,
                "totalCampaigns": total_campaigns,
                "activeCampaigns": active_campaigns
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalCampaigns": total_campaigns,
                "activeCampaigns": active_campaigns
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
