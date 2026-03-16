"""
Transformation: isReportingEnabled
Vendor: NINJIO  |  Category: Security Awareness Training
Evaluates: Whether NINJIO ALERT (the phishing reporter add-in) is available and enabled,
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isReportingEnabled", "vendor": "NINJIO", "category": "Security Awareness Training"}
        }
    }


def evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:
        if isinstance(data, list):
            campaigns = data
        else:
            campaigns = (
                data.get("results") or
                data.get("data") or
                data.get("campaigns") or
                data.get("items") or
                []
            )

        if not isinstance(campaigns, list):
            campaigns = [campaigns] if campaigns else []

        total_campaigns = len(campaigns)
        alert_configured = False

        # Active statuses
        active_statuses = {"active", "scheduled", "running", "in_progress", "live", "enabled", "ongoing"}

        active_campaign_count = 0
        for campaign in campaigns:
            if not isinstance(campaign, dict):
                continue

            status = str(campaign.get("status", campaign.get("state", ""))).lower()
            if status in active_statuses or status == "":
                active_campaign_count += 1

            # Check for explicit ALERT/reporter configuration in campaign
            alert_fields = [
                "alert_enabled", "alertEnabled",
                "reporter_enabled", "reporterEnabled",
                "phish_alert", "phishAlert",
                "alert_configured", "alertConfigured"
            ]
            for field in alert_fields:
                val = campaign.get(field)
                if val is not None:
                    if isinstance(val, bool) and val:
                        alert_configured = True
                    elif str(val).lower() in ("true", "yes", "1", "enabled"):
                        alert_configured = True

        # Primary check: explicit ALERT configuration found
        if alert_configured:
            result = True
        # Fallback: PHISH3D is active → ALERT is available (bundled)
        elif active_campaign_count > 0:
            result = True
        else:
            result = False
        return {"isReportingEnabled": result, "phishingCampaignCount": active_campaign_count}
    except Exception as e:
        return {"isReportingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isReportingEnabled"
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

        # Run core evaluation
        eval_result = evaluate(data)

        # Extract the boolean result and any extra fields
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(f"Review NINJIO configuration for {criteriaKey}")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
