"""
Transformation: isEmailSecurityLoggingEnabled
Vendor: Symantec  |  Category: emailsecurity
Evaluates: Whether email security data feeds and logging are active in Symantec Email Security.cloud (via the data feed status endpoint).
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEmailSecurityLoggingEnabled", "vendor": "Symantec", "category": "emailsecurity"}
        }
    }


def evaluate(data):
    try:
        feeds = data.get("data", [])
        if not isinstance(feeds, list):
            feeds = []

        total_feeds = len(feeds)
        active_feeds = []
        inactive_feeds = []

        for feed in feeds:
            if not isinstance(feed, dict):
                continue
            feed_name = str(feed.get("name", feed.get("feedName", feed.get("id", "unknown"))))
            status = str(feed.get("status", feed.get("state", ""))).lower()
            enabled = feed.get("enabled", feed.get("active", None))

            is_active = False
            if status in ["active", "enabled", "running", "streaming", "connected", "true"]:
                is_active = True
            elif enabled is True or str(enabled).lower() in ["true", "1", "yes"]:
                is_active = True

            if is_active:
                active_feeds.append(feed_name)
            else:
                inactive_feeds.append(feed_name)

        if total_feeds > 0:
            logging_enabled = len(active_feeds) > 0
        else:
            logging_enabled = False

        return {
            "isEmailSecurityLoggingEnabled": logging_enabled,
            "totalDataFeeds": total_feeds,
            "activeFeedsCount": len(active_feeds),
            "inactiveFeedsCount": len(inactive_feeds),
            "activeFeeds": active_feeds,
            "inactiveFeeds": inactive_feeds
        }
    except Exception as e:
        return {"isEmailSecurityLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEmailSecurityLoggingEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        total = extra_fields.get("totalDataFeeds", 0)
        active = extra_fields.get("activeFeedsCount", 0)
        inactive_list = extra_fields.get("inactiveFeeds", [])
        if result_value:
            pass_reasons.append("Email security data feeds are active. " + str(active) + " of " + str(total) + " feed(s) streaming.")
            pass_reasons.append("Active feeds: " + ", ".join(extra_fields.get("activeFeeds", [])))
        else:
            if total == 0:
                fail_reasons.append("No data feeds found in the data feed status response.")
                recommendations.append("Configure and enable email security data feeds in the Symantec Email Security.cloud portal under Services > Data Feeds.")
            else:
                fail_reasons.append("No active data feeds found. " + str(total) + " feed(s) present but none active.")
                recommendations.append("Activate email security data feeds. Inactive feeds: " + ", ".join(inactive_list))
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalDataFeeds": total, "activeFeedsCount": active})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
