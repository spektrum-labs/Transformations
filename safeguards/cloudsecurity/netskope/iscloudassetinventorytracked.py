"""
Transformation: isCloudAssetInventoryTracked
Vendor: Netskope
Category: Cloud Security / Asset Inventory

Confirms that the Netskope CASB cloud asset inventory is being tracked by
inspecting application events (/api/v2/events/data/application). Each event
represents a user's interaction with a sanctioned or unsanctioned cloud app,
which is the underlying data source for Netskope's cloud asset (Shadow IT)
inventory. The set of unique applications observed indicates the breadth of
cloud asset visibility.
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data.get("data"), input_data.get("validation")
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data.get(key)
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
                "transformationId": "isCloudAssetInventoryTracked",
                "vendor": "Netskope",
                "category": "Cloud Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isCloudAssetInventoryTracked"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        events = []
        if isinstance(data, list):
            events = data
        elif isinstance(data, dict):
            for key in ("result", "data", "events", "items", "value"):
                value = data.get(key)
                if isinstance(value, list):
                    events = value
                    break

        event_count = len(events) if isinstance(events, list) else 0

        unique_apps = {}
        unique_users = {}
        category_breakdown = {}
        ccl_breakdown = {}
        sanctioned_count = 0
        unsanctioned_count = 0

        for event in events:
            if not isinstance(event, dict):
                continue

            app_name = event.get("app") or event.get("application") or event.get("appname")
            if isinstance(app_name, str) and app_name:
                unique_apps[app_name] = unique_apps.get(app_name, 0) + 1

            user = event.get("user") or event.get("user_name") or event.get("src_user")
            if isinstance(user, str) and user:
                unique_users[user] = unique_users.get(user, 0) + 1

            category = event.get("appcategory") or event.get("category")
            if isinstance(category, str) and category:
                category_breakdown[category] = category_breakdown.get(category, 0) + 1

            ccl = event.get("ccl")
            if isinstance(ccl, str) and ccl:
                ccl_breakdown[ccl] = ccl_breakdown.get(ccl, 0) + 1

            classification = event.get("classification") or event.get("app_tags") or event.get("instance_id")
            sanctioned_flag = event.get("sanctioned_instance")
            if isinstance(sanctioned_flag, str):
                if sanctioned_flag.lower() in ("yes", "true", "1"):
                    sanctioned_count = sanctioned_count + 1
                elif sanctioned_flag.lower() in ("no", "false", "0"):
                    unsanctioned_count = unsanctioned_count + 1
            elif isinstance(sanctioned_flag, bool):
                if sanctioned_flag is True:
                    sanctioned_count = sanctioned_count + 1
                else:
                    unsanctioned_count = unsanctioned_count + 1
            elif isinstance(classification, str):
                lower_class = classification.lower()
                if "sanction" in lower_class and "unsanction" not in lower_class:
                    sanctioned_count = sanctioned_count + 1
                elif "unsanction" in lower_class or "shadow" in lower_class:
                    unsanctioned_count = unsanctioned_count + 1

        inventory_tracked = event_count > 0 and len(unique_apps) > 0

        if inventory_tracked:
            pass_reasons.append(
                "Netskope is tracking cloud assets: "
                + str(event_count)
                + " application event(s) across "
                + str(len(unique_apps))
                + " unique application(s)"
            )
            additional_findings.append({"uniqueApplications": len(unique_apps)})
            additional_findings.append({"uniqueUsers": len(unique_users)})
            if sanctioned_count > 0:
                additional_findings.append({"sanctionedInstanceCount": sanctioned_count})
            if unsanctioned_count > 0:
                additional_findings.append({"unsanctionedInstanceCount": unsanctioned_count})
            if category_breakdown:
                additional_findings.append({"categoryBreakdown": category_breakdown})
            if ccl_breakdown:
                additional_findings.append({"cloudConfidenceLevelBreakdown": ccl_breakdown})
        else:
            fail_reasons.append(
                "No application events were returned from /api/v2/events/data/application - the cloud asset inventory cannot be confirmed"
            )
            recommendations.append(
                "Confirm Netskope steering (inline traffic) or SaaS API instances are configured so application events are generated, and that the REST API v2 token can read /api/v2/events/data/application"
            )

        return create_response(
            result={
                criteriaKey: inventory_tracked,
                "applicationEventCount": event_count,
                "uniqueApplications": len(unique_apps),
                "uniqueUsers": len(unique_users),
                "sanctionedInstanceCount": sanctioned_count,
                "unsanctionedInstanceCount": unsanctioned_count
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "applicationEventCount": event_count,
                "uniqueApplications": len(unique_apps),
                "uniqueUsers": len(unique_users)
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
