"""
Transformation: isPrivilegedIdentityManagementEnabled
Vendor: Microsoft
Category: Identity / PIM

Evaluates if Privileged Identity Management (PIM) is enabled by checking role eligibility schedules.

Input: the Graph role eligibility read (roleEligibilitySchedules or roleEligibilityScheduleInstances). The read
may be a single page ($top=1, the original method), the full paged list with every page concatenated, a bare
list of instances, a list of Graph pages, or a merged body carrying the read under roleEligibilityScheduleInstances
or roleEligibilitySchedules. scheduleCount is the number of rows read across all pages. When a page still carries
@odata.nextLink the count is a lower bound (inputSummary.scheduleCountComplete false): at least one schedule still
shows PIM in use, but a read with no schedule and more pages (or an error marker in a page) is not evaluated
(dataCollection error). A row counts only when it is an object with an id, principalId or roleDefinitionId.
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
                "transformationId": "isPrivilegedIdentityManagementEnabled",
                "vendor": "Microsoft",
                "category": "Identity"
            }
        }
    }


SCHEDULE_KEYS = ["roleEligibilityScheduleInstances", "roleEligibilitySchedules"]


ERROR_MARKERS = ["error", "vendorErrorAsResponse", "PSError"]


def schedule_rows(data):
    """(rows, complete) across every page of the eligibility read. A row is a schedule only when it is an object
    with an id, principalId or roleDefinitionId; a page or row that is an error marker makes the read incomplete."""
    if isinstance(data, dict) and "value" not in data:
        for key in SCHEDULE_KEYS:
            if key in data:
                data = data.get(key)
                break
    if isinstance(data, dict) and "value" in data:
        pages = [data]
    elif isinstance(data, list) and len(data) > 0 and all(isinstance(page, dict) and "value" in page
                                                          for page in data):
        pages = data
    elif isinstance(data, list):
        pages = [{"value": data}]
    else:
        return [], True
    rows = []
    complete = True
    for page in pages:
        value = page.get("value") or []
        if not isinstance(value, list):
            value = [value] if value else []
        if len([k for k in ERROR_MARKERS if k in page]) > 0:
            complete = False
        for row in value:
            if not isinstance(row, dict):
                continue
            if len([k for k in ERROR_MARKERS if k in row]) > 0:
                complete = False
            elif row.get("id") or row.get("principalId") or row.get("roleDefinitionId"):
                rows.append(row)
        if str(page.get("@odata.nextLink") or "").strip() not in ("", "None", "null"):
            complete = False
    return rows, complete


def transform(input):
    criteriaKey = "isPrivilegedIdentityManagementEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if not isinstance(data, (dict, list)):
            return create_response(
                result={criteriaKey: False, "scheduleCount": 0},
                validation=validation,
                fail_reasons=["Unexpected input format: expected a JSON object"]
            )

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False, "scheduleCount": 0},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        if isinstance(data, dict) and "error" in data:
            error_info = data.get("error", {})
            inner_error = error_info.get("innerError", {})
            return create_response(
                result={criteriaKey: False, "scheduleCount": 0},
                validation={"status": "error", "errors": [error_info.get("message", "API error")], "warnings": []},
                fail_reasons=[f"Microsoft Graph API error: {error_info.get('code', 'unknown')}"],
                input_summary={"errorCode": error_info.get("code"), "innerErrorCode": inner_error.get("code") if inner_error else None}
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Same file as safeguards/d9b6f27a-2e67-4b55-a09e-0784c5de9abd/isprivilegedidentitymanagementenabled.py
        # Tenants with only permanent role assignments (no eligible/JIT roles) can false-negative here.
        schedules, complete = schedule_rows(data)

        if not schedules and not complete:
            return create_response(
                result={criteriaKey: False, "scheduleCount": 0},
                validation=validation,
                fail_reasons=["The role eligibility read returned no schedule and is incomplete (more pages "
                              "or an error returned as data)"],
                api_errors=["The role eligibility read is incomplete: no schedule read and more pages "
                            "(@odata.nextLink) or an error returned as data"],
                input_summary={"scheduleCount": 0, "scheduleCountComplete": False}
            )

        is_enabled = len(schedules) > 0
        count_text = ("at least " if not complete else "") + str(len(schedules))

        if is_enabled:
            pass_reasons.append(f"PIM is enabled with {count_text} role eligibility schedules configured")
        else:
            fail_reasons.append("No Privileged Identity Management (PIM) roles configured")
            recommendations.append("Enable Privileged Identity Management in Azure AD")

        return create_response(
            result={criteriaKey: is_enabled, "scheduleCount": len(schedules)},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"scheduleCount": len(schedules), "scheduleCountComplete": complete}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "scheduleCount": 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
