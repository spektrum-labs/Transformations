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
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
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


def find_people_list(obj, depth):
    """Recursively search for a list of person-like dicts regardless of envelope nesting."""
    if depth > 6:
        return None
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict) and ("tasksSummary" in item or "employment" in item):
                return obj
        return None
    if isinstance(obj, dict):
        preferred_keys = ["data", "results", "people", "apiResponse", "response", "result"]
        for key in preferred_keys:
            if key in obj:
                found = find_people_list(obj[key], depth + 1)
                if found is not None:
                    return found
        for key in obj.keys():
            if key in preferred_keys:
                continue
            found = find_people_list(obj[key], depth + 1)
            if found is not None:
                return found
    return None


def transform(input):
    data, validation = extract_input(input)
    if not isinstance(data, (dict, list)):
        data = {}

    people = find_people_list(data, 0)
    if people is None:
        people = []

    current_employee_count = 0
    applicable_count = 0
    complete_count = 0
    incomplete_samples = []

    for person in people:
        if not isinstance(person, dict):
            continue

        employment = person.get("employment")
        if not isinstance(employment, dict):
            employment = {}

        emp_status = employment.get("status")
        end_date = employment.get("endDate")

        is_current = True
        if emp_status is not None:
            emp_status_upper = str(emp_status).upper()
            if emp_status_upper in ("TERMINATED", "INACTIVE", "FORMER", "OFFBOARDED", "DEACTIVATED"):
                is_current = False
            elif emp_status_upper in ("ACTIVE", "CURRENT", "EMPLOYED"):
                is_current = True
            else:
                is_current = end_date is None
        else:
            is_current = end_date is None

        if not is_current:
            continue

        current_employee_count = current_employee_count + 1

        tasks_summary = person.get("tasksSummary")
        if not isinstance(tasks_summary, dict):
            tasks_summary = {}

        details = tasks_summary.get("details")
        if not isinstance(details, dict):
            details = {}

        task = details.get("installDeviceMonitoring")
        if not isinstance(task, dict):
            continue

        task_status = task.get("status")
        if task_status is None:
            continue

        applicable_count = applicable_count + 1
        task_status_upper = str(task_status).upper()
        if task_status_upper == "COMPLETE":
            complete_count = complete_count + 1
        else:
            if len(incomplete_samples) < 5:
                incomplete_samples.append(task_status)

    if applicable_count > 0:
        rate = (complete_count / applicable_count) * 100.0
    else:
        rate = 0.0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if people and current_employee_count == 0:
        fail_reasons.append(
            f"Found {len(people)} person record(s) in the response, but none could be classified as a "
            f"current employee from employment.status/employment.endDate; completion rate could not be computed."
        )
    elif applicable_count > 0:
        pass_reasons.append(
            f"{complete_count} of {applicable_count} current employees with an applicable "
            f"installDeviceMonitoring task show tasksSummary.details.installDeviceMonitoring.status=COMPLETE "
            f"(out of {current_employee_count} current employees total), a completion rate of {rate:.1f}%."
        )
    else:
        fail_reasons.append(
            f"No current employees ({current_employee_count} identified out of {len(people)} people records) "
            f"carried an applicable installDeviceMonitoring task in tasksSummary.details, so completion rate "
            f"could not be computed."
        )

    if applicable_count > 0 and complete_count < applicable_count:
        fail_reasons.append(
            f"{applicable_count - complete_count} current employees have an incomplete device monitoring "
            f"install task (sample statuses observed: {incomplete_samples})."
        )
        recommendations.append(
            "Follow up with employees whose installDeviceMonitoring task is not COMPLETE to ensure "
            "device monitoring agents are installed."
        )

    result = {
        "deviceMonitoringInstallCompletionRate": rate,
        "currentEmployeeCount": current_employee_count,
        "applicableCount": applicable_count,
        "completeCount": complete_count,
    }

    input_summary = {
        "totalPeopleRecordsSeen": len(people),
        "currentEmployeeCount": current_employee_count,
        "applicableCount": applicable_count,
        "completeCount": complete_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "deviceMonitoringInstallCompletionRate",
            "vendor": "Vanta Compliance Automation",
            "category": "compliance",
        },
    )
