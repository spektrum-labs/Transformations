"""
Transformation: isIncidentWorkflowConfigured
Vendor: Netwrix  |  Category: SIEM
Evaluates: Whether Netwrix Auditor has an incident response workflow configured
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isIncidentWorkflowConfigured", "vendor": "Netwrix", "category": "SIEM"}
        }
    }


def _evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:
        records = (
            data.get("ActivityRecordSearch", None) or
            data.get("activityRecordSearch", None) or
            data.get("ActivityRecordList", None) or
            data.get("activityRecordList", [])
        )

        if not isinstance(records, list):
            return {
                "isIncidentWorkflowConfigured": False,
                "error": "Unexpected response structure",
                "workflowActionCount": 0
            }

        # Look for indicators of incident workflow integration:
        # 1. DataSource = "Netwrix API" indicates 3rd-party data is flowing through
        #    the Integration API (e.g., ServiceNow correlation, custom workflow scripts)
        # 2. Action types like "Run Script", "Created Ticket", "Remediation"
        # 3. ObjectType = "Alert Response" or "Incident"

        workflow_indicators = {
            "data_sources": set(),
            "response_actions": [],
            "api_written_records": 0
        }

        response_action_keywords = {
            "run script", "script executed", "ticket created", "incident created",
            "remediation", "response action", "blocked", "quarantined",
            "alert response", "auto remediation", "automated response"
        }

        for record in records:
            data_source = str(record.get("DataSource", record.get("dataSource", ""))).lower()
            action = str(record.get("Action", record.get("action", ""))).lower()
            obj_type = str(record.get("ObjectType", record.get("objectType", ""))).lower()

            workflow_indicators["data_sources"].add(data_source)

            # Netwrix API data source = records written via Integration API (3rd-party workflows)
            if "netwrix api" in data_source or "api" in data_source:
                workflow_indicators["api_written_records"] += 1

            # Check action and object type for response indicators
            for keyword in response_action_keywords:
                if keyword in action or keyword in obj_type:
                    workflow_indicators["response_actions"].append({
                        "action": record.get("Action", ""),
                        "objectType": record.get("ObjectType", ""),
                        "dataSource": record.get("DataSource", "")
                    })
                    break

        workflow_action_count = (
            len(workflow_indicators["response_actions"]) +
            workflow_indicators["api_written_records"]
        )

        result = workflow_action_count > 0

        return {
            "isIncidentWorkflowConfigured": result,
            "workflowActionCount": workflow_action_count,
            "apiWrittenRecords": workflow_indicators["api_written_records"],
            "responseActionRecords": len(workflow_indicators["response_actions"]),
            "distinctDataSources": list(workflow_indicators["data_sources"]),
            "reason": (
                "Incident workflow evidence found: API-written records or response actions detected"
                if result
                else "No automated response or workflow integration records found"
            )
        }
    except Exception as e:
        return {"isIncidentWorkflowConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isIncidentWorkflowConfigured"
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
        eval_result = _evaluate(data)

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
            recommendations.append(f"Review Netwrix configuration for {criteriaKey}")

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
