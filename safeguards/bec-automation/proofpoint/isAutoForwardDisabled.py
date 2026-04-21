"""
Transformation: isAutoForwardDisabled
Vendor: Proofpoint  |  Category: bec-automation
Evaluates: Whether automatic email forwarding is blocked via org filter policies
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAutoForwardDisabled", "vendor": "Proofpoint", "category": "bec-automation"}
        }
    }


AUTO_FORWARD_TERMS = [
    "auto-forward", "autoforward", "auto forward", "automatic forward",
    "inbox rule", "inboxrule", "x-ms-exchange-inbox-rules-loop",
    "forwarding rule", "forwardingrule", "auto-replied", "autoreply",
    "external forward", "externalforward", "redirect", "mail forward"
]

BLOCKING_ACTIONS = [
    "block", "reject", "discard", "deny", "quarantine", "drop", "delete"
]


def contains_forward_term(text):
    lowered = text.lower()
    for term in AUTO_FORWARD_TERMS:
        if term in lowered:
            return True
    return False


def contains_blocking_action(text):
    lowered = text.lower()
    for action in BLOCKING_ACTIONS:
        if action in lowered:
            return True
    return False


def filter_blocks_auto_forward(f):
    name_val = f.get("name", "")
    desc_val = f.get("description", "")
    action_val = f.get("action", "")
    rule_val = f.get("rule", "")
    cond_val = f.get("condition", "")
    header_val = f.get("header", "")
    type_val = f.get("type", "")
    combined = str(name_val) + " " + str(desc_val) + " " + str(rule_val) + " " + str(cond_val) + " " + str(header_val) + " " + str(type_val)
    action_combined = str(action_val)
    if isinstance(f.get("actions"), list):
        for a in f.get("actions"):
            action_combined = action_combined + " " + str(a)
    has_forward = contains_forward_term(combined)
    has_block = contains_blocking_action(action_combined)
    if not has_block:
        has_block = contains_blocking_action(combined)
    return has_forward and has_block


def evaluate(data):
    try:
        filters = []

        if isinstance(data, list):
            filters = data
        elif isinstance(data, dict):
            for candidate_key in ["filters", "policies", "rules", "data"]:
                val = data.get(candidate_key, None)
                if isinstance(val, list):
                    filters = val
                    break
            if len(filters) == 0:
                direct_keys = [
                    "auto_forward_disabled", "autoForwardDisabled",
                    "block_auto_forward", "blockAutoForward",
                    "disable_auto_forward", "disableAutoForward"
                ]
                for key in direct_keys:
                    if key in data:
                        raw_val = data[key]
                        is_disabled = False
                        if isinstance(raw_val, bool):
                            is_disabled = raw_val
                        elif isinstance(raw_val, str):
                            is_disabled = raw_val.lower() in ["true", "enabled", "active", "1"]
                        elif isinstance(raw_val, int):
                            is_disabled = raw_val == 1
                        return {
                            "isAutoForwardDisabled": is_disabled,
                            "detectedField": key,
                            "detectedValue": str(raw_val),
                            "matchingFilters": 0
                        }

        matching = []
        for f in filters:
            if isinstance(f, dict) and filter_blocks_auto_forward(f):
                name = f.get("name", f.get("id", "unnamed"))
                matching.append(str(name))

        is_disabled = len(matching) > 0

        return {
            "isAutoForwardDisabled": is_disabled,
            "matchingFilters": len(matching),
            "totalFilters": len(filters),
            "matchingFilterNames": ", ".join(matching) if matching else "none"
        }
    except Exception as e:
        return {"isAutoForwardDisabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isAutoForwardDisabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False}, validation=validation,
                fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append(criteriaKey + " check passed")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields[k]))
        else:
            fail_reasons.append(criteriaKey + " check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Configure a filter policy in Proofpoint Essentials to block or discard outbound messages identified as auto-forwarded, including those matching X-MS-Exchange-Inbox-Rules-Loop or similar headers.")
        result = {criteriaKey: result_value}
        for k in extra_fields:
            result[k] = extra_fields[k]
        input_summary = {criteriaKey: result_value}
        for k in extra_fields:
            input_summary[k] = extra_fields[k]
        return create_response(
            result=result, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons,
            recommendations=recommendations, input_summary=input_summary)
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
