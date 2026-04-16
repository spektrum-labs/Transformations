"""
Transformation: isAccessPolicyConfigured
Vendor: BeyondTrust Privileged Remote Access (PRA)  |  Category: Identity & Access Management
Evaluates: At least one session policy with active access controls is configured.
In PRA, access/session behavior is governed through session policies (e.g. command
shell, screen sharing, remote control, file transfer). Presence of policies with
at least one meaningful access permission configured indicates access policy exists.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAccessPolicyConfigured", "vendor": "BeyondTrust PRA", "category": "Identity & Access Management"}
        }
    }


# Values that indicate a permission is actively granted in PRA session policies
ACTIVE_PERM_VALUES = ("allowed", "granted", "yes", "true", "1", "notdefined")
# Keys on a session policy that represent access-control permissions
ACCESS_PERM_KEYS = (
    "screen_sharing", "command_shell", "remote_control", "file_transfer",
    "canned_scripts", "send_special_actions", "system_information", "registry_access",
    "elevation_prompt", "session_recording", "system_info_chat"
)


def _is_active(val):
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return val > 0
    if isinstance(val, str):
        return val.lower() in ACTIVE_PERM_VALUES
    return False


def evaluate(data):
    try:
        if isinstance(data, dict):
            policies = data.get("session_policies", data.get("items", data.get("results", [])))
        elif isinstance(data, list):
            policies = data
        else:
            return {"isAccessPolicyConfigured": False, "totalPolicies": 0, "configuredPolicyCount": 0, "reason": "Unexpected type"}

        total = len(policies)
        configured_count = 0

        for policy in policies:
            if not isinstance(policy, dict):
                continue
            # A policy counts as "configured" if at least one access-control permission is explicitly set
            for key in ACCESS_PERM_KEYS:
                if key in policy and _is_active(policy[key]):
                    configured_count += 1
                    break

        return {
            "isAccessPolicyConfigured": configured_count > 0,
            "totalPolicies": total,
            "configuredPolicyCount": configured_count
        }
    except Exception as e:
        return {"isAccessPolicyConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isAccessPolicyConfigured"
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

        pass_reasons, fail_reasons, recommendations = [], [], []
        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Configure a PRA session policy with at least one explicit access-control permission (e.g. command_shell, screen_sharing, session_recording)")

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
