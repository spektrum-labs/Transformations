"""
Transformation: isBackupEnabledForCriticalSystems
Vendor: Commvault  |  Category: Backups
Evaluates: What percentage of registered servers/clients have an active backup plan
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupEnabledForCriticalSystems", "vendor": "Commvault", "category": "Backups"}
        }
    }


def _evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:
        COVERAGE_THRESHOLD = 90.0

        servers = (
            data.get("fileServers") or
            data.get("servers") or
            data.get("clients") or
            data.get("clientList") or
            data.get("value") or
            []
        )

        if not isinstance(servers, list):
            return {
                "isBackupEnabledForCriticalSystems": False,
                "error": "No server list in response"
            }

        total = len(servers)
        if total == 0:
            return {
                "isBackupEnabledForCriticalSystems": False,
                "coverage": 0.0,
                "protectedServers": 0,
                "totalServers": 0,
                "reason": "No servers found in environment"
            }

        protected = 0
        for server in servers:
            # Check if server is configured for backup (has a plan assigned)
            plan_id = server.get("planId", server.get("backupPlanId"))
            plan_name = server.get("planName", server.get("assignedPlan", ""))
            configured = server.get("configured", server.get("isConfigured", False))
            last_backup = server.get("lastBackupTime", server.get("lastBackupJobTime"))

            # A server is considered protected if it has a plan assigned
            # OR if it's marked as configured with a recent backup
            has_plan = bool(plan_id or plan_name)
            is_configured = bool(configured) and str(configured).lower() not in ("false", "0", "no")
            has_recent_backup = bool(last_backup) and int(last_backup) > 0

            if has_plan or is_configured or has_recent_backup:
                protected += 1

        coverage = (protected / total) * 100
        result = coverage >= COVERAGE_THRESHOLD
    except Exception as e:
        return {"isBackupEnabledForCriticalSystems": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupEnabledForCriticalSystems"
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
            recommendations.append(f"Review Commvault configuration for {criteriaKey}")

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
