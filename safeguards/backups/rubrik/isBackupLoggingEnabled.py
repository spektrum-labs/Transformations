"""
Transformation: isBackupLoggingEnabled
Vendor: Rubrik  |  Category: Backup
Evaluates: Whether backup audit logging / event logging is enabled on the Rubrik cluster.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupLoggingEnabled", "vendor": "Rubrik", "category": "Backup"}
        }
    }


def evaluate(data):
    try:
        if not isinstance(data, dict):
            if isinstance(data, list) and len(data) > 0:
                return {"isBackupLoggingEnabled": True, "loggingSource": "event_list", "eventCount": len(data)}
            return {"isBackupLoggingEnabled": False, "error": "Unexpected response format"}

        if "isEnabled" in data:
            enabled = bool(data["isEnabled"])
            log_level = str(data.get("logLevel", data.get("level", "Unknown")))
            return {"isBackupLoggingEnabled": enabled, "logLevel": log_level, "loggingSource": "isEnabled_field"}

        if "loggingEnabled" in data:
            enabled = bool(data["loggingEnabled"])
            log_level = str(data.get("logLevel", "Unknown"))
            return {"isBackupLoggingEnabled": enabled, "logLevel": log_level, "loggingSource": "loggingEnabled_field"}

        if "auditLogEnabled" in data:
            enabled = bool(data["auditLogEnabled"])
            return {"isBackupLoggingEnabled": enabled, "logLevel": str(data.get("logLevel", "Unknown")), "loggingSource": "auditLogEnabled_field"}

        if "syslogConfig" in data:
            cfg = data["syslogConfig"]
            if isinstance(cfg, dict):
                enabled = cfg.get("isEnabled", cfg.get("enabled", False))
                hostname = cfg.get("hostname", cfg.get("host", ""))
                return {"isBackupLoggingEnabled": bool(enabled), "syslogHost": str(hostname), "loggingSource": "syslogConfig"}

        if "hostname" in data and ("port" in data or "protocol" in data):
            enabled = data.get("isEnabled", data.get("enabled", True))
            return {"isBackupLoggingEnabled": bool(enabled), "syslogHost": str(data.get("hostname", "")), "loggingSource": "syslog_direct"}

        if "data" in data and isinstance(data["data"], list) and len(data["data"]) > 0:
            event_count = len(data["data"])
            return {"isBackupLoggingEnabled": True, "eventCount": event_count, "loggingSource": "event_data_present"}

        if "total" in data and int(data.get("total", 0)) > 0:
            return {"isBackupLoggingEnabled": True, "totalEvents": int(data["total"]), "loggingSource": "total_events"}

        if "enabledFeatures" in data and isinstance(data["enabledFeatures"], list):
            features = [str(f).upper() for f in data["enabledFeatures"]]
            logging_enabled = any("LOG" in f or "AUDIT" in f for f in features)
            return {"isBackupLoggingEnabled": logging_enabled, "loggingSource": "enabledFeatures"}

        return {"isBackupLoggingEnabled": False, "error": "Could not determine logging status from response"}
    except Exception as e:
        return {"isBackupLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupLoggingEnabled"
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
        if result_value:
            pass_reasons.append("Rubrik backup logging is enabled")
            source = extra_fields.get("loggingSource", "")
            if source:
                additional_findings.append("Logging detected via: " + source)
            if "logLevel" in extra_fields:
                additional_findings.append("Log level: " + str(extra_fields["logLevel"]))
            if "syslogHost" in extra_fields:
                additional_findings.append("Syslog host: " + str(extra_fields["syslogHost"]))
        else:
            fail_reasons.append("Rubrik backup logging does not appear to be enabled")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable audit logging and syslog forwarding in Rubrik cluster settings to maintain an event trail")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, "loggingSource": extra_fields.get("loggingSource", "")}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
