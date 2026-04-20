"""
Transformation: isEmailSecurityLoggingEnabled
Vendor: Mimecast  |  Category: Email Security
Evaluates: Check if email security logging is enabled and producing log data
via the Mimecast SIEM endpoint /api/audit/get-siem-logs. A successful
non-empty data response or a valid isLastToken flag confirms logging is active.
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
                "transformationId": "isEmailSecurityLoggingEnabled",
                "vendor": "Mimecast",
                "category": "Email Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isEmailSecurityLoggingEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed" and not isinstance(data, dict):
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        logging_enabled = False
        log_entry_count = 0
        is_last_token = None
        meta_status = None
        file_names = []

        meta = {}
        log_entries = []

        # getSiemLogs returnSpec exposes both meta and data keys.
        # After extract_input the payload is a dict containing both.
        if isinstance(data, dict):
            meta = data.get("meta", {})
            raw_entries = data.get("data", [])
            if isinstance(raw_entries, list):
                log_entries = raw_entries
        elif isinstance(data, list):
            log_entries = data

        if isinstance(meta, dict):
            meta_status = meta.get("status")
            is_last_token = meta.get("isLastToken")

        log_entry_count = len(log_entries)

        for entry in log_entries:
            if isinstance(entry, dict):
                file_name = entry.get("file", "")
                if file_name:
                    file_names.append(str(file_name))

        # Evaluation logic:
        # 1. Non-empty data array  -> active log delivery confirmed.
        # 2. isLastToken present   -> SIEM endpoint is configured and responding.
        # 3. meta.status == 200    -> successful API call without data yet.
        if log_entry_count > 0:
            logging_enabled = True
        elif is_last_token is not None:
            logging_enabled = True
        elif meta_status == 200:
            logging_enabled = True

        if logging_enabled:
            if log_entry_count > 0:
                pass_reasons.append(
                    "Mimecast SIEM logging is active with "
                    + str(log_entry_count) + " log file(s) available"
                )
                for fn in file_names:
                    additional_findings.append("Log file: " + fn)
            else:
                pass_reasons.append(
                    "Mimecast SIEM logging endpoint is configured and responding "
                    "(no new log entries in the current collection period)"
                )
            if is_last_token is not None:
                additional_findings.append("isLastToken: " + str(is_last_token))
        else:
            fail_reasons.append(
                "Mimecast SIEM logging does not appear to be active or configured"
            )
            recommendations.append(
                "Enable SIEM log integration in the Mimecast Administration Console "
                "under Account | Account Settings | Enhanced Logging"
            )
            recommendations.append(
                "Ensure the API application has the 'Logs | SIEM | Read' permission "
                "in Mimecast"
            )

        return create_response(
            result={
                criteriaKey: logging_enabled,
                "logEntryCount": log_entry_count,
                "isLastToken": is_last_token
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "logEntryCount": log_entry_count,
                "isLastToken": is_last_token,
                "metaStatus": meta_status
            },
            additional_findings=additional_findings
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
