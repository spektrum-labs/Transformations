"""
Transformation: isDataExportConfigured
Vendor: DNSFilter
Category: Network Security

Confirms SIEM data export (S3 or Splunk) is configured.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isDataExportConfigured", "vendor": "DNSFilter", "category": "Network Security"}
        }
    }

def transform(input):
    criteriaKey = "isDataExportConfigured"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        data_export_enabled = False
        s3_configured = False
        splunk_configured = False

        if isinstance(data, dict):
            data_export_enabled = bool(data.get("data_export_enabled", False))

            s3_export = data.get("s3_export", {})
            splunk_export = data.get("splunk_export", {})

            if isinstance(s3_export, dict):
                s3_configured = bool(s3_export.get("enabled", False))
            if isinstance(splunk_export, dict):
                splunk_configured = bool(splunk_export.get("enabled", False))

        is_configured = data_export_enabled or s3_configured or splunk_configured

        if is_configured:
            exports = []
            if s3_configured:
                exports.append("S3")
            if splunk_configured:
                exports.append("Splunk")
            if data_export_enabled and not exports:
                exports.append("data export")
            pass_reasons.append(f"Data export configured: {', '.join(exports)}")
        else:
            fail_reasons.append("No SIEM data export configured")
            recommendations.append("Configure S3 or Splunk data export in DNSFilter for centralized logging")

        return create_response(
            result={criteriaKey: is_configured, "s3Export": s3_configured, "splunkExport": splunk_configured},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"dataExportEnabled": data_export_enabled, "s3Export": s3_configured, "splunkExport": splunk_configured}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
