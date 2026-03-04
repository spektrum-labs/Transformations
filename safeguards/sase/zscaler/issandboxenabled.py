"""
Transformation: isSandboxEnabled
Vendor: Zscaler ZIA
Category: SASE / Sandbox

Evaluates if cloud sandbox for file analysis is enabled in Zscaler ZIA.
Checks for behavioral analysis and sandbox settings that indicate
files are being analyzed in a sandbox environment.
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
                "transformationId": "isSandboxEnabled",
                "vendor": "Zscaler ZIA",
                "category": "SASE"
            }
        }
    }


def transform(input):
    criteriaKey = "isSandboxEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False, "behavioralAnalysisEnabled": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        isSandboxEnabled = False
        behavioral_analysis_enabled = False

        if isinstance(data, dict):
            # Get sandbox settings from response
            sandbox_settings = data.get('sandboxSettings', data.get('responseData', {}))

            if isinstance(sandbox_settings, dict):
                # Check for sandbox enabled flag
                if sandbox_settings.get('sandboxEnabled', False):
                    isSandboxEnabled = True

                if sandbox_settings.get('cloudSandbox', False):
                    isSandboxEnabled = True

                # Check for behavioral analysis
                if sandbox_settings.get('behavioralAnalysis', False):
                    behavioral_analysis_enabled = True
                    isSandboxEnabled = True

                if sandbox_settings.get('behavioralAnalysisEnabled', False):
                    behavioral_analysis_enabled = True
                    isSandboxEnabled = True

                # Check for file detonation
                if sandbox_settings.get('fileDetonation', False):
                    isSandboxEnabled = True

                if sandbox_settings.get('fileDetonationEnabled', False):
                    isSandboxEnabled = True

                # Check for advanced settings indicating sandbox is active
                if sandbox_settings.get('advancedSettings') or sandbox_settings.get('analysisSettings'):
                    isSandboxEnabled = True

            # If sandbox settings exist and have content, assume sandbox is configured
            if isinstance(sandbox_settings, dict) and len(sandbox_settings) > 0:
                isSandboxEnabled = True

        if isSandboxEnabled:
            reason = "Cloud sandbox is enabled"
            if behavioral_analysis_enabled:
                reason += " with behavioral analysis"
            pass_reasons.append(reason)
        else:
            fail_reasons.append("Cloud sandbox is not configured")
            recommendations.append("Enable cloud sandbox with behavioral analysis in Zscaler ZIA for advanced threat detection")

        return create_response(
            result={criteriaKey: isSandboxEnabled, "behavioralAnalysisEnabled": behavioral_analysis_enabled},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "sandboxEnabled": isSandboxEnabled,
                "behavioralAnalysisEnabled": behavioral_analysis_enabled
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "behavioralAnalysisEnabled": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
