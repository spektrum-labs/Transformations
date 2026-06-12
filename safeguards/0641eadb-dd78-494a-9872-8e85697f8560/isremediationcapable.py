"""
Transformation: isRemediationCapable
Vendor: Anthropic (Claude) Compliance API
Category: Remediation

Evaluates whether the key holds delete:compliance_user_data for automated remediation.

Per the Anthropic Compliance API docs ("Check your key's scopes"), there is NO
programmatic scope-introspection endpoint, and Compliance Access Key scopes are
immutable after creation. Scopes are knowable only via (1) key prefix [type only],
(2) the claude.ai Settings UI Scopes column, or (3) a 403 "Got: [...]" error from an
endpoint the key lacks scope for. None of these confirm delete:compliance_user_data
without attempting a DELETE. This criterion is therefore an OPERATOR ATTESTATION of
the scope list recorded at key creation (supplied via the grantedScopes setting);
it is scope-presence only and NEVER invokes a DELETE endpoint.
"""

import json
from datetime import datetime


def transform(input):
    criteriaKey = "isRemediationCapable"

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
                    "transformationId": "isRemediationCapable",
                    "vendor": "Anthropic",
                    "category": "Remediation"
                }
            }
        }

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

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        result_value = False

        scopes = (data.get("scopes") or data.get("granted_scopes") or data.get("grantedScopes")
                  or data.get("permissions") or []) if isinstance(data, dict) else []
        if isinstance(scopes, str):
            scopes = [s.strip() for s in scopes.replace(",", " ").split()]
        normalized = {str(s).strip().lower() for s in scopes} if isinstance(scopes, list) else set()
        result_value = "delete:compliance_user_data" in normalized
        if result_value:
            pass_reasons.append("Automated remediation provisioned (delete scope granted)")
        else:
            fail_reasons.append("delete:compliance_user_data scope not granted")
            recommendations.append("Grant delete:compliance_user_data if DLP/data-privacy deletion is required")

        return create_response(
            result={criteriaKey: result_value},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % str(e)]
        )
