"""
Transformation: isBehavioralMonitoringValid
Vendor: Automox
Category: Endpoint Protection

Evaluates isBehavioralMonitoringValid for Automox (EPP)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBehavioralMonitoringValid", "vendor": "Automox", "category": "Endpoint Protection"}
        }
    }


def transform(input):
    criteriaKey = "isBehavioralMonitoringValid"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # ── EVALUATION LOGIC ──
        # Automox uses Worklets (custom policies) and required software policies
        # to enforce security tooling. Check for active policies that indicate
        # behavioral monitoring enforcement
        result = False
        policies = data if isinstance(data, list) else data.get("results", data.get("data", []))

        if not isinstance(policies, list):
            policies = []

        active_policies = [
            p for p in policies
            if p.get("status", "").lower() == "active"
        ]

        # Automox enforces compliance through active patch and custom policies
        # Having active policies indicates the platform is being used for monitoring
        behavioral_keywords = ["monitor", "behavioral", "detection", "worklet", "custom"]
        matching = 0
        for p in active_policies:
            name = p.get("name", "").lower()
            policy_type = p.get("policy_type_name", "").lower()
            for keyword in behavioral_keywords:
                if keyword in name or keyword in policy_type:
                    matching += 1
                    break

        if matching > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return create_response(

            result={
            "isBehavioralMonitoringValid": result,
            "matchingPolicies": matching,
            "totalActivePolicies": len(active_policies)
        },

            validation=validation

        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
