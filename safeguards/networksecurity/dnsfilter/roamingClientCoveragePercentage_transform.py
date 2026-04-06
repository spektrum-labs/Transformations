"""
Transformation: roamingClientCoveragePercentage
Vendor: DNSFilter
Category: Network Security

Calculates percentage of protected roaming clients.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "roamingClientCoveragePercentage", "vendor": "DNSFilter", "category": "Network Security"}
        }
    }

def transform(input):
    criteriaKey = "roamingClientCoveragePercentage"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        agents = data if isinstance(data, list) else []
        if isinstance(data, dict):
            agents = data.get("agents", data.get("roamingClients", []))

        total_agents = len(agents)

        if total_agents == 0:
            fail_reasons.append("No roaming clients deployed")
            recommendations.append("Deploy DNSFilter roaming clients to protect remote endpoints")
            return create_response(
                result={criteriaKey: False, "coverage": 0, "totalAgents": 0, "protectedAgents": 0},
                validation=validation,
                fail_reasons=fail_reasons,
                recommendations=recommendations,
                input_summary={"totalAgents": 0, "protectedAgents": 0}
            )

        protected_agents = 0
        for agent in agents:
            if isinstance(agent, dict):
                status = str(agent.get("status", "")).lower()
                if status in ("protected", "active", "online"):
                    protected_agents = protected_agents + 1

        coverage = (protected_agents * 100) / total_agents if total_agents > 0 else 0
        coverage = round(coverage, 2)
        meets_threshold = coverage >= 95

        if meets_threshold:
            pass_reasons.append(f"Roaming client coverage is {coverage}% ({protected_agents}/{total_agents})")
        else:
            fail_reasons.append(f"Roaming client coverage is {coverage}% ({protected_agents}/{total_agents}), below 95% threshold")
            recommendations.append("Ensure at least 95% of roaming clients are in active/protected status")

        return create_response(
            result={criteriaKey: meets_threshold, "coverage": coverage, "totalAgents": total_agents, "protectedAgents": protected_agents},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalAgents": total_agents, "protectedAgents": protected_agents, "coverage": coverage}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
