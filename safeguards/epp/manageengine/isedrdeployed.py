"""
Transformation: isEDRDeployed
Vendor: ManageEngine Endpoint Central  |  Category: EPP
Evaluates: Percentage of managed endpoints with agents deployed based on SOM summary.
Source: GET /api/1.4/som/summary
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEDRDeployed", "vendor": "ManageEngine", "category": "EPP"}
        }
    }


def evaluate(data):
    """Evaluate agent deployment coverage from SOM summary data."""
    try:
        # SOM summary provides total computers, managed (agent installed), and unmanaged counts
        total_computers = 0
        managed_computers = 0

        # Direct summary fields
        total_computers = int(data.get("total_computers", data.get("totalComputers", data.get("total", 0))))
        managed_computers = int(data.get("managed_computers", data.get("managedComputers", data.get("managed", 0))))
        agent_installed = int(data.get("agent_installed_count", data.get("agentInstalledCount", data.get("agents_installed", 0))))

        # Use agent_installed if available, otherwise use managed
        deployed = agent_installed if agent_installed > 0 else managed_computers

        # If summary has nested computer_summary or som_summary
        summary = data.get("computer_summary", data.get("computerSummary", data.get("som_summary", {})))
        if isinstance(summary, dict) and not total_computers:
            total_computers = int(summary.get("total_computers", summary.get("total", 0)))
            managed_computers = int(summary.get("managed_computers", summary.get("managed", 0)))
            deployed = managed_computers

        # Fallback: if data contains a list of computers
        if not total_computers and isinstance(data.get("computers", data.get("data", None)), list):
            computers = data.get("computers", data.get("data", []))
            total_computers = len(computers)
            deployed = len([c for c in computers if isinstance(c, dict) and str(c.get("agent_status", c.get("agentStatus", ""))).lower() in ("installed", "active", "online", "managed")])

        coverage_percentage = 0.0
        if total_computers > 0:
            coverage_percentage = (deployed / total_computers) * 100

        is_deployed = coverage_percentage >= 80.0

        return {
            "isEDRDeployed": is_deployed,
            "totalEndpoints": total_computers,
            "agentDeployedCount": deployed,
            "coveragePercentage": round(coverage_percentage, 2)
        }
    except Exception as e:
        return {"isEDRDeployed": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEDRDeployed"
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

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"Agent deployed on {extra_fields.get('agentDeployedCount', 0)} of {extra_fields.get('totalEndpoints', 0)} endpoints ({extra_fields.get('coveragePercentage', 0)}%)")
        else:
            total = extra_fields.get("totalEndpoints", 0)
            deployed = extra_fields.get("agentDeployedCount", 0)
            pct = extra_fields.get("coveragePercentage", 0)
            if total == 0:
                fail_reasons.append("No endpoints found in ManageEngine Endpoint Central SOM")
                recommendations.append("Verify agents are installed and reporting to Endpoint Central")
            else:
                fail_reasons.append(f"Agent coverage is {pct}% ({deployed}/{total} endpoints) - below 80% threshold")
                recommendations.append("Deploy Endpoint Central agent to remaining unmanaged computers via SOM > Install Agent")

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
