"""
Transformation: isFirewallConfigured
Vendor: Cisco FMC  |  Category: Firewall
Evaluates: Whether access control policies are assigned to managed devices.

Data source: FMC REST API
  - GET /api/fmc_config/v1/domain/{domainUUID}/assignment/policyassignments

A firewall is configured when:
  1. Policy assignments exist
  2. Each assignment has a policy and at least one target device
  3. At least one managed device has a policy assigned

Response structure:
  { "items": [
      { "id": "...",
        "name": "...",
        "policy": { "id": "...", "name": "Production Policy", "type": "AccessPolicy" },
        "targets": [ { "id": "...", "name": "FTD-01", "type": "Device" } ]
      }
  ]}
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isFirewallConfigured", "vendor": "Cisco FMC", "category": "Firewall"}
        }
    }


def extract_assignments(data):
    """Extract policy assignment items from various input shapes."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        items = data.get("items", [])
        if isinstance(items, list):
            return items
        if "policy" in data and "targets" in data:
            return [data]
    return []


def evaluate(data):
    """Evaluate whether access control policies are assigned to managed devices."""
    try:
        assignments = extract_assignments(data)

        if not assignments:
            return {"isFirewallConfigured": False, "error": "No policy assignments found"}

        configured_devices = set()
        policy_names = []
        unassigned_policies = []
        findings = []

        for assignment in assignments:
            if not isinstance(assignment, dict):
                continue

            policy = assignment.get("policy")
            if not isinstance(policy, dict):
                continue

            policy_name = policy.get("name", "Unknown")
            targets = assignment.get("targets", [])
            if not isinstance(targets, list):
                targets = []

            device_names = []
            for target in targets:
                if isinstance(target, dict):
                    device_name = target.get("name", target.get("id", "Unknown"))
                    device_id = target.get("id", "")
                    configured_devices.add(device_id)
                    device_names.append(device_name)

            if device_names:
                policy_names.append(policy_name)
                findings.append(f"{policy_name} assigned to {len(device_names)} device(s): {', '.join(device_names[:5])}")
            else:
                unassigned_policies.append(policy_name)
                findings.append(f"{policy_name}: no target devices assigned")

        is_configured = len(configured_devices) > 0 and len(policy_names) > 0

        return {
            "isFirewallConfigured": is_configured,
            "assignedPolicies": len(policy_names),
            "assignedPolicyNames": policy_names,
            "configuredDevices": len(configured_devices),
            "unassignedPolicies": unassigned_policies,
            "findings": findings[:10]
        }
    except Exception as e:
        return {"isFirewallConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isFirewallConfigured"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            policies = eval_result.get("assignedPolicyNames", [])
            devices = eval_result.get("configuredDevices", 0)
            pass_reasons.append(f"{len(policies)} policy/policies assigned to {devices} device(s)")
            if policies:
                pass_reasons.append(f"Policies: {', '.join(policies[:5])}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Assign access control policies to managed devices in Cisco FMC")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "assignedPolicies": extra_fields.get("assignedPolicies", 0), "configuredDevices": extra_fields.get("configuredDevices", 0)},
            additional_findings=eval_result.get("findings", [])
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
