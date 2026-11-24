"""
Transformation: isMFAEnforced
Vendor: PingFederate  |  Category: Multi-Factor Authentication
Evaluates: Active authentication policy trees reference MFA adapters (currently not evaluated; see evaluate())
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMFAEnforced", "vendor": "PingFederate", "category": "Multi-Factor Authentication"}
        }
    }


# WHY THIS RETURNS "NOT EVALUATED" RATHER THAN A VERDICT
#
# evaluate() called walk_node(), which was never defined, so any enabled policy tree raised
# NameError. It also returned its verdict under "isMFAEnforcedForUsers" while transform() reads
# "isMFAEnforced", and it read authenticationPolicies[].authenticationPolicyTrees[] -- a shape
# PingFederate does not send. Each defect alone meant the check could never pass.
#
# Defining walk_node does not make a verdict possible. PingFederate's policy endpoint
# (GET /pf-admin-api/v1/authenticationPolicies/default; the official Terraform provider's
# pingfederate_authentication_policies resource mirrors it) returns authnSelectionTrees, each a
# rootNode whose action may be an AUTHN_SOURCE naming an adapter by sourceRef.id. That id is
# the adapter INSTANCE name the customer chose ("HTMLForm", "PingID", anything), not the plugin
# type. Telling an MFA adapter from a password form needs the adapter list
# (/idp/adapters -> pluginDescriptorRef.id), which this response does not carry; see
# ismfaenabled.py for what is and is not verified about those plugin ids. Counting every
# referenced source as MFA would pass a password-only policy.
#
# So walk_node collects the sources the enabled trees reference, as evidence, and the verdict
# is None until the policy tree is joined with the adapter list.


def walk_node(node, found_refs):
    """Collect sourceRef ids of authentication sources in a policy tree, depth first."""
    stack = [node]
    while stack:
        current = stack.pop()
        if not isinstance(current, dict):
            continue
        action = current.get("action")
        if isinstance(action, dict):
            source = action.get("authenticationSource")
            if isinstance(source, dict):
                ref = source.get("sourceRef")
                if isinstance(ref, dict) and ref.get("id"):
                    found_refs.append(str(ref.get("id")))
        children = current.get("children")
        if isinstance(children, list):
            stack.extend(children)


def evaluate(data):
    """Deliberately returns no verdict. See the note above."""
    trees = data.get("authnSelectionTrees") if isinstance(data, dict) else None
    found_refs = []
    enabled_trees = 0
    if isinstance(trees, list):
        for tree in trees:
            if not isinstance(tree, dict) or tree.get("enabled") is False:
                continue
            enabled_trees += 1
            root_node = tree.get("rootNode")
            if root_node:
                walk_node(root_node, found_refs)
    return {
        "isMFAEnforced": None,
        "enabledPolicyTrees": enabled_trees,
        "authenticationSourcesReferenced": sorted(set(found_refs)),
        "reason": ("PingFederate's authentication policy names each authentication source by the "
                   "adapter instance id the administrator chose, not by adapter type, and this "
                   "response does not include the adapter list needed to tell an MFA adapter from "
                   "a password form, so isMFAEnforced was not evaluated."),
    }


def transform(input):
    criteriaKey = "isMFAEnforced"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                fail_reasons=["Input validation failed, so this was not evaluated."],
                api_errors=["Input validation failed, so this was not evaluated."]
            )

        # Run core evaluation
        eval_result = evaluate(data)

        # Extract the boolean result and any extra fields
        result_value = eval_result.get(criteriaKey, None)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        api_errors = []

        if result_value is None:
            # Not evaluated. dataCollection.status "error" (from api_errors) is what makes
            # Token-Service record it as not evaluated rather than as a measured failure.
            reason = str(eval_result.get("reason") or f"{criteriaKey} was not evaluated.")
            fail_reasons.append(reason)
            api_errors.append(reason)
        elif result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(f"Review PingFederate configuration for {criteriaKey}")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields},
            api_errors=api_errors
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
