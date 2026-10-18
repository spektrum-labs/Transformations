"""Cisco Meraki MX - isFirewallEnabled (NW-03: Next-Generation Firewall).

Reads GET /organizations/{orgId}/appliance/security/intrusion.

NW-03 asks for a next-generation firewall "in place of a stateful-inspection-only
firewall", so the signal is intrusion detection/prevention being active -- NOT the
presence of L3 firewall rules. Meraki always returns an implicit default-allow L3
rule, so a rule-count check can never fail and would pass this control vacuously.

Passes when at least one appliance reports mode 'prevention' or 'detection' and
none reports 'disabled'. Handles the org-scoped {'items': [...]} shape, a single
{'mode': ...}, and a list produced by iterating across networks. A network the
definition reports as {'vendorErrorAsResponse': ...} with status 400 ("Intrusion detection is not
supported by this network") counts as unprotected. Any other refusal (401, 403, 429, 5xx), an empty
body or an unreadable appliance is a failed read: with no appliance read, or with every read
appliance protected but another unread, the criterion is None (Not evaluated), never a pass or a fail.
"""

import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
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
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


def not_measured(criteria_key, problem, validation=None):
    """Nothing usable was read: the criterion is None with a dataCollection error, never a fail."""
    return create_response(
        result={criteria_key: None},
        validation=validation,
        fail_reasons=[problem],
        recommendations=[
            "Verify the Meraki intrusion settings are readable with this key on every appliance network."
        ],
        api_errors=[problem],
        metadata={
            "transformationId": criteria_key,
            "vendor": "Cisco Meraki MX",
            "category": "firewalls",
        },
    )


def transform(input):
    criteriaKey = "isFirewallEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return not_measured(
                criteriaKey, "The Meraki response failed input validation; nothing to measure.", validation
            )

        modes_seen = {}
        unread_seen = {}

        def collect(obj):
            if isinstance(obj, dict):
                refusal = obj.get("vendorErrorAsResponse")
                if isinstance(refusal, dict):
                    if refusal.get("status") in (400, "400"):
                        # 400 "Intrusion detection is not supported by this network", handed over as
                        # data by the definition: that network has no next-gen protection.
                        modes_seen["not supported"] = modes_seen.get("not supported", 0) + 1
                    else:
                        # Any other refusal (401, 403, 429, 5xx) says nothing about the network.
                        unread_seen["count"] = unread_seen.get("count", 0) + 1
                if "mode" in obj:
                    mode = str(obj.get("mode", "")).lower()
                    modes_seen[mode] = modes_seen.get(mode, 0) + 1

                if "items" in obj:
                    collect(obj["items"])
            elif isinstance(obj, list):
                for item in obj:
                    collect(item)

        collect(data)

        # Derived from modes_seen rather than a closure counter: the sandbox
        # rejects closure rebinding, and every counted appliance lands in
        # modes_seen, so the sum is the same number.
        appliances_evaluated = sum(modes_seen.values())
        unreadable_count = unread_seen.get("count", 0)

        active_count = modes_seen.get("prevention", 0) + modes_seen.get("detection", 0)
        disabled_count = modes_seen.get("disabled", 0) + modes_seen.get("not supported", 0)

        if appliances_evaluated == 0:
            return not_measured(
                criteriaKey,
                "No Meraki MX intrusion mode could be read on any appliance network; nothing to measure.",
                validation,
            )
        if disabled_count > 0:
            enabled = False
        elif unreadable_count > 0:
            # Every appliance that was read is protected, but an unread one could be unprotected,
            # so a pass cannot be proven.
            return not_measured(
                criteriaKey,
                "%d appliance network(s) could not be read, so intrusion protection cannot be "
                "confirmed on every appliance." % unreadable_count,
                validation,
            )
        else:
            enabled = active_count > 0

        if enabled:
            mode_summary = ", ".join(
                f"{mode}:{count}" for mode, count in sorted(modes_seen.items())
            )
            pass_reasons = [
                f"Intrusion prevention/detection is active on {active_count} appliance(s); observed modes: {mode_summary}."
            ]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            if disabled_count > 0:
                fail_reasons = [
                    f"Intrusion prevention/detection is disabled or not supported on {disabled_count} appliance network(s); no active next-gen firewall protection detected."
                ]
                recommendations = [
                    "Enable intrusion prevention or detection on all Meraki MX appliances."
                ]
            else:
                fail_reasons = [
                    "No Meraki MX intrusion prevention/detection mode was found; next-gen firewall protection is not enabled."
                ]
                recommendations = [
                    "Enable intrusion prevention or detection in the Meraki MX security appliance intrusion settings."
                ]

        result = {
            criteriaKey: enabled,
            "modesSeen": modes_seen,
            "appliancesEvaluated": appliances_evaluated,
        }

        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "appliancesEvaluated": appliances_evaluated,
                "modesSeen": modes_seen,
            },
            metadata={
                "transformationId": criteriaKey,
                "vendor": "Cisco Meraki MX",
                "category": "firewalls",
            },
        )

    except Exception:
        # The exception text stays out of the response: it can carry fragments of the vendor body.
        return not_measured(
            criteriaKey,
            "The Meraki response could not be read; nothing to measure.",
            {"status": "error", "errors": [], "warnings": []},
        )
