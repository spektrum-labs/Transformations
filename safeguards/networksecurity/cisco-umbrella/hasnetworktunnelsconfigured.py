import json
from datetime import datetime, timedelta


def extract_input(input_data):
    """Extract (data, validation) from either the enriched or the legacy input format."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
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
    """Build the standard 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
        "vendor": "Cisco Umbrella",
        "category": "Network Security",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if transform_err_list else "success",
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


def as_list(data, item_key="items"):
    """Return the list of records regardless of how far the platform unwrapped the response.

    Token-Service walks response/result/apiResponse/Output/data before the transform runs,
    so a {"data": [...]} envelope can arrive already reduced to a bare list.
    """
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in (item_key, "items", "data", "records"):
            value = data.get(key)
            if isinstance(value, list):
                return value
    return []


CRITERIA_KEY = "hasNetworkTunnelsConfigured"

# Tunnel states Umbrella reports as carrying live traffic.
USABLE_STATES = ("active", "up", "connected", "established")
# States that mean the tunnel object exists but is not passing traffic.
DOWN_STATES = ("inactive", "down", "disconnected", "unestablished")


def normalise(value):
    return str(value or "").strip().lower()


def transform(input):
    try:
        if isinstance(input, (str, bytes)):
            input = json.loads(input)
        data, validation = extract_input(input)
        tunnels = as_list(data)
        tunnels = [t for t in tunnels if isinstance(t, dict)]

        usable, down, unknown_state = [], [], []
        for tunnel in tunnels:
            state = normalise(tunnel.get("state") or tunnel.get("status"))
            if state in USABLE_STATES:
                usable.append(tunnel)
            elif state in DOWN_STATES:
                down.append(tunnel)
            else:
                # Umbrella omits a state field on some tunnel shapes; an existing
                # tunnel object with no explicit down state still counts as configured.
                unknown_state.append(tunnel)

        configured = len(usable) + len(unknown_state) > 0
        result = {
            CRITERIA_KEY: configured,
            "totalTunnels": len(tunnels),
            "usableTunnels": len(usable),
            "downTunnels": len(down),
            "tunnelsWithoutState": len(unknown_state),
        }

        pass_reasons, fail_reasons, recommendations = [], [], []
        if not tunnels:
            fail_reasons.append(
                "No IPsec/GRE network tunnels are configured, so branch traffic can egress "
                "without traversing Umbrella's inspection path.")
            recommendations.append(
                "Configure at least one encrypted network tunnel from a branch site to "
                "Umbrella under Deployments > Network Tunnels, or confirm this estate is "
                "covered by roaming clients instead of site tunnels.")
        elif configured:
            names = [t.get("name") or t.get("id") for t in (usable + unknown_state)[:5]]
            pass_reasons.append(
                "%d network tunnel(s) are configured (%d reporting a live state), confirming "
                "encrypted site-to-cloud connectivity into Umbrella."
                % (len(tunnels), len(usable)))
            if names:
                pass_reasons.append("Tunnels: %s" % ", ".join(str(n) for n in names))
        else:
            fail_reasons.append(
                "%d tunnel(s) exist but all report a down state, so no encrypted site-to-cloud "
                "path is currently carrying traffic." % len(tunnels))
            recommendations.append("Investigate why the configured tunnels are not established.")

        return create_response(
            result=result, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalTunnels": len(tunnels), "usableTunnels": len(usable)},
            metadata={"transformationId": CRITERIA_KEY})
    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: False}, transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % e],
            metadata={"transformationId": CRITERIA_KEY})
