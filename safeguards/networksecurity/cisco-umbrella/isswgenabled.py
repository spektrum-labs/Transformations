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


CRITERIA_KEY = "isSWGEnabled"

# Cisco Umbrella reports SWG state per roaming device as one of:
#   Protected                    - full-proxy SWG inspection active
#   Off                          - SWG module present but switched off
#   NA                           - device/OS does not report SWG at all
#   DisabledDueToTrustedNetwork  - suppressed by design while on a trusted network
PROTECTED = "protected"
OFF = "off"
NOT_APPLICABLE = "na"
TRUSTED_NETWORK = "disabledduetotrustednetwork"

# Share of ELIGIBLE devices (Protected + Off) that must be Protected to pass.
# Devices reporting NA or DisabledDueToTrustedNetwork are excluded from the
# denominator: neither is a misconfiguration.
MIN_COVERAGE_PERCENT = 90


def normalise(value):
    return str(value or "").strip().lower().replace(" ", "").replace("_", "")


def transform(input):
    try:
        if isinstance(input, (str, bytes)):
            input = json.loads(input)
        data, validation = extract_input(input)
        devices = as_list(data)

        protected = []
        switched_off = []
        not_applicable = 0
        trusted_network = 0

        for device in devices:
            if not isinstance(device, dict):
                continue
            state = normalise(device.get("swgStatus"))
            if state == PROTECTED:
                protected.append(device)
            elif state == NOT_APPLICABLE:
                not_applicable += 1
            elif state == TRUSTED_NETWORK:
                trusted_network += 1
            else:
                switched_off.append(device)

        total = len(devices)
        eligible = len(protected) + len(switched_off)
        coverage = round(len(protected) / eligible * 100, 2) if eligible else 0.0
        enabled = eligible > 0 and coverage >= MIN_COVERAGE_PERCENT

        result = {
            CRITERIA_KEY: enabled,
            "swgCoveragePercentage": coverage,
            "protectedDevices": len(protected),
            "unprotectedDevices": len(switched_off),
            "eligibleDevices": eligible,
            "totalDevices": total,
            "notApplicableDevices": not_applicable,
            "trustedNetworkDevices": trusted_network,
            "requiredCoveragePercentage": MIN_COVERAGE_PERCENT,
        }

        pass_reasons, fail_reasons, recommendations = [], [], []
        if total == 0:
            fail_reasons.append(
                "No roaming computers were returned, so Secure Web Gateway coverage "
                "could not be confirmed for any device.")
            recommendations.append(
                "Confirm roaming clients are deployed and reporting under "
                "Deployments > Core Identities > Roaming Computers.")
        elif eligible == 0:
            fail_reasons.append(
                "None of the %d devices report a usable swgStatus (%d are NA, %d are "
                "suppressed on a trusted network), so SWG enforcement cannot be confirmed."
                % (total, not_applicable, trusted_network))
        elif enabled:
            pass_reasons.append(
                "%d of %d eligible devices report swgStatus=Protected (%.2f%%), at or above "
                "the %d%% bar, confirming full-proxy Secure Web Gateway inspection beyond "
                "DNS-layer-only filtering."
                % (len(protected), eligible, coverage, MIN_COVERAGE_PERCENT))
        else:
            fail_reasons.append(
                "Only %d of %d eligible devices report swgStatus=Protected (%.2f%%), below "
                "the %d%% bar. %d device(s) have SWG switched off and are limited to "
                "DNS-layer filtering."
                % (len(protected), eligible, coverage, MIN_COVERAGE_PERCENT, len(switched_off)))
            sample = [d.get("name") or d.get("originId") for d in switched_off[:5]]
            if sample:
                fail_reasons.append("Examples with SWG off: %s" % ", ".join(str(s) for s in sample))
            recommendations.append(
                "Enable the Secure Web Gateway module in the roaming client policy for the "
                "%d device(s) currently reporting swgStatus=Off." % len(switched_off))

        findings = []
        if not_applicable:
            findings.append("%d device(s) report swgStatus=NA and were excluded from the "
                            "coverage denominator." % not_applicable)
        if trusted_network:
            findings.append("%d device(s) are suppressed by design on a trusted network and "
                            "were excluded from the coverage denominator." % trusted_network)

        return create_response(
            result=result, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalDevices": total, "eligibleDevices": eligible,
                           "protectedDevices": len(protected)},
            additional_findings=findings,
            metadata={"transformationId": CRITERIA_KEY})
    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: False}, transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % e],
            metadata={"transformationId": CRITERIA_KEY})
