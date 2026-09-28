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


def as_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def is_rfm(value):
    return value is True or str(value).strip().lower() in ("yes", "true")


def transform(input):
    """
    isEPPConfigured (CrowdStrike, from GET /devices/combined/devices/v1, Hosts: Read).

    A whole-number percentage, floor(100 * configured / protected); the pass bar lives in the
    requirement. protected = Falcon host records returned (computers and servers; mobile hosts are
    left out). configured = hosts whose prevention policy is applied (device_policies.prevention has a
    policy_id and applied true) and whose sensor is not in reduced functionality mode. Host last_seen
    age is not read, so staleness is never held against a host.

    Not evaluated (dataCollection error, no value) on an API error, no resources list, a record that
    is not a host, a truncated device list, or no host to measure.
    """
    if isinstance(input, bytes):
        input = input.decode("utf-8")
    if isinstance(input, str):
        try:
            input = json.loads(input) if input.strip() else None
        except ValueError:
            input = None
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    api_errors = []
    if data.get("error") or data.get("errorType") == "internal" or str(data.get("status", "")).lower() == "error":
        msg = data.get("errorMessage") or data.get("message") or "Unknown API error"
        api_errors.append(f"CrowdStrike API returned an error: {msg}")

    resources = data.get("resources")
    if not isinstance(resources, list):
        if not api_errors:
            api_errors.append("Response has no resources list; not a Falcon host list")
        resources = []

    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    pagination = meta.get("pagination") if isinstance(meta.get("pagination"), dict) else {}
    reported_total = as_int(pagination.get("total"))
    truncated_flag = pagination.get("truncated") is True or str(pagination.get("truncated")).strip().lower() == "true"
    if not api_errors and ((reported_total is not None and reported_total > len(resources)) or truncated_flag):
        api_errors.append(
            f"Device list was truncated: {len(resources)} of {reported_total if reported_total is not None else 'unknown'} "
            "devices returned; not evaluated on a sample"
        )
    if not api_errors and any(not isinstance(d, dict) or not d.get("device_id") for d in resources):
        api_errors.append("Response is not a Falcon host list (a record has no device_id); check the method wiring")

    protected = 0
    configured = 0
    no_prevention = 0
    rfm = 0
    skipped_mobile = 0
    if not api_errors:
        for device in resources:
            platform = str(device.get("platform_name") or "")
            if device.get("product_type_desc") == "Mobile" or platform in ("Android", "iOS"):
                skipped_mobile = skipped_mobile + 1
                continue
            protected = protected + 1
            policies = device.get("device_policies") if isinstance(device.get("device_policies"), dict) else {}
            prevention = policies.get("prevention") if isinstance(policies.get("prevention"), dict) else {}
            applied = bool(prevention.get("policy_id")) and str(prevention.get("applied")).strip().lower() == "true"
            if is_rfm(device.get("reduced_functionality_mode")):
                rfm = rfm + 1
            elif not applied:
                no_prevention = no_prevention + 1
            else:
                configured = configured + 1
        if protected == 0:
            api_errors.append(
                f"No Falcon computer or server was returned ({len(resources)} host records, {skipped_mobile} mobile); "
                "there is nothing to measure"
            )

    value = None if api_errors else (configured * 100) // protected

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    if api_errors:
        fail_reasons.append("Not measured: " + "; ".join(api_errors))
        recommendations.append(
            "Verify the CrowdStrike API credentials (Hosts: Read) and that the device method pages through the "
            "whole estate, then re-run the scan."
        )
    else:
        line = (
            f"{configured} of {protected} Falcon hosts ({value}%) have their prevention policy applied with a fully "
            f"functional sensor; {no_prevention} without an applied prevention policy, {rfm} in reduced functionality mode."
        )
        if configured == protected:
            pass_reasons.append(line)
        else:
            fail_reasons.append(line)
            recommendations.append(
                "Assign an enabled prevention policy to those hosts' groups and resolve reduced functionality mode."
            )

    summary = {
        "hostRecords": len(resources),
        "protectedHosts": protected,
        "configuredHosts": configured,
        "noAppliedPreventionPolicy": no_prevention,
        "reducedFunctionalityMode": rfm,
        "mobileSkipped": skipped_mobile,
    }
    result = {"isEPPConfigured": value, "protectedHosts": protected, "configuredHosts": configured}

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=summary,
        metadata={
            "transformationId": "isEPPConfigured",
            "vendor": "CrowdStrike Falcon",
            "category": "epp",
            "source": "devices/combined/devices/v1 device_policies.prevention",
        },
        api_errors=api_errors,
    )
