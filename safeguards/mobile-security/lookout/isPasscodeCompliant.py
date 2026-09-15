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


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}
    devices = data.get("devices") or []
    if not isinstance(devices, list):
        devices = []

    total = len(devices)
    compliant = 0
    noncompliant = 0
    unknown = 0
    noncompliant_examples = []

    explicit_keys = ("passcode_compliant", "passcode_status", "screen_lock_enabled", "is_passcode_set", "passcodeCompliant")

    for d in devices:
        if not isinstance(d, dict):
            continue
        passcode_field = None
        for key in explicit_keys:
            if key in d:
                passcode_field = d.get(key)
                break
        if passcode_field is not None:
            if isinstance(passcode_field, str):
                is_ok = passcode_field.upper() in ("TRUE", "COMPLIANT", "ENABLED", "SET")
            else:
                is_ok = bool(passcode_field)
            if is_ok:
                compliant = compliant + 1
            else:
                noncompliant = noncompliant + 1
                noncompliant_examples.append(d.get("guid") or d.get("oid") or "unknown")
        else:
            sec = d.get("security_status")
            prot = d.get("protection_status")
            if sec is None and prot is None:
                unknown = unknown + 1
            elif sec == "SECURE" and prot == "PROTECTED":
                compliant = compliant + 1
            else:
                noncompliant = noncompliant + 1
                noncompliant_examples.append(d.get("guid") or d.get("oid") or "unknown")

    evaluated = compliant + noncompliant

    if evaluated == 0:
        result_bool = False
        pass_reasons = []
        fail_reasons = [
            "No devices in the response carried explicit passcode fields or security_status/protection_status pairs, so passcode compliance could not be confirmed for any of the %d devices returned." % total
        ]
        recommendations = [
            "Verify the Lookout MES tenant is populating security_status/protection_status (or passcode-specific fields) on device records before relying on this criterion."
        ]
    else:
        result_bool = noncompliant == 0
        if result_bool:
            pass_reasons = [
                "All %d evaluated devices report security_status='SECURE' and protection_status='PROTECTED' (or an explicit compliant passcode field), indicating passcode policy compliance. %d devices lacked security data and were excluded from evaluation." % (evaluated, unknown)
            ]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            examples = ", ".join(noncompliant_examples[:5])
            fail_reasons = [
                "%d of %d evaluated devices report a non-SECURE security_status or non-PROTECTED protection_status (or an explicit non-compliant passcode field), including devices: %s." % (noncompliant, evaluated, examples)
            ]
            recommendations = [
                "Review the flagged device GUIDs in the Lookout console and enforce the passcode policy via the connected MDM (e.g. Intune) for those devices."
            ]

    result = {
        "isPasscodeCompliant": result_bool,
        "totalDevices": total,
        "evaluatedDevices": evaluated,
        "compliantDevices": compliant,
        "nonCompliantDevices": noncompliant,
        "unknownDevices": unknown,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalDevices": total, "evaluatedDevices": evaluated},
        metadata={
            "transformationId": "isPasscodeCompliant",
            "vendor": "Lookout",
            "category": "mobile-security",
        },
    )
