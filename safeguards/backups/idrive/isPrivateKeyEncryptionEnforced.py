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


def b64decode_to_str(s):
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    lookup = {}
    i = 0
    for c in chars:
        lookup[c] = i
        i = i + 1
    s = s.rstrip("=")
    bits = ""
    for c in s:
        if c in lookup:
            val = lookup[c]
            b = ""
            shift = 5
            while shift >= 0:
                b = b + str((val >> shift) & 1)
                shift = shift - 1
            bits = bits + b
    bytes_out = []
    idx = 0
    while idx + 8 <= len(bits):
        byte_str = bits[idx:idx + 8]
        byte_val = int(byte_str, 2)
        bytes_out.append(byte_val)
        idx = idx + 8
    return "".join([chr(b) for b in bytes_out])


def decode_configuration(configuration_id):
    if not configuration_id or not isinstance(configuration_id, str):
        return None
    try:
        decoded_str = b64decode_to_str(configuration_id)
        parsed = json.loads(decoded_str)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        return None
    return None


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    transformation_errors = []
    companies = []

    if isinstance(data, dict):
        companies.append(data)
        sub_list = data.get("sub_company_list") or []
        if isinstance(sub_list, list):
            for sub in sub_list:
                if isinstance(sub, dict):
                    companies.append(sub)
    elif isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict):
                companies.append(entry)

    evaluated = []
    for company in companies:
        cfg_id = company.get("configuration_id")
        decoded = decode_configuration(cfg_id)
        if decoded is not None:
            enc_required = bool(decoded.get("encryptionRequired"))
            evaluated.append({
                "company_id": company.get("company_id"),
                "name": company.get("name"),
                "encryptionRequired": enc_required,
                "decoded": True,
            })
        else:
            evaluated.append({
                "company_id": company.get("company_id"),
                "name": company.get("name"),
                "encryptionRequired": False,
                "decoded": False,
            })

    total_companies = len(evaluated)
    decoded_companies = [c for c in evaluated if c["decoded"]]
    enforced_companies = [c for c in evaluated if c["decoded"] and c["encryptionRequired"]]

    if total_companies == 0:
        transformation_errors.append("No company records found in response")
        is_enforced = False
    elif len(decoded_companies) == 0:
        transformation_errors.append("Could not decode configuration_id for any company")
        is_enforced = False
    else:
        is_enforced = (len(enforced_companies) == len(decoded_companies)) and (len(decoded_companies) == total_companies)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enforced:
        names = [str(c.get("name")) for c in evaluated]
        pass_reasons.append(
            f"All {total_companies} company record(s) ({', '.join(names)}) decode configuration_id "
            f"to encryptionRequired=true, indicating private-key encryption is mandatory."
        )
    else:
        for c in evaluated:
            if c["decoded"] and not c["encryptionRequired"]:
                fail_reasons.append(
                    f"Company '{c.get('name')}' (company_id={c.get('company_id')}) has configuration_id "
                    f"decoding to encryptionRequired=false, meaning private-key encryption is not enforced."
                )
            elif not c["decoded"]:
                fail_reasons.append(
                    f"Company '{c.get('name')}' (company_id={c.get('company_id')}) has a configuration_id "
                    f"that could not be decoded; encryption enforcement could not be confirmed."
                )
        if not fail_reasons:
            fail_reasons.append("Private-key encryption is not confirmed as enforced for all companies.")
        recommendations.append(
            "Enable and enforce private-key (local) encryption for all companies/devices in the IDrive 360 "
            "management console, rather than leaving it optional."
        )

    result = {
        "isPrivateKeyEncryptionEnforced": is_enforced,
        "totalCompaniesEvaluated": total_companies,
        "companiesWithEncryptionEnforced": len(enforced_companies),
    }

    input_summary = {
        "totalCompaniesEvaluated": total_companies,
        "decodedCompanies": len(decoded_companies),
        "enforcedCompanies": len(enforced_companies),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        transformation_errors=transformation_errors,
        metadata={
            "transformationId": "isPrivateKeyEncryptionEnforced",
            "vendor": "IDrive",
            "category": "backup",
        },
    )
