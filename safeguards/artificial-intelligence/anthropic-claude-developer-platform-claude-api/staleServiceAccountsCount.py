"""Transformation: staleServiceAccountsCount"""
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


def is_service_account_key(record):
    principal = record.get("principal") or {}
    principal_type = principal.get("type") if isinstance(principal, dict) else None
    created_by = record.get("created_by") or {}
    created_by_type = created_by.get("type") if isinstance(created_by, dict) else None
    key_id = record.get("id") or ""
    if principal_type == "service_account_actor":
        return True
    if created_by_type == "service_account":
        return True
    if isinstance(key_id, str) and key_id.startswith("svac_"):
        return True
    principal_id = principal.get("user_id") if isinstance(principal, dict) else None
    if isinstance(principal_id, str) and principal_id.startswith("svac_"):
        return True
    return False


def parse_iso_date(dt_str):
    if not isinstance(dt_str, str) or len(dt_str) < 10:
        return None
    try:
        date_part = dt_str[0:10]
        year_s, month_s, day_s = date_part.split("-")
        return (int(year_s), int(month_s), int(day_s))
    except Exception:
        return None


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = data.get("data") or []
    else:
        records = []

    if not isinstance(records, list):
        records = []

    service_account_keys = [r for r in records if isinstance(r, dict) and is_service_account_key(r)]
    total_service_accounts = len(service_account_keys)

    now = datetime.utcnow()
    now_tuple = (now.year, now.month, now.day)

    stale_records = []
    for r in service_account_keys:
        status = r.get("status") or ""
        expires_at = r.get("expires_at")
        is_stale = False
        if status in ("archived", "expired", "inactive"):
            is_stale = True
        else:
            expires_tuple = parse_iso_date(expires_at)
            if expires_tuple is not None and expires_tuple < now_tuple:
                is_stale = True
        if is_stale:
            stale_records.append(r)

    stale_count = len(stale_records)

    input_summary = {
        "totalApiKeys": len(records),
        "totalServiceAccountKeys": total_service_accounts,
        "staleServiceAccountsCount": stale_count,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_service_accounts == 0:
        pass_reasons.append(
            "None of the %d API keys in the listOrganizationApiKeys response carry a service_account "
            "principal (principal.type=='service_account_actor'), a created_by.type=='service_account', "
            "or an svac_-prefixed id, so the derived stale-service-account count is %d." % (len(records), stale_count)
        )
    elif stale_count > 0:
        names = ", ".join(
            [str(r.get("name") or r.get("id")) for r in stale_records[:5]]
        )
        fail_reasons.append(
            "%d of %d service-account API keys are stale: status is archived/expired/inactive or "
            "expires_at is in the past (examples: %s)." % (stale_count, total_service_accounts, names)
        )
        recommendations.append(
            "Revoke or rotate the stale service-account API keys identified (e.g. %s) since the "
            "Admin API exposes no last_used_at field, status/expiry is the closest available signal "
            "of unused standing credentials." % names
        )
    else:
        pass_reasons.append(
            "All %d service-account API keys have status='active' and no past expires_at, so the "
            "stale-service-account count is 0." % total_service_accounts
        )

    result = {
        "staleServiceAccountsCount": stale_count,
        "totalServiceAccountKeys": total_service_accounts,
        "totalApiKeys": len(records),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "staleServiceAccountsCount",
            "vendor": "Anthropic Claude Developer Platform Claude API",
            "category": "Artificial Intelligence",
        },
    )
