"""Evaluate visibility of the SonicOS local-account inventory."""

import json
from datetime import datetime


CRITERIA_KEY = "hasLocalAccountInventoryVisibility"
SUPPORTED_CONTRACTS = ("gen6-combined", "gen6-split", "gen7-split")
SUPPORTED_AUTHENTICATION_MODES = ("basicSession", "digestSession", "tfaBearer")


def empty_counts():
    return {
        "totalLocalAccounts": 0,
        "activeLocalAccounts": 0,
        "expiredAccounts": 0,
        "excludedDomainProxies": 0,
        "unknownAccounts": 0,
    }


def create_response(passed, counts=None, validation_status="passed", validation_errors=None,
                    collection_errors=None, transformation_errors=None, pass_reasons=None,
                    fail_reasons=None, recommendations=None):
    if counts is None:
        counts = empty_counts()
    result = {CRITERIA_KEY: passed}
    for key in counts:
        result[key] = counts[key]
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if collection_errors else "success",
                "errors": collection_errors or [],
            },
            "validation": {
                "status": validation_status,
                "errors": validation_errors or [],
                "warnings": [],
            },
            "transformation": {
                "status": "error" if transformation_errors else "success",
                "errors": transformation_errors or [],
                "inputSummary": counts,
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": [],
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": CRITERIA_KEY,
                "vendor": "SonicWall",
                "category": "Firewall",
            },
        },
    }


def normalized_name(value):
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    return value if value else None


def nested_value(data, path):
    current = data
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current.get(key)
    return current


def extract_input(input_data):
    unknown = {"status": "unknown", "errors": [], "warnings": []}
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        if "source" in input_data or "collection" in input_data or "counts" in input_data or "evidence" in input_data:
            return None, unknown, True
        return input_data.get("data"), input_data.get("validation") or unknown, True
    data = input_data
    if isinstance(data, dict) and ("source" in data or "collection" in data or "counts" in data or "evidence" in data):
        return data, unknown, False
    if isinstance(data, dict):
        for unused in range(3):
            if "source" in data or "collection" in data or "counts" in data or "evidence" in data:
                break
            unwrapped = False
            for key in ("api_response", "response", "result", "apiResponse", "Output"):
                if isinstance(data.get(key), dict):
                    data = data.get(key)
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, unknown, False


def parse_source(record, contract):
    if "domain" not in record or record.get("domain") is None:
        return "local"
    domain = record.get("domain")
    if contract.startswith("gen6"):
        if isinstance(domain, dict) and normalized_name(domain.get("name")):
            return "domainProxy"
        return "unknown"
    if isinstance(domain, str) and normalized_name(domain):
        return "domainProxy"
    return "unknown"


def parse_state(record):
    lifetime = record.get("account_lifetime")
    if not isinstance(lifetime, dict):
        return "unknown"
    if lifetime.get("expired") is True:
        return "expired"
    if lifetime.get("expired") is False:
        return "active"
    return "unknown"


def identity(record, contract, name):
    vendor_uuid = normalized_name(record.get("uuid"))
    if vendor_uuid is not None:
        return ("uuid", vendor_uuid)
    domain = record.get("domain")
    if domain is None:
        return ("local", name)
    if contract.startswith("gen6") and isinstance(domain, dict):
        domain_name = normalized_name(domain.get("name"))
    elif not contract.startswith("gen6") and isinstance(domain, str):
        domain_name = normalized_name(domain)
    else:
        domain_name = None
    if domain_name is not None:
        return ("domain", domain_name, name)
    return ("unknown", name)


def validate_envelope(data):
    errors = []
    if not isinstance(data, dict):
        return None, ["collector_envelope_not_object"]
    source = data.get("source")
    collection = data.get("collection")
    counts = data.get("counts")
    evidence = data.get("evidence")
    if not isinstance(source, dict):
        errors.append("source_missing")
        source = {}
    if not isinstance(collection, dict):
        errors.append("collection_missing")
        collection = {}
    if not isinstance(counts, dict):
        errors.append("counts_missing")
        counts = {}
    if not isinstance(evidence, dict):
        errors.append("evidence_missing")
        evidence = {}
    contract = source.get("apiContract")
    if source.get("vendor") != "SonicWall" or source.get("product") != "SonicOS":
        errors.append("source_not_sonicos")
    if contract not in SUPPORTED_CONTRACTS:
        errors.append("api_contract_unrecognized")
    if source.get("authenticationMode") not in SUPPORTED_AUTHENTICATION_MODES:
        errors.append("authentication_mode_unrecognized")
    if not isinstance(source.get("firmwareVersion"), str):
        errors.append("firmware_version_invalid")
    collection_errors = collection.get("errors")
    ready = (
        collection.get("requiredEndpointsSucceeded") is True
        and collection.get("capabilityProfileRecognized") is True
        and collection.get("allExpectedResponseSectionsPresent") is True
        and isinstance(collection_errors, list)
        and len(collection_errors) == 0
    )
    if not ready:
        safe = collection_errors if isinstance(collection_errors, list) and collection_errors else ["required_collection_incomplete"]
        return {"collectionErrors": safe}, errors
    users_body = evidence.get("localUsers")
    groups_body = evidence.get("localGroups")
    admin_body = evidence.get("administrationGlobal")
    users = nested_value(users_body, ("user", "local", "user"))
    if contract == "gen6-combined":
        groups = nested_value(users_body, ("user", "local", "group"))
        if groups_body is not None:
            errors.append("combined_contract_has_split_groups")
    else:
        groups = nested_value(groups_body, ("user", "local", "group"))
        if nested_value(users_body, ("user", "local", "group")) is not None:
            errors.append("split_contract_has_combined_groups")
    admin = nested_value(admin_body, ("administration", "administration", "admin"))
    if not isinstance(users, list):
        errors.append("local_users_shape_unrecognized")
        users = []
    if not isinstance(groups, list):
        errors.append("local_groups_shape_unrecognized")
        groups = []
    if not isinstance(admin, dict):
        errors.append("built_in_administrator_shape_unrecognized")
    raw_users = counts.get("rawUserEntries")
    raw_groups = counts.get("rawGroupEntries")
    if not isinstance(raw_users, int) or isinstance(raw_users, bool) or raw_users != len(users):
        errors.append("raw_user_count_mismatch")
    if not isinstance(raw_groups, int) or isinstance(raw_groups, bool) or raw_groups != len(groups):
        errors.append("raw_group_count_mismatch")
    return {"contract": contract, "users": users, "collectionErrors": []}, errors


def sanitize_collection_errors(errors):
    allowed = (
        "invalid_settings", "authentication_failed", "local_users_failed",
        "local_groups_failed", "administration_global_failed", "logout_failed",
        "required_collection_incomplete",
    )
    safe = []
    for error in errors:
        text = str(error)
        safe.append(text if text in allowed else "collector_error")
    return safe


def evaluate(users, contract):
    counts = empty_counts()
    errors = []
    identities = {}
    for record in users:
        if not isinstance(record, dict):
            errors.append("local_user_record_not_object")
            counts["unknownAccounts"] = counts["unknownAccounts"] + 1
            continue
        name = normalized_name(record.get("name"))
        if name is None:
            errors.append("local_user_identity_missing")
            counts["unknownAccounts"] = counts["unknownAccounts"] + 1
            continue
        account_identity = identity(record, contract, name)
        if account_identity in identities:
            errors.append("duplicate_local_user_identity")
            counts["unknownAccounts"] = counts["unknownAccounts"] + 1
            continue
        identities[account_identity] = True
        source = parse_source(record, contract)
        if source == "domainProxy":
            counts["excludedDomainProxies"] = counts["excludedDomainProxies"] + 1
            continue
        if source == "unknown":
            errors.append("account_source_unresolved")
            counts["unknownAccounts"] = counts["unknownAccounts"] + 1
            continue
        counts["totalLocalAccounts"] = counts["totalLocalAccounts"] + 1
        state = parse_state(record)
        if state == "active":
            counts["activeLocalAccounts"] = counts["activeLocalAccounts"] + 1
        elif state == "expired":
            counts["expiredAccounts"] = counts["expiredAccounts"] + 1
        else:
            errors.append("account_state_unresolved")
            counts["unknownAccounts"] = counts["unknownAccounts"] + 1
    unique_errors = []
    for error in errors:
        if error not in unique_errors:
            unique_errors.append(error)
    return counts, unique_errors


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, upstream, enriched = extract_input(input)
        if enriched and (not isinstance(upstream, dict) or upstream.get("status") != "passed" or not isinstance(upstream.get("errors"), list) or upstream.get("errors")):
            return create_response(False, validation_status="failed",
                                   validation_errors=["upstream_schema_validation_failed"],
                                   transformation_errors=["input_validation_failed"],
                                   fail_reasons=["SonicOS account inventory evidence could not be validated"])
        validated, envelope_errors = validate_envelope(data)
        if validated is not None and validated.get("collectionErrors"):
            return create_response(False, validation_status="unknown",
                                   collection_errors=sanitize_collection_errors(validated["collectionErrors"]),
                                   fail_reasons=["Required SonicOS account inventory evidence was not collected"],
                                   recommendations=["Verify the SonicOS integration and re-run collection"])
        if envelope_errors:
            return create_response(False, validation_status="failed", validation_errors=envelope_errors,
                                   transformation_errors=["collector_contract_invalid"],
                                   fail_reasons=["SonicOS account inventory evidence did not match a recognized contract"],
                                   recommendations=["Re-collect using a validated SonicOS capability profile"])
        counts, errors = evaluate(validated["users"], validated["contract"])
        if errors:
            return create_response(False, counts=counts, validation_status="failed", validation_errors=errors,
                                   fail_reasons=["SonicOS local-account inventory evidence was indeterminate"],
                                   recommendations=["Resolve incomplete account identity, source, or state evidence and re-check"])
        return create_response(True, counts=counts,
                               pass_reasons=["The complete SonicOS local-account inventory is visible"])
    except Exception:
        return create_response(False, validation_status="failed",
                               validation_errors=["transformation_exception"],
                               transformation_errors=["transformation_failed_safely"],
                               fail_reasons=["SonicOS local-account inventory evaluation could not be completed"])
