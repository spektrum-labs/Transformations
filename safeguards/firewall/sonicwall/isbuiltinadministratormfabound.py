"""Report whether SonicOS has built-in administrator TOTP configured."""

import json
from datetime import datetime

CRITERIA_KEY = "isBuiltInAdministratorMFABound"
CONTRACTS = ("gen6-combined", "gen6-split", "gen7-split")
AUTH_MODES = ("basicSession", "digestSession", "tfaBearer")


def empty_counts():
    return {"builtInAdministratorAccounts": 0, "totpConfiguredAccounts": 0,
            "notTotpConfiguredAccounts": 0, "unknownAccounts": 0}


def response(passed, counts=None, validation_status="passed", validation_errors=None,
             collection_errors=None, transformation_errors=None, pass_reasons=None,
             fail_reasons=None, recommendations=None):
    counts = counts or empty_counts(); result = {CRITERIA_KEY: passed}; result.update(counts)
    return {"transformedResponse": result, "additionalInfo": {
        "dataCollection": {"status": "error" if collection_errors else "success", "errors": collection_errors or []},
        "validation": {"status": validation_status, "errors": validation_errors or [], "warnings": []},
        "transformation": {"status": "error" if transformation_errors else "success", "errors": transformation_errors or [], "inputSummary": counts},
        "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": ["This setting evidence shows TOTP configuration only; it does not prove that TOTP is bound to a person or enforced during authentication."]},
        "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0", "transformationId": CRITERIA_KEY, "vendor": "SonicWall", "category": "Firewall"}}}


def normalized(value):
    if not isinstance(value, str): return None
    value = value.strip().lower()
    return value if value else None


def nested(data, path):
    for key in path:
        if not isinstance(data, dict) or key not in data: return None
        data = data.get(key)
    return data


def unpack(value):
    unknown = {"status": "unknown", "errors": [], "warnings": []}
    if isinstance(value, dict) and "data" in value and "validation" in value:
        if "source" in value or "collection" in value or "counts" in value or "evidence" in value:
            return None, unknown, True
        return value.get("data"), value.get("validation") or unknown, True
    data = value
    if isinstance(data, dict) and ("source" in data or "collection" in data or "counts" in data or "evidence" in data):
        return data, unknown, False
    if isinstance(data, dict):
        for unused in range(3):
            if "source" in data or "collection" in data or "counts" in data or "evidence" in data: break
            found = False
            for key in ("api_response", "response", "result", "apiResponse", "Output"):
                if isinstance(data.get(key), dict): data = data.get(key); found = True; break
            if not found: break
    return data, unknown, False


def validate(data):
    errors = []
    if not isinstance(data, dict): return None, ["collector_envelope_not_object"]
    source, collection, counts, evidence = data.get("source"), data.get("collection"), data.get("counts"), data.get("evidence")
    if not isinstance(source, dict): errors.append("source_missing"); source = {}
    if not isinstance(collection, dict): errors.append("collection_missing"); collection = {}
    if not isinstance(counts, dict): errors.append("counts_missing"); counts = {}
    if not isinstance(evidence, dict): errors.append("evidence_missing"); evidence = {}
    contract = source.get("apiContract")
    if source.get("vendor") != "SonicWall" or source.get("product") != "SonicOS": errors.append("source_not_sonicos")
    if contract not in CONTRACTS: errors.append("api_contract_unrecognized")
    if source.get("authenticationMode") not in AUTH_MODES: errors.append("authentication_mode_unrecognized")
    if not isinstance(source.get("firmwareVersion"), str): errors.append("firmware_version_invalid")
    collection_errors = collection.get("errors")
    ready = collection.get("requiredEndpointsSucceeded") is True and collection.get("capabilityProfileRecognized") is True and collection.get("allExpectedResponseSectionsPresent") is True and isinstance(collection_errors, list) and not collection_errors
    if not ready: return {"collectionErrors": collection_errors if isinstance(collection_errors, list) and collection_errors else ["required_collection_incomplete"]}, errors
    users_body, groups_body = evidence.get("localUsers"), evidence.get("localGroups")
    users = nested(users_body, ("user", "local", "user"))
    if contract == "gen6-combined":
        groups = nested(users_body, ("user", "local", "group"))
        if groups_body is not None: errors.append("combined_contract_has_split_groups")
    else: groups = nested(groups_body, ("user", "local", "group"))
    if contract != "gen6-combined" and nested(users_body, ("user", "local", "group")) is not None: errors.append("split_contract_has_combined_groups")
    admin = nested(evidence.get("administrationGlobal"), ("administration", "administration", "admin"))
    if not isinstance(users, list): errors.append("local_users_shape_unrecognized"); users = []
    if not isinstance(groups, list): errors.append("local_groups_shape_unrecognized"); groups = []
    if not isinstance(admin, dict): errors.append("built_in_administrator_shape_unrecognized"); admin = {}
    if not isinstance(counts.get("rawUserEntries"), int) or isinstance(counts.get("rawUserEntries"), bool) or counts.get("rawUserEntries") != len(users): errors.append("raw_user_count_mismatch")
    if not isinstance(counts.get("rawGroupEntries"), int) or isinstance(counts.get("rawGroupEntries"), bool) or counts.get("rawGroupEntries") != len(groups): errors.append("raw_group_count_mismatch")
    return {"admin": admin, "collectionErrors": []}, errors


def evaluate(admin):
    counts = empty_counts(); counts["builtInAdministratorAccounts"] = 1
    if normalized(admin.get("name")) is None:
        counts["unknownAccounts"] = 1
        return counts, ["built_in_administrator_identity_missing"]
    value = admin.get("one_time_password")
    if not isinstance(value, dict) or "totp" not in value or "otp" in value or not isinstance(value.get("totp"), bool):
        counts["unknownAccounts"] = 1
        return counts, ["built_in_administrator_totp_unresolved"]
    if value.get("totp") is True: counts["totpConfiguredAccounts"] = 1
    else: counts["notTotpConfiguredAccounts"] = 1
    return counts, []


def safe_collection(errors):
    allowed = ("invalid_settings", "authentication_failed", "local_users_failed", "local_groups_failed", "administration_global_failed", "logout_failed", "required_collection_incomplete")
    return [str(error) if str(error) in allowed else "collector_error" for error in errors]


def transform(input):
    try:
        if isinstance(input, str): input = json.loads(input)
        elif isinstance(input, bytes): input = json.loads(input.decode("utf-8"))
        data, upstream, enriched = unpack(input)
        if enriched and (not isinstance(upstream, dict) or upstream.get("status") != "passed" or not isinstance(upstream.get("errors"), list) or upstream.get("errors")):
            return response(False, validation_status="failed", validation_errors=["upstream_schema_validation_failed"], transformation_errors=["input_validation_failed"], fail_reasons=["Built-in administrator TOTP configuration evidence could not be validated"])
        validated, envelope_errors = validate(data)
        if validated is not None and validated.get("collectionErrors"):
            return response(False, validation_status="unknown", collection_errors=safe_collection(validated["collectionErrors"]), fail_reasons=["Required built-in administrator evidence was not collected"])
        if envelope_errors: return response(False, validation_status="failed", validation_errors=envelope_errors, transformation_errors=["collector_contract_invalid"], fail_reasons=["Built-in administrator evidence did not match a recognized SonicOS contract"])
        counts, errors = evaluate(validated["admin"])
        if errors: return response(False, counts, "failed", errors, fail_reasons=["Built-in administrator TOTP configuration evidence was indeterminate"])
        if counts["totpConfiguredAccounts"] == 1:
            return response(True, counts, pass_reasons=["TOTP is configured for the built-in administrator"])
        return response(False, counts, fail_reasons=["TOTP is not configured for the built-in administrator"], recommendations=["Configure TOTP for the built-in administrator"])
    except Exception:
        return response(False, validation_status="failed", validation_errors=["transformation_exception"], transformation_errors=["transformation_failed_safely"], fail_reasons=["Built-in administrator TOTP configuration evaluation could not be completed"])
