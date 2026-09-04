"""Evaluate configured MFA coverage for ordinary local SonicOS accounts."""

import json
from datetime import datetime

CRITERIA_KEY = "isMFAEnforcedForLocalAccounts"
SUPPORTED_CONTRACTS = ("gen6-combined", "gen6-split", "gen7-split")
SUPPORTED_AUTHENTICATION_MODES = ("basicSession", "digestSession", "tfaBearer")
ADMIN_GROUPS = ("sonicwall administrators", "sonicwall read-only admins", "limited administrators")
SSL_VPN_GROUP = "sslvpn services"


def empty_counts():
    return {"scoredLocalAccounts": 0, "compliantLocalAccounts": 0,
            "noncompliantLocalAccounts": 0, "administratorAccountsExcluded": 0,
            "sslVpnAccounts": 0, "expiredAccounts": 0,
            "excludedDomainProxies": 0, "unknownAccounts": 0}


def response(passed, counts=None, validation_status="passed", validation_errors=None,
             collection_errors=None, transformation_errors=None, pass_reasons=None,
             fail_reasons=None, recommendations=None):
    counts = counts or empty_counts()
    result = {CRITERIA_KEY: passed}
    result.update(counts)
    return {"transformedResponse": result, "additionalInfo": {
        "dataCollection": {"status": "error" if collection_errors else "success", "errors": collection_errors or []},
        "validation": {"status": validation_status, "errors": validation_errors or [], "warnings": []},
        "transformation": {"status": "error" if transformation_errors else "success", "errors": transformation_errors or [], "inputSummary": counts},
        "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": ["SonicOS settings show MFA configuration; they do not prove enforcement during authentication."]},
        "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0", "transformationId": CRITERIA_KEY, "vendor": "SonicWall", "category": "Firewall"}}}


def name(value):
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    return value if value else None


def at(data, path):
    for key in path:
        if not isinstance(data, dict) or key not in data:
            return None
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
            if "source" in data or "collection" in data or "counts" in data or "evidence" in data:
                break
            found = False
            for key in ("api_response", "response", "result", "apiResponse", "Output"):
                if isinstance(data.get(key), dict):
                    data = data.get(key)
                    found = True
                    break
            if not found:
                break
    return data, unknown, False


def otp(record):
    value = record.get("one_time_password") if isinstance(record, dict) else None
    if not isinstance(value, dict) or (("otp" in value) == ("totp" in value)):
        return "unknown"
    if "totp" in value:
        return "totp" if value.get("totp") is True else ("none" if value.get("totp") is False else "unknown")
    return "email" if value.get("otp") is True else ("none" if value.get("otp") is False else "unknown")


def state(record):
    lifetime = record.get("account_lifetime")
    if not isinstance(lifetime, dict):
        return "unknown"
    return "expired" if lifetime.get("expired") is True else ("active" if lifetime.get("expired") is False else "unknown")


def source(record, contract):
    if "domain" not in record or record.get("domain") is None:
        return "local"
    domain = record.get("domain")
    if contract.startswith("gen6"):
        return "domainProxy" if isinstance(domain, dict) and name(domain.get("name")) else "unknown"
    return "domainProxy" if isinstance(domain, str) and name(domain) else "unknown"


def identity(record, contract, account_name):
    vendor_uuid = name(record.get("uuid"))
    if vendor_uuid:
        return ("uuid", vendor_uuid)
    domain = record.get("domain")
    if domain is None:
        return ("local", account_name)
    domain_name = name(domain.get("name")) if contract.startswith("gen6") and isinstance(domain, dict) else (name(domain) if not contract.startswith("gen6") else None)
    return ("domain", domain_name, account_name) if domain_name else ("unknown", account_name)


def references(record, field):
    if field not in record or record.get(field) is None:
        return [], False
    values = record.get(field)
    if not isinstance(values, list):
        return [], True
    names = []
    invalid = False
    for value in values:
        reference = name(value.get("name")) if isinstance(value, dict) else None
        if reference is None:
            invalid = True
        elif reference not in names:
            names.append(reference)
    return names, invalid


def validate(data):
    errors = []
    if not isinstance(data, dict):
        return None, ["collector_envelope_not_object"]
    source_data, collection, counts, evidence = data.get("source"), data.get("collection"), data.get("counts"), data.get("evidence")
    if not isinstance(source_data, dict):
        errors.append("source_missing"); source_data = {}
    if not isinstance(collection, dict):
        errors.append("collection_missing"); collection = {}
    if not isinstance(counts, dict):
        errors.append("counts_missing"); counts = {}
    if not isinstance(evidence, dict):
        errors.append("evidence_missing"); evidence = {}
    contract = source_data.get("apiContract")
    if source_data.get("vendor") != "SonicWall" or source_data.get("product") != "SonicOS": errors.append("source_not_sonicos")
    if contract not in SUPPORTED_CONTRACTS: errors.append("api_contract_unrecognized")
    if source_data.get("authenticationMode") not in SUPPORTED_AUTHENTICATION_MODES: errors.append("authentication_mode_unrecognized")
    if not isinstance(source_data.get("firmwareVersion"), str): errors.append("firmware_version_invalid")
    collection_errors = collection.get("errors")
    ready = collection.get("requiredEndpointsSucceeded") is True and collection.get("capabilityProfileRecognized") is True and collection.get("allExpectedResponseSectionsPresent") is True and isinstance(collection_errors, list) and not collection_errors
    if not ready:
        return {"collectionErrors": collection_errors if isinstance(collection_errors, list) and collection_errors else ["required_collection_incomplete"]}, errors
    users_body, groups_body = evidence.get("localUsers"), evidence.get("localGroups")
    users = at(users_body, ("user", "local", "user"))
    if contract == "gen6-combined":
        groups = at(users_body, ("user", "local", "group"))
        if groups_body is not None: errors.append("combined_contract_has_split_groups")
    else:
        groups = at(groups_body, ("user", "local", "group"))
        if at(users_body, ("user", "local", "group")) is not None: errors.append("split_contract_has_combined_groups")
    admin = at(evidence.get("administrationGlobal"), ("administration", "administration", "admin"))
    if not isinstance(users, list): errors.append("local_users_shape_unrecognized"); users = []
    if not isinstance(groups, list): errors.append("local_groups_shape_unrecognized"); groups = []
    if not isinstance(admin, dict): errors.append("built_in_administrator_shape_unrecognized")
    raw_users, raw_groups = counts.get("rawUserEntries"), counts.get("rawGroupEntries")
    if not isinstance(raw_users, int) or isinstance(raw_users, bool) or raw_users != len(users): errors.append("raw_user_count_mismatch")
    if not isinstance(raw_groups, int) or isinstance(raw_groups, bool) or raw_groups != len(groups): errors.append("raw_group_count_mismatch")
    return {"contract": contract, "users": users, "groups": groups, "collectionErrors": []}, errors


def parse(validated):
    users, groups, errors = {}, {}, []
    contract = validated["contract"]
    for record in validated["users"]:
        if not isinstance(record, dict): errors.append("local_user_record_not_object"); continue
        account_name = name(record.get("name"))
        if account_name is None: errors.append("local_user_identity_missing"); continue
        key = identity(record, contract, account_name)
        if key in users: errors.append("duplicate_local_user_identity"); continue
        member_of, invalid = references(record, "member_of")
        email = record.get("email_address")
        users[key] = {"name": account_name, "source": source(record, contract), "state": state(record),
                      "otp": otp(record), "hasEmail": isinstance(email, str) and bool(email.strip()),
                      "memberOf": member_of, "membershipUnknown": invalid}
    for record in validated["groups"]:
        if not isinstance(record, dict): errors.append("local_group_record_not_object"); continue
        group_name = name(record.get("name"))
        if group_name is None: errors.append("local_group_identity_missing"); continue
        if group_name in groups: errors.append("duplicate_local_group_identity"); continue
        members, invalid = references(record, "member")
        groups[group_name] = {"otp": otp(record), "members": members, "invalid": invalid}
    return users, groups, errors


def graph(users, groups):
    direct, parents, by_name, errors = {}, {}, {}, []
    for key in users:
        direct[key] = []
        account_name = users[key]["name"]
        if account_name not in by_name: by_name[account_name] = []
        by_name[account_name].append(key)
    for group_name in groups: parents[group_name] = []
    for key in users:
        for group_name in users[key]["memberOf"]:
            if group_name not in groups: users[key]["membershipUnknown"] = True
            elif group_name not in direct[key]: direct[key].append(group_name)
    for parent in groups:
        if groups[parent]["invalid"]: errors.append("group_membership_unresolved")
        for member in groups[parent]["members"]:
            matches, is_group = by_name.get(member, []), member in groups
            if len(matches) > 1 or ((len(matches) == 1) == is_group): errors.append("group_membership_unresolved")
            elif len(matches) == 1:
                if parent not in direct[matches[0]]: direct[matches[0]].append(parent)
            elif parent not in parents[member]: parents[member].append(parent)
    return direct, parents, errors


def resolved_groups(key, users, groups, direct, parents):
    resolved, stack, unknown = [], [], users[key]["membershipUnknown"]
    for group_name in direct[key]: stack.append((group_name, []))
    while stack:
        group_name, path = stack.pop()
        if group_name in path: unknown = True; continue
        if group_name in resolved: continue
        resolved.append(group_name)
        if groups[group_name]["otp"] == "unknown": unknown = True
        for parent in parents[group_name]: stack.append((parent, path + [group_name]))
    return resolved, unknown


def stronger(first, second):
    ranks = {"unknown": -1, "none": 0, "email": 1, "totp": 2}
    return first if ranks[first] >= ranks[second] else second


def evaluate(users, groups, errors):
    counts = empty_counts()
    direct, parents, graph_errors = graph(users, groups)
    errors.extend(graph_errors)
    for key in users:
        user = users[key]
        if user["source"] == "domainProxy": counts["excludedDomainProxies"] = counts["excludedDomainProxies"] + 1; continue
        if user["source"] == "unknown": errors.append("account_source_unresolved"); counts["unknownAccounts"] = counts["unknownAccounts"] + 1; continue
        memberships, membership_unknown = resolved_groups(key, users, groups, direct, parents)
        is_admin, is_ssl_vpn, inherited = False, False, "none"
        for group_name in memberships:
            if group_name in ADMIN_GROUPS: is_admin = True
            if group_name == SSL_VPN_GROUP: is_ssl_vpn = True
            inherited = stronger(inherited, groups[group_name]["otp"])
        if is_ssl_vpn: counts["sslVpnAccounts"] = counts["sslVpnAccounts"] + 1
        if user["state"] == "expired": counts["expiredAccounts"] = counts["expiredAccounts"] + 1; continue
        if user["state"] == "unknown": errors.append("account_state_unresolved"); counts["unknownAccounts"] = counts["unknownAccounts"] + 1; continue
        if is_admin:
            counts["administratorAccountsExcluded"] = counts["administratorAccountsExcluded"] + 1
            if membership_unknown: errors.append("administrator_membership_unresolved"); counts["unknownAccounts"] = counts["unknownAccounts"] + 1
            continue
        counts["scoredLocalAccounts"] = counts["scoredLocalAccounts"] + 1
        if membership_unknown or user["otp"] == "unknown" or inherited == "unknown":
            errors.append("scored_account_evidence_unresolved"); counts["unknownAccounts"] = counts["unknownAccounts"] + 1; continue
        effective = stronger(user["otp"], inherited)
        if effective == "totp" or (effective == "email" and user["hasEmail"]): counts["compliantLocalAccounts"] = counts["compliantLocalAccounts"] + 1
        else: counts["noncompliantLocalAccounts"] = counts["noncompliantLocalAccounts"] + 1
    unique = []
    for error in errors:
        if error not in unique: unique.append(error)
    return counts, unique


def safe_collection(errors):
    allowed = ("invalid_settings", "authentication_failed", "local_users_failed", "local_groups_failed", "administration_global_failed", "logout_failed", "required_collection_incomplete")
    return [str(error) if str(error) in allowed else "collector_error" for error in errors]


def transform(input):
    try:
        if isinstance(input, str): input = json.loads(input)
        elif isinstance(input, bytes): input = json.loads(input.decode("utf-8"))
        data, upstream, enriched = unpack(input)
        if enriched and (not isinstance(upstream, dict) or upstream.get("status") != "passed" or not isinstance(upstream.get("errors"), list) or upstream.get("errors")):
            return response(False, validation_status="failed", validation_errors=["upstream_schema_validation_failed"], transformation_errors=["input_validation_failed"], fail_reasons=["SonicOS local-account MFA evidence could not be validated"])
        validated, envelope_errors = validate(data)
        if validated is not None and validated.get("collectionErrors"):
            return response(False, validation_status="unknown", collection_errors=safe_collection(validated["collectionErrors"]), fail_reasons=["Required SonicOS account MFA evidence was not collected"], recommendations=["Verify the SonicOS integration and re-run collection"])
        if envelope_errors:
            return response(False, validation_status="failed", validation_errors=envelope_errors, transformation_errors=["collector_contract_invalid"], fail_reasons=["SonicOS account MFA evidence did not match a recognized contract"])
        users, groups, parse_errors = parse(validated)
        counts, errors = evaluate(users, groups, parse_errors)
        if errors:
            return response(False, counts, "failed", errors, fail_reasons=["SonicOS local-account MFA evidence was indeterminate"], recommendations=["Resolve incomplete OTP, account-state, or group-membership evidence and re-check"])
        passed = counts["noncompliantLocalAccounts"] == 0 and counts["compliantLocalAccounts"] == counts["scoredLocalAccounts"]
        if passed:
            return response(True, counts, pass_reasons=["Every scored ordinary local account has configured TOTP or email OTP with a configured email address"])
        return response(False, counts, fail_reasons=[str(counts["noncompliantLocalAccounts"]) + " ordinary local account(s) lack an approved configured MFA method"], recommendations=["Configure TOTP, or email OTP with a nonblank email address, for every ordinary local account"])
    except Exception:
        return response(False, validation_status="failed", validation_errors=["transformation_exception"], transformation_errors=["transformation_failed_safely"], fail_reasons=["SonicOS local-account MFA evaluation could not be completed"])
