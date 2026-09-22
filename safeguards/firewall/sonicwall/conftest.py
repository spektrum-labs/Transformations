import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).parent
FIXTURES = ROOT / "fixtures"


def load_module(filename, directory=None):
    path = (directory or ROOT) / filename
    spec = importlib.util.spec_from_file_location("sonicwall_" + path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def otp(method):
    if method == "totp":
        return {"totp": True}
    if method == "email":
        return {"otp": True}
    if method == "unknown":
        return None
    return {"otp": False}


def user(name, method="none", groups=None, expired=False, domain=None,
         vendor_uuid=None, email_address=None, include_state=True):
    record = {"name": name, "one_time_password": otp(method)}
    if include_state:
        record["account_lifetime"] = {"expired": expired}
    if groups is not None:
        record["member_of"] = [{"name": group} for group in groups]
    if domain is not None:
        record["domain"] = domain
    if vendor_uuid is not None:
        record["uuid"] = vendor_uuid
    if email_address is not None:
        record["email_address"] = email_address
    return record


def group(name, method="none", members=None):
    record = {"name": name, "one_time_password": otp(method)}
    if members is not None:
        record["member"] = [{"name": member} for member in members]
    return record


def envelope(users=None, groups=None, admin=None, contract="gen7-split"):
    users = users or []
    groups = groups or []
    admin = admin or {"name": "built-in-administrator", "one_time_password": {"totp": True}}
    local_users = {"user": {"local": {"user": users}}}
    evidence = {"localUsers": local_users, "administrationGlobal": {"administration": {"administration": {"admin": admin}}}}
    if contract == "gen6-combined":
        local_users["user"]["local"]["group"] = groups
    else:
        evidence["localGroups"] = {"user": {"local": {"group": groups}}}
    return {
        "source": {"vendor": "SonicWall", "product": "SonicOS",
                   "firmwareVersion": "6.5.4.8" if contract.startswith("gen6") else "7.x",
                   "apiContract": contract, "authenticationMode": "basicSession"},
        "collection": {"requiredEndpointsSucceeded": True,
                       "capabilityProfileRecognized": True,
                       "allExpectedResponseSectionsPresent": True, "errors": []},
        "counts": {"rawUserEntries": len(users), "rawGroupEntries": len(groups)},
        "evidence": evidence,
    }


def fixture_envelope(contract):
    admin = json.loads((FIXTURES / (contract + "-administration-global.json")).read_text())
    if contract == "gen6-combined":
        combined = json.loads((FIXTURES / "gen6-combined-user-local.json").read_text())
        users = combined["user"]["local"]["user"]
        groups = combined["user"]["local"]["group"]
        evidence = {"localUsers": combined, "administrationGlobal": admin}
    else:
        users_body = json.loads((FIXTURES / (contract + "-users.json")).read_text())
        groups_body = json.loads((FIXTURES / (contract + "-groups.json")).read_text())
        users = users_body["user"]["local"]["user"]
        groups = groups_body["user"]["local"]["group"]
        evidence = {"localUsers": users_body, "localGroups": groups_body, "administrationGlobal": admin}
    return {
        "source": {"vendor": "SonicWall", "product": "SonicOS",
                   "firmwareVersion": "6.5.4.8" if contract.startswith("gen6") else "7.x",
                   "apiContract": contract, "authenticationMode": "basicSession"},
        "collection": {"requiredEndpointsSucceeded": True,
                       "capabilityProfileRecognized": True,
                       "allExpectedResponseSectionsPresent": True, "errors": []},
        "counts": {"rawUserEntries": len(users), "rawGroupEntries": len(groups)},
        "evidence": evidence,
    }
