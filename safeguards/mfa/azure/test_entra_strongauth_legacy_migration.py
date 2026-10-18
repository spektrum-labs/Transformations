"""entra_strongauth_methods.py, legacy migration states (4 Oct 2026).

With neither phishing-resistant method enabled in the authentication methods policy, preMigration and
migrationInProgress now read False: Microsoft documents that FIDO2 security keys, Temporary Access Pass and
certificate-based authentication "aren't available in the legacy policies", so the legacy MFA/SSPR policies
cannot enable one. Every other path is unchanged; this file pins that, plain and under RestrictedPython.
"""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SOURCE = (HERE / "entra_strongauth_methods.py").read_text()


def load():
    spec = importlib.util.spec_from_file_location("entra_strongauth_methods_legacy", HERE / "entra_strongauth_methods.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M = load()
CTX = "https://graph.microsoft.com/v1.0/$metadata#authenticationMethodsPolicy"
DUO = {"@odata.type": "#microsoft.graph.externalAuthenticationMethodConfiguration", "id": "ext-1",
       "displayName": "External MFA", "state": "enabled"}


def body(enabled, migration, extra=()):
    ids = ["Fido2", "X509Certificate", "MicrosoftAuthenticator", "Sms", "Voice", "Email", "TemporaryAccessPass"]
    configs = [{"id": i, "state": "enabled" if i in enabled else "disabled"} for i in ids] + [copy.deepcopy(e) for e in extra]
    return {"@odata.context": CTX, "policyMigrationState": migration, "authenticationMethodConfigurations": configs}


def run(b):
    out = M.transform(copy.deepcopy(b))
    out["additionalInfo"]["metadata"].pop("evaluatedAt", None)
    return out


@pytest.mark.parametrize("migration", ["preMigration", "migrationInProgress", "PREMIGRATION", "MigrationInProgress"])
def test_no_strong_method_in_a_legacy_state_fails_with_the_microsoft_reason(migration):
    out = run(body(["MicrosoftAuthenticator", "Sms"], migration))
    assert out["transformedResponse"]["isStrongAuthRequired"] is False
    assert out["transformedResponse"]["policyMigrationState"] == migration
    reason = out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert "aren't available in the legacy MFA and SSPR policies" in reason
    assert "Temporary Access Pass" in reason and "certificate-based authentication" in reason
    assert "MicrosoftAuthenticator, Sms" in reason
    assert out["additionalInfo"]["dataCollection"] == {"status": "success", "errors": []}


def test_no_method_enabled_at_all_in_a_legacy_state_fails_without_a_phishable_list():
    out = run(body([], "preMigration"))
    assert out["transformedResponse"]["isStrongAuthRequired"] is False
    assert "phishable" not in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_temporary_access_pass_alone_is_not_strong():
    assert run(body(["TemporaryAccessPass"], "migrationInProgress"))["transformedResponse"]["isStrongAuthRequired"] is False


@pytest.mark.parametrize("migration", ["preMigration", "migrationInProgress", "migrationComplete", None])
def test_strong_methods_pass_in_every_state(migration):
    for strong in (["Fido2"], ["X509Certificate"]):
        assert run(body(strong, migration))["transformedResponse"]["isStrongAuthRequired"] is True


def test_external_method_during_migration_keeps_the_old_not_evaluated_reason():
    out = run(body(["Sms"], "preMigration", extra=[DUO]))
    assert out["transformedResponse"]["isStrongAuthRequired"] is None
    assert out["additionalInfo"]["dataCollection"]["errors"] == [
        "No strong method is enabled in the authentication methods policy, but its migration state is "
        "preMigration: the legacy MFA and SSPR policies still apply and cannot be read here"]


@pytest.mark.parametrize("bad", [None, {}, "", [], {"error": {"code": "Authorization_RequestDenied"}},
                                 {"vendorErrorAsResponse": {"status": 403, "body": {"error": {}}}},
                                 {"policyMigrationState": "preMigration"},
                                 {"policyMigrationState": "preMigration", "authenticationMethodConfigurations": []},
                                 {"policyMigrationState": "preMigration", "authenticationMethodConfigurations": ["x"]}])
def test_missing_refused_or_unrecognised_input_is_never_a_verdict(bad):
    out = M.transform(copy.deepcopy(bad))
    assert out["transformedResponse"]["isStrongAuthRequired"] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_restricted_python_compiles_and_agrees():
    rp = pytest.importorskip("RestrictedPython")
    from RestrictedPython import compile_restricted, safe_globals, limited_builtins, utility_builtins
    from RestrictedPython.Eval import default_guarded_getitem, default_guarded_getiter
    from RestrictedPython.Guards import guarded_iter_unpack_sequence, guarded_unpack_sequence, safer_getattr
    import builtins as _real
    code = compile_restricted(SOURCE, "<entra_strongauth_methods>", "exec")
    assert "getattr(" not in SOURCE and "re.compile" not in SOURCE and "strptime" not in SOURCE
    glb = dict(safe_globals)
    builtins = dict(safe_globals["__builtins__"])
    builtins.update(limited_builtins)
    builtins.update(utility_builtins)
    allowed = {"json", "datetime", "warnings"}

    def guarded_import(name, *args, **kwargs):
        if name not in allowed:
            raise ImportError(name)
        return _real.__import__(name, *args, **kwargs)

    builtins.update(__import__=guarded_import,
                    isinstance=isinstance, list=list, dict=dict, str=str, any=any, bytes=bytes,
                    ValueError=ValueError, Exception=Exception)
    glb["__builtins__"] = builtins
    glb.update(_getitem_=default_guarded_getitem, _getiter_=default_guarded_getiter,
               _iter_unpack_sequence_=guarded_iter_unpack_sequence, _unpack_sequence_=guarded_unpack_sequence,
               _getattr_=safer_getattr,
               _write_=lambda x: x, __name__="sandboxed", __metaclass__=type)
    exec(code, glb)
    for b in (body(["Sms"], "preMigration"), body(["Fido2"], "preMigration"), body(["Sms"], "migrationComplete"),
              body(["Sms"], "migrationInProgress", extra=[DUO]), None):
        sandboxed = glb["transform"](copy.deepcopy(b))
        plain = M.transform(copy.deepcopy(b))
        assert sandboxed["transformedResponse"] == plain["transformedResponse"]
        assert sandboxed["additionalInfo"]["evaluation"] == plain["additionalInfo"]["evaluation"]
