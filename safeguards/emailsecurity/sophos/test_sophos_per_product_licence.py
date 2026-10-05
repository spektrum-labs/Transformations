"""Sophos per-product licence transforms (Email and Firewall), 5 Oct 2026. Synthetic data only (public repo)."""
import builtins as real_builtins
import copy
import importlib.util
from datetime import datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
EMAIL = ROOT / "emailsecurity" / "sophos" / "confirmedlicensepurchased.py"
FIREWALL = ROOT / "firewall" / "sophos" / "confirmedlicensepurchased.py"
KEY = "confirmedLicensePurchased"
TODAY = datetime.utcnow().date()
FUTURE = (TODAY + timedelta(days=200)).isoformat() + "T00:00:00Z"
PAST = (TODAY - timedelta(days=30)).isoformat() + "T00:00:00Z"
START = (TODAY - timedelta(days=300)).isoformat() + "T00:00:00Z"


def load(path):
    spec = importlib.util.spec_from_file_location(path.stem + path.parent.parent.name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


E, F = load(EMAIL), load(FIREWALL)


def lic(code, name, end=FUTURE, kind="term", perpetual=False, start=START):
    return {"product": {"code": code, "name": name}, "type": kind, "perpetual": perpetual, "startDate": start,
            "endDate": end, "quantity": 10, "unlimited": False}


def value(module, body):
    return module.transform(copy.deepcopy(body))["transformedResponse"][KEY]


# --- Email ----------------------------------------------------------------------------------------------------------

def test_email_current_licence_passes():
    assert value(E, {"licenses": [lic("CPHISH", "Central Phish Threat"), lic("CEMA", "Sophos Email")]}) is True


@pytest.mark.parametrize("items", [
    [lic("CPHISH", "Central Phish Threat"), lic("NDR", "Network Detection")],
    [lic("CEMA", "Sophos Email", end=PAST)],
    [lic("CEMA", "Sophos Email", kind="trial")],
    [lic("CEMA", "Sophos Email", start=FUTURE)],
])
def test_email_no_current_licence_fails(items):
    assert value(E, {"licenses": items}) is False


@pytest.mark.parametrize("body", [{}, {"licenses": []}, {"error": "x"}, {"licenses": "x"}, None, "not json",
                                  {"vendorErrorAsResponse": {"status": 403}},
                                  {"licenses": [lic("CEMA", "Sophos Email", end="")]}])
def test_email_unreadable_is_not_evaluated(body):
    try:
        out = E.transform(copy.deepcopy(body))
    except Exception:
        pytest.fail("transform raised")
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_email_perpetual_and_wrappers():
    assert value(E, {"apiResponse": {"licenses": [lic("CEMA", "Sophos Email", end="", perpetual=True)]}}) is True
    assert value(E, {"licenses": [lic("X1", "Sophos Email Advanced")]}) is True


# --- Firewall -------------------------------------------------------------------------------------------------------

def devices(*per_device, total=None):
    body = {"items": [{"serialNumber": "S%d" % i, "model": "XGS", "licenses": l} for i, l in enumerate(per_device)]}
    if total is not None:
        body["pages"] = {"items": total}
    return body


def test_firewall_every_device_licensed_passes():
    assert value(F, devices([lic("FWBASE", "Base Firewall", perpetual=True, end="")],
                            [lic("XPROT", "Xstream Protection")])) is True
    assert value(F, {"firewallLicenses": devices([lic("XPROT", "Xstream Protection")]),
                     "tenantLicenses": {"licenses": []}}) is True


def test_firewall_lapsed_device_fails():
    assert value(F, devices([lic("XPROT", "Xstream Protection")], [lic("XPROT", "Xstream Protection", end=PAST)])) is False
    assert value(F, devices([lic("XPROT", "Xstream Protection", kind="trial")])) is False


@pytest.mark.parametrize("body", [
    devices(), devices([]), devices([lic("XPROT", "Xstream", end="")]),
    devices([lic("XPROT", "Xstream Protection")], total=5),
    {"licenses": [lic("CEMA", "Sophos Email"), lic("NDR", "Network Detection")]},
    {"tenantLicenses": {"licenses": [lic("CEMA", "Sophos Email")]}, "firewallLicenses": {"error": "404"}},
    {}, {"error": "x"}, None,
])
def test_firewall_unreadable_or_tenant_only_is_never_a_fail(body):
    out = F.transform(copy.deepcopy(body))
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_firewall_tenant_list_with_firewall_product_passes():
    assert value(F, {"licenses": [lic("XSTREAM", "Xstream Protection")]}) is True


# --- RestrictedPython -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", [EMAIL, FIREWALL])
def test_restricted_python_agrees(path):
    pytest.importorskip("RestrictedPython")
    from RestrictedPython import compile_restricted, limited_builtins, safe_globals, utility_builtins
    from RestrictedPython.Eval import default_guarded_getitem, default_guarded_getiter
    from RestrictedPython.Guards import guarded_iter_unpack_sequence, guarded_unpack_sequence, safer_getattr
    source = path.read_text()
    for banned in ("getattr(", "re.compile", "strptime", "strftime"):
        assert banned not in source
    code = compile_restricted(source, "<sophos>", "exec")

    def guarded_import(name, *args, **kwargs):
        if name not in {"json", "datetime"}:
            raise ImportError(name)
        return real_builtins.__import__(name, *args, **kwargs)

    names = dict(safe_globals["__builtins__"])
    names.update(limited_builtins)
    names.update(utility_builtins)
    names.update(__import__=guarded_import, isinstance=isinstance, list=list, dict=dict, str=str, any=any,
                 all=all, bytes=bytes, set=set, sorted=sorted, len=len, int=int, bool=bool, Exception=Exception)
    glb = dict(safe_globals)
    glb.update(__builtins__=names, _getitem_=default_guarded_getitem, _getiter_=default_guarded_getiter,
               _iter_unpack_sequence_=guarded_iter_unpack_sequence, _unpack_sequence_=guarded_unpack_sequence,
               _getattr_=safer_getattr, _write_=lambda x: x, __name__="sandboxed", __metaclass__=type)
    exec(code, glb)
    plain = load(path)
    for body in ({"licenses": [lic("CEMA", "Sophos Email")]}, {"licenses": [lic("CEMA", "Sophos Email", end=PAST)]},
                 devices([lic("XPROT", "Xstream Protection")]), devices([lic("XPROT", "Xstream", end=PAST)]), {}):
        assert glb["transform"](copy.deepcopy(body))["transformedResponse"] == \
            plain.transform(copy.deepcopy(body))["transformedResponse"]
