"""Microsoft Azure Payment HSM (Encryption): confirmedLicensePurchased.

Payment HSMs are Microsoft.HardwareSecurityModules/dedicatedHSMs resources with a payShield10K_* SKU
(https://learn.microsoft.com/en-us/azure/payment-hsm/quickstart-cli).
"""
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("phsm_clp", Path(__file__).with_name("confirmedLicensePurchased.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def hsm(i, sku="payShield10K_LMK1_CPS60", state="Succeeded"):
    return {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.HardwareSecurityModules/dedicatedHSMs/h%d" % i,
            "name": "h%d" % i, "type": "Microsoft.HardwareSecurityModules/dedicatedHSMs", "sku": {"name": sku},
            "properties": {"provisioningState": state, "stampId": "stamp1"}}


def run(payload):
    out = m.transform(payload)
    return out["transformedResponse"]["confirmedLicensePurchased"], out["additionalInfo"]["dataCollection"]["status"]


def test_provisioned_payment_hsm():
    body = {"value": [hsm(1), hsm(2, state="Provisioning")]}
    assert run(body) == (True, "success")
    out = m.transform(body)["transformedResponse"]
    assert (out["paymentHsmCount"], out["provisionedPaymentHsmCount"]) == (2, 1)


def test_only_safenet_or_unprovisioned_is_false():
    assert run({"value": [hsm(1, sku="SafeNet Luna Network HSM A790")]}) == (False, "success")
    assert run({"value": [hsm(1, state="Failed")]}) == (False, "success")
    assert run({"value": []}) == (False, "success")


NO_EVIDENCE = {
    "null": None,
    "empty_dict": {},
    "empty_string": "",
    "arm_403": {"error": {"code": "AuthorizationFailed", "message": "no authorization"}},
    "auth_401": {"statusCode": 401, "error": "Unauthorized"},
    "unrelated": {"hello": "world"},
    "paged": {"value": [hsm(1)], "nextLink": "https://management.azure.com/next"},
}


@pytest.mark.parametrize("name", sorted(NO_EVIDENCE))
def test_no_evidence_is_unevaluated(name):
    assert run(NO_EVIDENCE[name]) == (None, "error")
