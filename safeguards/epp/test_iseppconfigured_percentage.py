"""isEPPConfigured is a whole-number percentage on every Endpoint Security vendor (FF-04).

protected = endpoints with the vendor's protection installed (computers and servers); configured = those
enforcing and healthy by the vendor's own signal. floor(100 * configured / protected). Staleness is not held
against an endpoint, except on Sophos and NinjaOne, which judge only endpoints seen within 15 days of the newest
check-in (endpoint rules 2026-09-29, see test_endpoint_rules.py). No protected endpoint, or a truncated list, is not evaluated: dataCollection error and no
value. Synthetic bodies in each vendor's documented shape; no customer data."""
import copy
import importlib.util
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

SAFEGUARDS = pathlib.Path(__file__).resolve().parent.parent


def load(rel):
    spec = importlib.util.spec_from_file_location("ff04_" + rel.replace("/", "_").replace(".", "_"), SAFEGUARDS / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(rel, body):
    out = load(rel).transform(copy.deepcopy(body))
    return out["transformedResponse"].get("isEPPConfigured"), out["additionalInfo"]["dataCollection"]["status"]


SOPHOS = "epp/sophos/iseppconfigured.py"
S1 = "epp/sentinelone/isEPPConfigured.py"
NINJA = "epp/ninjaone-endpoint-management/isEPPConfigured.py"
THREATDOWN = "epp/threatdown/iseppmisconfigured.py"
FALCON = "epp/crowdstrike-falcon/isEPPConfiguredFromHosts.py"
MDE = "7BC425FA-0638-4BF1-8194-19E7E4F2F43C/microsoft_endpoint_iseppconfigured.py"


RECENT = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


def sophos_endpoint(kind, healthy=True, last_seen=RECENT):
    return {"type": kind, "lastSeenAt": last_seen, "tamperProtectionEnabled": True,
            "assignedProducts": [{"code": "endpointProtection", "status": "installed"}],
            "health": {"overall": "good" if healthy else "bad",
                       "services": {"status": "good", "serviceDetails": [{"name": "Sophos MCS Agent", "status": "running"}]}}}


def sophos_body():
    # 2 computers (1 unhealthy) and 8 servers, all seen yesterday (Sophos applies the 15-day window): 9 of 10 = 90.
    return {"items": [sophos_endpoint("computer"), sophos_endpoint("computer", healthy=False)]
            + [sophos_endpoint("server") for _ in range(8)], "pages": {"nextKey": None}}


def s1_body(n=8):
    agents = [{"computerName": f"h{i}", "mitigationMode": "protect", "activeProtection": ["edr"]} for i in range(n)]
    return {"data": agents, "pagination": {"totalItems": n, "nextCursor": None}}


def s1_new_format(body):
    return {"data": body, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def threatdown_policy(self_protection=True):
    return {"name": "p", "contents": {"status": "ok", "policy": {"protect_service": True}, "packages": [
        {"product_name": "Endpoint Protection", "enabled": True,
         "policy": {"rtp_settings": {"malware": {"enabled": True}}, "self_protection": self_protection,
                    "protection_update_enabled": True}}]}}


def falcon_host(i, applied=True, rfm="no", product="Workstation"):
    return {"device_id": f"d{i}", "platform_name": "Windows", "product_type_desc": product, "status": "normal",
            "reduced_functionality_mode": rfm, "last_seen": "2025-01-01T00:00:00Z",
            "device_policies": {"prevention": {"policy_type": "prevention", "policy_id": "p1", "applied": applied}}}


def mde_machine(health, onboarded=True):
    return {"onboardingStatus": "Onboarded" if onboarded else "CanBeOnboarded", "healthStatus": health,
            "isExcluded": False, "lastSeen": "2026-01-01T00:00:00Z", "osPlatform": "WindowsServer2022"}


MEASURED = [
    # Servers count, and staleness is not held against an endpoint: 9 of 10.
    (SOPHOS, sophos_body(), 90),
    (S1, s1_new_format(s1_body()), 100),
    (NINJA, [{"id": i, "policyId": 7 if i < 18 else None} for i in range(21)], 85),
    (THREATDOWN, {"policies": [threatdown_policy(), threatdown_policy(), threatdown_policy(False)]}, 66),
    (FALCON, {"resources": [falcon_host(i) for i in range(9)] + [falcon_host(9, rfm="yes")],
              "meta": {"pagination": {"total": 10}}}, 90),
    # "Inactive" (not reported for 7+ days) is counted; a sensor fault is not: 9 of 10.
    (MDE, {"value": [mde_machine("Active")] * 7 + [mde_machine("Inactive")] * 2 + [mde_machine("NoSensorData")]
           + [mde_machine("Active", onboarded=False)]}, 90),
]


@pytest.mark.parametrize("rel,body,expected", MEASURED)
def test_whole_number_percentage(rel, body, expected):
    value, status = run(rel, body)
    assert status == "success"
    assert value == expected and type(value) is int


def test_percentage_is_floored_not_rounded():
    # 89.9 must not become 90: 899 of 1000 SentinelOne agents enforce protection.
    body = s1_body(1000)
    for agent in body["data"][:101]:
        agent["mitigationMode"] = "detect"
    assert run(S1, s1_new_format(body)) == (89, "success")


FLIPS = [
    (SOPHOS, lambda b: b["items"][2]["health"].update(overall="bad"), (80, "success")),
    (S1, lambda b: b["data"]["data"][0].update(mitigationMode="detect"), (87, "success")),
    (FALCON, lambda b: b["resources"][0]["device_policies"]["prevention"].update(applied=False), (80, "success")),
    (MDE, lambda b: b["value"].__setitem__(0, mde_machine("ImpairedCommunication")), (80, "success")),
]


@pytest.mark.parametrize("rel,flip,expected", FLIPS)
def test_flip_moves_the_number(rel, flip, expected):
    body = copy.deepcopy(next(b for r, b, _ in MEASURED if r == rel))
    flip(body)
    assert run(rel, body) == expected


NOT_EVALUATED = [
    (SOPHOS, {"items": [], "pages": {}}),
    (SOPHOS, dict(sophos_body(), pages={"truncated": True, "scannedCount": 10})),
    (S1, s1_new_format({"data": [], "pagination": {"totalItems": 0}})),
    (S1, s1_new_format(dict(s1_body(), pagination={"totalItems": 1500, "nextCursor": None}))),
    (S1, s1_new_format(dict(s1_body(), pagination={"totalItems": 8, "nextCursor": "abc"}))),
    (NINJA, []),
    (THREATDOWN, {"policies": []}),
    (FALCON, {"resources": [], "meta": {"pagination": {"total": 0}}}),
    (FALCON, {"resources": [falcon_host(i) for i in range(10)], "meta": {"pagination": {"total": 5000}}}),
    (FALCON, {"resources": [falcon_host(0, product="Mobile")]}),
    (FALCON, {"resources": [{"name": "policy", "enabled": True}]}),
    (MDE, {"value": []}),
    (MDE, {"value": [mde_machine("Active", onboarded=False)]}),
    (MDE, {"value": [mde_machine("Active")], "@odata.nextLink": "https://api.securitycenter.microsoft.com/api/machines?$skiptoken=x"}),
]


@pytest.mark.parametrize("rel,body", NOT_EVALUATED)
def test_zero_or_truncated_is_not_evaluated(rel, body):
    assert run(rel, body) == (None, "error")


@pytest.mark.parametrize("rel", [SOPHOS, S1, NINJA, THREATDOWN, FALCON, MDE])
def test_error_body_never_passes(rel):
    value, status = run(rel, {"error": True, "message": "HTTP 403: Forbidden"})
    assert status == "error" or value is None or (value is not True and isinstance(value, int) and value < 90)
