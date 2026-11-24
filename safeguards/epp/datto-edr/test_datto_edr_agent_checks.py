"""Datto EDR agent checks: protection judged from eppData (not the online flag), a 15-day window on
the newest heartbeat, stale as its own number, None on anything that is not a complete agent read."""
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
KEYS = ["isEPPEnabled", "offlineSensorCount", "staleSensorCount"]
NEWEST = "2026-09-30T12:00:00.000Z"


def load(name):
    spec = importlib.util.spec_from_file_location("datto_edr_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def agent(i, active=True, authorized=True, datto_av=True, defender=False, beat=NEWEST, kind="installed",
          uninstall=False):
    return {"id": "agent-" + str(i), "hostname": "host-" + str(i), "type": kind, "active": active,
            "authorized": authorized, "markedForUninstall": uninstall, "heartbeat": beat,
            "dattoAvEnabled": datto_av,
            "eppData": {"dattoav": {"enabled": datto_av, "eppType": "Datto AV"},
                        "defender": {"enabled": defender, "eppType": "Defender"}}}


def envelope(items):
    return {"data": items, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def out(key, payload):
    return load(key)(payload)["transformedResponse"]


FLEET = [
    agent(1),
    agent(2, active=False),                                   # offline right now, still protected
    agent(3, datto_av=False, defender=True),                  # Defender instead of Datto AV
    agent(4, beat="2026-09-20T08:00:00.000Z"),                # 10 days before newest: judged
    agent(5, active=False, beat="2026-08-01T00:00:00.000Z"),  # stale
]


def test_offline_agents_are_not_counted_as_unprotected():
    result = out("isEPPEnabled", envelope(FLEET))
    assert result["isEPPEnabled"] is True
    assert result["judgedAgents"] == 4
    assert result["staleSensorCount"] == 1


def test_agent_with_no_engine_fails_and_is_named():
    fleet = FLEET + [agent(6, datto_av=False)]
    full = load("isEPPEnabled")(envelope(fleet))
    assert full["transformedResponse"]["isEPPEnabled"] is False
    assert full["transformedResponse"]["unprotectedAgents"] == 1
    assert "host-6" in full["additionalInfo"]["evaluation"]["failReasons"][0]


def test_unauthorized_agent_fails():
    result = out("isEPPEnabled", envelope(FLEET + [agent(7, authorized=False)]))
    assert result["isEPPEnabled"] is False


def test_stale_agent_without_engine_is_not_judged():
    result = out("isEPPEnabled", envelope(FLEET + [agent(8, datto_av=False, beat="2026-07-01T00:00:00.000Z")]))
    assert result["isEPPEnabled"] is True
    assert result["staleSensorCount"] == 2


def test_offline_counts_only_judged_agents():
    assert out("offlineSensorCount", envelope(FLEET))["offlineSensorCount"] == 1


def test_stale_count_and_zero_case():
    assert out("staleSensorCount", envelope(FLEET))["staleSensorCount"] == 1
    assert out("staleSensorCount", envelope([agent(1), agent(2)]))["staleSensorCount"] == 0


def test_uninstalled_agents_are_ignored():
    fleet = [agent(1), agent(2, datto_av=False, uninstall=True), agent(3, datto_av=False, kind="pending")]
    assert out("isEPPEnabled", envelope(fleet))["isEPPEnabled"] is True


def test_bare_list_input_is_read():
    assert out("isEPPEnabled", FLEET)["isEPPEnabled"] is True


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("payload", [
    envelope([]),
    envelope({"error": {"message": "Authorization Required"}}),
    envelope({"unexpected": True}),
    envelope([agent(i) for i in range(1000)]),
    "not json",
])
def test_not_a_complete_read_is_not_evaluated(key, payload):
    full = load(key)(payload)
    assert full["transformedResponse"][key] is None
    assert full["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("key", ["isEPPEnabled", "offlineSensorCount"])
def test_all_agents_stale_is_not_evaluated(key):
    fleet = [agent(1, beat="2026-09-30T12:00:00.000Z"), agent(2, beat="2026-09-30T12:00:00.000Z")]
    fleet[0]["heartbeat"] = None
    fleet[1]["heartbeat"] = None
    assert out(key, envelope(fleet))[key] is None
