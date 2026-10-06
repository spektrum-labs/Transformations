"""CrowdStrike Falcon requiredCoveragePercentage and isEPPConfigured (isEPPConfiguredFromHosts.py):
one staleness rule, three failure buckets, and a bounded pending state.

  * Coverage tests last_seen age against an explicit window and prints it in the pass reason; it used to
    claim "a recent last_seen" while testing only that the field was non-empty.
  * A host that has not reported within the window cannot show its configuration, so isEPPConfigured
    leaves it out and coverage counts it. The two checks used to do the reverse.
  * A failing host is reported as no policy assigned / assigned but not applied / reduced functionality,
    each with its own recommendation, instead of one "assign a policy" line.
  * A host assigned a policy within PENDING_WINDOW_HOURS that has not checked in since is pending: counted
    separately, never as configured, and a reassignment cannot restart the clock on an online host.

Synthetic hosts, plus the redacted real device list's last_seen spread shifted to the present."""
import copy
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("csstale_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


COV = load("requiredCoveragePercentage")
CFG = load("isEPPConfiguredFromHosts")
NOW = datetime.utcnow().replace(microsecond=0)
DEVICES = json.loads((HERE / "fixtures" / "xdr_devices_unpaged_real_2026-09-25.json").read_text())


def iso(when):
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def ago(**kw):
    return iso(NOW - timedelta(**kw))


def host(i, seen=None, policy_id="p1", applied=True, assigned=None, rfm="no", status="normal", product="Workstation"):
    prevention = {"policy_type": "prevention", "applied": applied}
    if policy_id:
        prevention["policy_id"] = policy_id
    if assigned:
        prevention["assigned_date"] = assigned
    return {"device_id": f"d{i}", "platform_name": "Windows", "product_type_desc": product, "status": status,
            "agent_version": "7.20.1", "reduced_functionality_mode": rfm,
            "last_seen": ago(minutes=5) if seen is None else seen,
            "device_policies": {"prevention": prevention}}


def body(hosts):
    return {"resources": hosts, "meta": {"pagination": {"total": len(hosts)}}}


def cov(hosts):
    out = COV.transform(body(hosts))
    return out["transformedResponse"], out["additionalInfo"]


def cfg(hosts):
    out = CFG.transform(body(hosts))
    return out["transformedResponse"], out["additionalInfo"]


# --- coverage: an explicit window, printed ---

def test_coverage_counts_a_host_unseen_for_46_days_as_not_reporting():
    result, info = cov([host(0), host(1, seen=ago(days=46))])
    assert result["requiredCoveragePercentage"] == 50.0
    assert result["notReportingDevices"] == 1
    assert info["dataCollection"]["status"] == "success"


def test_coverage_window_boundary_is_inclusive_at_15_days():
    assert COV.ACTIVE_WINDOW_DAYS == 15
    newest = ago(minutes=0)
    edge = iso(NOW - timedelta(days=15))
    past = iso(NOW - timedelta(days=15, seconds=1))
    result, _ = cov([host(0, seen=newest), host(1, seen=edge), host(2, seen=past)])
    assert (result["activeDevices"], result["notReportingDevices"]) == (2, 1)


def test_coverage_pass_reason_prints_the_window_and_no_longer_claims_unchecked_recency():
    _, info = cov([host(0), host(1, seen=ago(days=20))])
    reason = info["evaluation"]["passReasons"][0]
    assert "within 15 days of the newest check-in" in reason
    assert "recent last_seen" not in reason
    assert "1 not seen within 15 days" in info["evaluation"]["failReasons"][0]
    assert any("not checked in for more than 15 days" in r for r in info["evaluation"]["recommendations"])


def test_coverage_missing_or_unreadable_last_seen_is_not_reporting():
    for bad in (None, "", "yesterday", "2026-13-45T00:00:00Z", 12345):
        h = host(1)
        h["last_seen"] = bad
        result, _ = cov([host(0), h])
        assert result["requiredCoveragePercentage"] == 50.0, bad


def test_coverage_reads_nanosecond_timestamps():
    result, _ = cov([host(0, seen=ago(hours=1)[:-1] + ".123456789Z")])
    assert result["requiredCoveragePercentage"] == 100.0


def test_coverage_dark_fleet_uses_the_wall_clock_so_every_host_is_stale():
    result, info = cov([host(i, seen=ago(days=20)) for i in range(3)])
    assert result["requiredCoveragePercentage"] == 0
    assert result["notReportingDevices"] == 3
    assert info["dataCollection"]["status"] == "success"


def test_coverage_breaks_inactive_hosts_down_by_first_failed_test():
    _, info = cov([host(0), host(1, seen=ago(days=30), status="contained"), host(2, status="bogus"),
                   host(3, rfm="yes")])
    summary = info["transformation"]["inputSummary"]
    assert (summary["notReportingDevices"], summary["statusNotNormalDevices"],
            summary["reducedFunctionalityDevices"], summary["activeDevices"]) == (1, 1, 1, 1)


def test_coverage_contained_hosts_are_covered_and_called_out_separately():
    hosts = [host(0), host(1, status="contained"), host(2, status="containment_pending"),
             host(3, status="lift_containment_pending")]
    result, info = cov(hosts)
    assert result["requiredCoveragePercentage"] == 100.0
    assert result["containedDevices"] == 3
    assert any("3 of the covered devices are network-contained" in r for r in info["evaluation"]["passReasons"])


def test_coverage_contained_but_stale_or_rfm_is_still_not_covered():
    result, _ = cov([host(0), host(1, status="contained", seen=ago(days=20)), host(2, status="contained", rfm="yes")])
    assert (result["activeDevices"], result["containedDevices"]) == (1, 0)


def test_coverage_one_future_dated_record_cannot_make_every_host_stale():
    hosts = [host(i) for i in range(9)] + [host(9, seen=iso(NOW + timedelta(days=20)))]
    result, _ = cov(hosts)
    assert result["requiredCoveragePercentage"] == 100.0
    cfg_result, info = cfg(hosts)
    assert cfg_result["isEPPConfigured"] == 100


def test_timestamps_with_an_offset_are_converted_not_dropped():
    assert COV.parse_time("2026-10-01T12:00:00+02:00") == datetime(2026, 10, 1, 10, 0, 0)
    assert COV.parse_time("2026-10-01T12:00:00-05:30") == datetime(2026, 10, 1, 17, 30, 0)
    assert COV.parse_time("2026-10-01T12:00:00.123456789Z") == datetime(2026, 10, 1, 12, 0, 0)
    for bad in ("2026-10-01T12:00:00 UTC", "2026-10-01", "2026-10-01T12:00:00+0200", "x" * 25):
        assert COV.parse_time(bad) is None, bad


def test_coverage_real_last_seen_spread_shifted_to_the_present():
    real = copy.deepcopy(DEVICES)
    seen = [datetime.fromisoformat(d["last_seen"][:19]) for d in real["resources"]]
    shift = NOW - max(seen)
    for d, when in zip(real["resources"], seen):
        d["last_seen"] = iso(when + shift)
        d["reduced_functionality_mode"] = "no"
    real["meta"]["pagination"]["total"] = len(real["resources"])
    expected_stale = sum(1 for when in seen if when < max(seen) - timedelta(days=15))
    assert expected_stale > 0  # the real spread exercises the window
    out = COV.transform(real)["transformedResponse"]
    assert out["notReportingDevices"] == expected_stale
    assert out["activeDevices"] == len(seen) - expected_stale


# --- isEPPConfigured: staleness belongs to coverage ---

def test_config_leaves_out_a_stale_host_that_coverage_counts():
    hosts = [host(0), host(1, seen=ago(days=20), applied=False)]
    result, info = cfg(hosts)
    assert (result["isEPPConfigured"], result["protectedHosts"]) == (100, 1)
    assert info["transformation"]["inputSummary"]["notReportingHosts"] == 1
    assert any("left out" in f for f in info["evaluation"]["additionalFindings"])
    assert cov(hosts)[0]["notReportingDevices"] == 1


def test_config_all_hosts_stale_is_not_evaluated():
    result, info = cfg([host(i, seen=ago(days=40)) for i in range(3)])
    assert result["isEPPConfigured"] is None
    assert info["dataCollection"]["status"] == "error"


def test_both_checks_share_one_window_and_one_rule():
    assert CFG.ACTIVE_WINDOW_DAYS == COV.ACTIVE_WINDOW_DAYS
    for name in ("parse_time", "reference_clock", "is_reporting"):
        cov_src = (HERE / "requiredCoveragePercentage.py").read_text()
        cfg_src = (HERE / "isEPPConfiguredFromHosts.py").read_text()
        start = "def " + name + "("
        assert cov_src[cov_src.index(start):].split("\n\n\n")[0] == cfg_src[cfg_src.index(start):].split("\n\n\n")[0], name


# --- isEPPConfigured: three buckets, three fixes ---

def test_config_separates_no_policy_from_assigned_not_applied_and_rfm():
    hosts = [host(0), host(1, policy_id=None, applied=False), host(2, applied=False, assigned=ago(days=10)),
             host(3, rfm="yes")]
    result, info = cfg(hosts)
    summary = info["transformation"]["inputSummary"]
    assert result["isEPPConfigured"] == 25
    assert (summary["noPreventionPolicyAssigned"], summary["preventionPolicyAssignedNotApplied"],
            summary["reducedFunctionalityMode"]) == (1, 1, 1)
    recs = info["evaluation"]["recommendations"]
    assert len(recs) == 3
    not_applied = [r for r in recs if "assigned that their sensor has not applied" in r][0]
    assert "rather than the group assignment" in not_applied


def test_config_assigned_not_applied_does_not_recommend_assigning_a_policy():
    _, info = cfg([host(0), host(1, applied=False, assigned=ago(days=3))])
    assert not any(r.startswith("Assign") or "add their host groups" in r for r in info["evaluation"]["recommendations"])


def test_config_applied_as_string_true_counts():
    assert cfg([host(0, applied="True")])[0]["isEPPConfigured"] == 100


# --- isEPPConfigured: pending, bounded and visible ---

def test_config_host_assigned_recently_and_not_seen_since_is_pending_and_left_out():
    assigned = NOW - timedelta(hours=3)
    hosts = [host(0), host(1, applied=False, assigned=iso(assigned), seen=iso(assigned - timedelta(hours=2)))]
    result, info = cfg(hosts)
    assert (result["isEPPConfigured"], result["configuredHosts"], result["protectedHosts"]) == (100, 1, 1)
    assert info["transformation"]["inputSummary"]["pendingPreventionPolicy"] == 1
    assert any("pending" in f for f in info["evaluation"]["additionalFindings"])


def test_config_only_pending_hosts_is_not_evaluated_never_a_pass():
    assigned = NOW - timedelta(hours=3)
    result, info = cfg([host(0, applied=False, assigned=iso(assigned), seen=iso(assigned - timedelta(hours=1)))])
    assert result["isEPPConfigured"] is None
    assert info["dataCollection"]["status"] == "error"


def test_config_pending_ends_after_the_window():
    assigned = NOW - timedelta(hours=CFG.PENDING_WINDOW_HOURS + 1)
    hosts = [host(0), host(1, applied=False, assigned=iso(assigned), seen=iso(assigned - timedelta(hours=1)))]
    result, info = cfg(hosts)
    assert result["isEPPConfigured"] == 50
    assert info["transformation"]["inputSummary"]["pendingPreventionPolicy"] == 0


def test_reassigning_an_online_failing_host_does_not_restart_its_clock():
    """Reassigned 2 hours ago; the host has checked in since and still not applied: failing, not pending."""
    hosts = [host(0), host(1, applied=False, assigned=ago(hours=2), seen=ago(minutes=5))]
    result, info = cfg(hosts)
    assert result["isEPPConfigured"] == 50
    assert info["transformation"]["inputSummary"]["pendingPreventionPolicy"] == 0
    assert info["transformation"]["inputSummary"]["preventionPolicyAssignedNotApplied"] == 1


def test_config_online_host_within_pickup_grace_is_pending():
    hosts = [host(0), host(1, applied=False, assigned=ago(minutes=10), seen=ago(minutes=1))]
    assert cfg(hosts)[1]["transformation"]["inputSummary"]["pendingPreventionPolicy"] == 1


def test_config_host_silent_before_the_assignment_is_never_pending():
    """Last seen 5 days ago, reassigned an hour ago: repeated reassignment cannot keep it out."""
    hosts = [host(0), host(1, applied=False, assigned=ago(hours=1), seen=ago(days=5))]
    result, info = cfg(hosts)
    assert result["isEPPConfigured"] == 50
    assert info["transformation"]["inputSummary"]["pendingPreventionPolicy"] == 0


def test_config_no_assigned_date_is_never_pending():
    hosts = [host(0), host(1, applied=False, seen=ago(minutes=1))]
    assert cfg(hosts)[0]["isEPPConfigured"] == 50
