"""Amazon GuardDuty checks. Shapes follow the GuardDuty API reference (ListDetectors, GetDetector,
GetFindingsStatistics) and the Integration-Service workflow outputs {"detectorIds": [...], "detectors": [...],
"findingStatisticsByDetector": [...]}. Every fixture is synthetic; nothing calls AWS."""
import importlib.util
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
DET = "0" * 31 + "a"


def load(name):
    spec = importlib.util.spec_from_file_location("awsguardduty_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def value(out, key):
    return out["transformedResponse"][key]


def collection(out):
    return out["additionalInfo"]["dataCollection"]["status"]


ERR_IS = {"error": True, "statusCode": 403, "message": "Forbidden"}
AWS_DENIED = {"__type": "AccessDeniedException", "message": "not authorized to perform: guardduty:ListDetectors"}
EMPTYISH = [{}, None, "{}", "", "null", [], ERR_IS, AWS_DENIED, json.dumps(ERR_IS), {"result": {}},
            {"detectorIds": "x"}, {"detectorIds": [DET]}, {"detectorIds": [DET], "detectors": [ERR_IS]},
            {"detectorIds": [DET], "detectors": []}, {"detectorIds": [], "nextToken": "AAEXAMPLE"},
            {"detectorIds": [DET], "detectors": [{"status": "ENABLED"}], "nextToken": "AAEXAMPLE"}]


def feature(name, status):
    return {"name": name, "status": status, "updatedAt": 1.7e9}


def detector(status="ENABLED", features=None, data_sources=None):
    d = {"createdAt": "2026-01-01T00:00:00.000Z", "findingPublishingFrequency": "SIX_HOURS",
         "serviceRole": "arn:aws:iam::111111111111:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
         "status": status, "updatedAt": "2026-01-01T00:00:00.000Z"}
    if features is not None:
        d["features"] = features
    if data_sources is not None:
        d["dataSources"] = data_sources
    return d


ALL_ON = [feature("S3_DATA_EVENTS", "ENABLED"), feature("EBS_MALWARE_PROTECTION", "ENABLED"),
          feature("RUNTIME_MONITORING", "ENABLED"), feature("EKS_RUNTIME_MONITORING", "DISABLED")]


def state(*detectors):
    return {"detectorIds": [DET[:-1] + str(i) for i in range(len(detectors))], "detectors": list(detectors)}


def test_no_evidence_is_never_an_answer():
    keys = ["isGuardDutyEnabled", "isMalwareProtectionEnabled", "isRuntimeMonitoringEnabled",
            "criticalOpenFindingsCount", "highSeverityOpenFindingsCount"]
    for key in keys:
        t = load(key)
        for body in EMPTYISH:
            out = t(body)
            assert value(out, key) is None, (key, body)
            assert collection(out) == "error", (key, body)


def test_enabled():
    t = load("isGuardDutyEnabled")
    assert value(t(state(detector())), "isGuardDutyEnabled") is True
    assert value(t(state(detector("DISABLED"))), "isGuardDutyEnabled") is False
    off = t({"detectorIds": []})
    assert value(off, "isGuardDutyEnabled") is False
    assert collection(off) == "success"
    assert value(t({"apiResponse": state(detector())}), "isGuardDutyEnabled") is True
    assert value(t(json.dumps(state(detector()))), "isGuardDutyEnabled") is True
    assert value(t(state({"status": "PAUSED"})), "isGuardDutyEnabled") is None


def test_malware_protection():
    t = load("isMalwareProtectionEnabled")
    key = "isMalwareProtectionEnabled"
    assert value(t(state(detector(features=ALL_ON))), key) is True
    assert value(t(state(detector(features=[feature("EBS_MALWARE_PROTECTION", "DISABLED")]))), key) is False
    legacy = {"malwareProtection": {"scanEc2InstanceWithFindings": {"ebsVolumes": {"status": "ENABLED"}}}}
    assert value(t(state(detector(data_sources=legacy))), key) is True
    assert value(t(state(detector(features=[feature("S3_DATA_EVENTS", "ENABLED")]))), key) is None
    assert value(t(state(detector("DISABLED", features=ALL_ON))), key) is False
    assert value(t({"detectorIds": []}), key) is False


def test_runtime_monitoring():
    t = load("isRuntimeMonitoringEnabled")
    key = "isRuntimeMonitoringEnabled"
    assert value(t(state(detector(features=ALL_ON))), key) is True
    eks_only = [feature("RUNTIME_MONITORING", "DISABLED"), feature("EKS_RUNTIME_MONITORING", "ENABLED")]
    assert value(t(state(detector(features=eks_only))), key) is True
    both_off = [feature("RUNTIME_MONITORING", "DISABLED"), feature("EKS_RUNTIME_MONITORING", "DISABLED")]
    assert value(t(state(detector(features=both_off))), key) is False
    assert value(t(state(detector(features=[feature("S3_DATA_EVENTS", "ENABLED")]))), key) is None
    assert value(t(state(detector())), key) is None


def stats(groups=None, legacy=None, token=None):
    body = {"findingStatistics": {}}
    if groups is not None:
        body["findingStatistics"]["groupedBySeverity"] = [
            {"severity": s, "totalFindings": n, "lastGeneratedAt": 1.7e9} for s, n in groups]
    if legacy is not None:
        body["findingStatistics"]["countBySeverity"] = legacy
    if token:
        body["nextToken"] = token
    return body


def with_stats(det, body):
    out = state(det)
    out["findingStatisticsByDetector"] = [body]
    return out


def test_counts_by_band():
    crit = load("criticalOpenFindingsCount")
    high = load("highSeverityOpenFindingsCount")
    body = with_stats(detector(), stats([(8.0, 3), (9.5, 1), (5.0, 10), (7.0, 2), (9.0, 4)]))
    assert value(crit(body), "criticalOpenFindingsCount") == 5
    assert value(high(body), "highSeverityOpenFindingsCount") == 5
    zero = with_stats(detector(), stats([(2.0, 7)]))
    assert value(high(zero), "highSeverityOpenFindingsCount") == 0
    assert collection(high(zero)) == "success"
    assert value(high(with_stats(detector(), stats([])))  , "highSeverityOpenFindingsCount") == 0
    legacy = with_stats(detector(), stats(legacy={"8.0": 2, "2.0": 1, "9": "3"}))
    assert value(high(legacy), "highSeverityOpenFindingsCount") == 2
    assert value(crit(legacy), "criticalOpenFindingsCount") == 3


def test_counts_fail_closed():
    high = load("highSeverityOpenFindingsCount")
    key = "highSeverityOpenFindingsCount"
    assert value(high({"detectorIds": []}), key) is None
    assert value(high(with_stats(detector("DISABLED"), stats([(8.0, 0)]))), key) is None
    assert value(high(with_stats(detector(), stats([(8.0, 1)], token="AAEXAMPLE"))), key) is None
    many = [(1.0 + i / 10.0, 1) for i in range(100)]
    assert value(high(with_stats(detector(), stats(many))), key) is None
    assert value(high(with_stats(detector(), ERR_IS)), key) is None
    assert value(high(with_stats(detector(), {"findingStatistics": {}})), key) is None
    assert value(high(with_stats(detector(), stats([(None, 1)]))), key) is None
    no_stats = state(detector())
    assert value(high(no_stats), key) is None
    two = state(detector(), detector())
    two["findingStatisticsByDetector"] = [stats([(8.0, 1)])]
    assert value(high(two), key) is None
