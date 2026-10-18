"""Palo Alto Networks Cloud NGFW (AWS): seven checks over the Integration-Service workflows.

Bodies are SYNTHETIC and follow the public OpenAPI reference for Cloud NGFW for AWS
(github.com/PaloAltoNetworks/pan.dev, openapi-specs/cloudngfw/aws). Where the reference does
not say how a read is filtered (query string or body) or which strings a field can hold, the
transform answers Not evaluated (null) rather than a pass. No customer data.

Every vendor answer arrives as {"Response": {...}, "ResponseStatus": {"ErrorCode": 0}}.
An unreadable, refused (401/403), error-shaped, empty or possibly cut-off read must come back
as null with additionalInfo.dataCollection.status == "error": never False and never 0.
"""
import copy
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
KEYS = ["ipsEnabled", "isURLFilteringProfileEnabled", "sslDeepInspectionEnabled", "isRulestackCommitClean",
        "firewallLoggingEnabled", "hasCertificatesManagedExternally", "restApiTokenExpiryEnforced"]
RULESTACK_KEYS = KEYS[:4]
OK = {"ErrorCode": 0}


def load(name):
    spec = importlib.util.spec_from_file_location("palo_alto_cloud_ngfw_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def full(name, body):
    return load(name).transform(copy.deepcopy(body))


def run(name, body):
    return full(name, body)["transformedResponse"][name]


def reason_of(out):
    return " ".join(out["additionalInfo"]["dataCollection"]["errors"])


def not_evaluated(name, body):
    out = full(name, body)
    assert out["transformedResponse"][name] is None, out["transformedResponse"]
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert out["additionalInfo"]["dataCollection"]["errors"]
    return out


def ok(response):
    return {"Response": response, "ResponseStatus": dict(OK)}


# --- builders ---------------------------------------------------------------------------

def firewall(name, rulestack="rs-a", global_rulestack=None):
    fw = {"FirewallName": name, "RuleStackName": rulestack, "EndpointMode": "ServiceManaged",
          "VpcId": "vpc-0000", "SubnetMappings": []}
    if global_rulestack is not None:
        fw["GlobalRuleStackName"] = global_rulestack
    return ok({"Firewall": fw, "Status": {"FirewallStatus": "CREATE_COMPLETE", "Attachments": []}})


def profiles(vuln="BestPractice", url="BestPractice", trust="decrypt-cert"):
    p = {"AntiSpywareProfile": "BestPractice", "AntiVirusProfile": "BestPractice",
         "FileBlockingProfile": "BestPractice", "VulnerabilityProfile": vuln, "URLFilteringProfile": url}
    if trust is not None:
        p["OutboundTrustCertificate"] = trust
    return p


def rulestack(name="rs-a", running=None, state="Running"):
    data = {"RuleStackName": name, "RuleStackState": state}
    if running is not None:
        data["RuleStackRunning"] = {"Scope": "Local", "Profiles": running}
    return ok(data)


def rulestack_body(fws=None, stacks=None, uncommitted=None, running_names=None):
    fws = fws if fws is not None else [firewall("fw-a")]
    stacks = stacks if stacks is not None else [rulestack("rs-a", profiles())]
    names = running_names if running_names is not None else ["rs-a"]
    listing = {"RuleStackRunning": names, "RuleStackCandidate": names,
               "RuleStackUncommitted": uncommitted if uncommitted is not None else []}
    return {"firewallList": ok({"Firewalls": [{"FirewallName": "fw-a"}]}),
            "firewalls": fws, "rulestackList": ok(listing), "rulestacks": stacks}


def logprofile(name="fw-a", configs=None):
    if configs is None:
        configs = [{"LogType": "TRAFFIC", "LogDestinationType": "S3", "LogDestination": "logs-bucket"},
                   {"LogType": "THREAT", "LogDestinationType": "S3", "LogDestination": "logs-bucket"},
                   {"LogType": "DECRYPTION", "LogDestinationType": "S3", "LogDestination": "logs-bucket"}]
    return ok({"FirewallName": name, "LogDestinationConfigs": configs})


def logs_of(*kinds, name="fw-a"):
    """A log profile that has a destination for exactly these log types."""
    return logprofile(name, [{"LogType": k, "LogDestinationType": "S3", "LogDestination": "logs-bucket"}
                             for k in kinds])


def log_body(profiles_list=None, listed=None):
    """listed: the firewall names the firewall list holds; by default the ones the profiles name."""
    profiles_list = profiles_list if profiles_list is not None else [logprofile()]
    if listed is None:
        listed = []
        for entry in profiles_list:
            name = (entry.get("Response") or {}).get("FirewallName") or entry.get("item")
            if name and name not in listed:
                listed.append(name)
    return {"firewallList": ok({"Firewalls": [{"FirewallName": name} for name in listed]}),
            "logProfiles": profiles_list}


SM_ARN = "arn:aws:secretsmanager:us-east-1:111122223333:secret:decrypt-ca-AbCdEf"


def cert(arn=SM_ARN, name="decrypt-cert"):
    return ok({"Name": name, "RuleStackName": "rs-a",
               "CertificateObjectRunning": {"CertificateSignerArn": arn, "CertificateSelfSigned": True}})


def cert_body(certs=None, stacks=None):
    certs = certs if certs is not None else [cert()]
    stacks = stacks if stacks is not None else [rulestack("rs-a", profiles())]
    return {"rulestackList": ok({"RuleStackRunning": ["rs-a"]}), "rulestacks": stacks, "certificates": certs}


def token_body(enabled=True, max_expiry=1440):
    r = {"Enabled": enabled}
    if max_expiry is not None:
        r["MaxExpiryTime"] = max_expiry
    return ok(r)


VENDOR_ERRORS = [
    {},
    [],
    None,
    "",
    "not json",
    {"error": True, "statusCode": 401, "message": "Unauthorized"},
    {"error": True, "statusCode": 403, "message": "Forbidden"},
    {"statusCode": 403, "message": "token expired"},
    {"message": "The security token included in the request is expired"},
    {"Response": {}, "ResponseStatus": {"ErrorCode": 403, "Reason": "AccessDeniedException"}},
]
ALL_KEYS_NO_EVIDENCE = [(k, b) for k in KEYS for b in VENDOR_ERRORS]


@pytest.mark.parametrize("key,body", ALL_KEYS_NO_EVIDENCE)
def test_unreadable_or_refused_body_is_not_evaluated(key, body):
    not_evaluated(key, body)


@pytest.mark.parametrize("key", KEYS)
def test_string_encoded_empty_object_is_not_evaluated(key):
    not_evaluated(key, "{}")


# --- ipsEnabled ------------------------------------------------------------------------
# The vendor reference allows only custom or BestPractice for VulnerabilityProfile and defaults it
# to BestPractice, so a read can never show IPS off. A key that cannot be both True and False from
# the vendor reply answers Not evaluated until a read can.

def ips_probes():
    two = rulestack_body(fws=[firewall("fw-a", "rs-a"), firewall("fw-b", "rs-b")],
                         stacks=[rulestack("rs-a", profiles()), rulestack("rs-b", profiles(vuln="custom"))],
                         running_names=["rs-a", "rs-b"])
    return [rulestack_body(),
            rulestack_body(stacks=[rulestack("rs-a", profiles(vuln="custom"))]),
            rulestack_body(stacks=[rulestack("rs-a", profiles(vuln="None"))]),
            rulestack_body(stacks=[rulestack("rs-a", profiles(vuln="Strict"))]),
            two,
            {"response": rulestack_body()},
            json.dumps({"response": rulestack_body(stacks=[rulestack("rs-a", profiles(vuln="custom"))])}),
            rulestack_body(fws=[firewall("fw-a", rulestack="", global_rulestack="gs-1")],
                           stacks=[rulestack("gs-1", profiles())], running_names=["gs-1"])]


def test_ips_discriminates_nothing_so_it_never_answers_true_or_false():
    for body in ips_probes():
        out = not_evaluated("ipsEnabled", body)
        assert "default" in reason_of(out) and "BestPractice" in reason_of(out)


@pytest.mark.parametrize("value", ["BestPractice", "custom", "None", "Strict"])
def test_ips_is_not_evaluated_whatever_the_vulnerability_profile_says(value):
    body = rulestack_body(stacks=[rulestack("rs-a", profiles(vuln=value))])
    assert run("ipsEnabled", body) is None


def test_ips_two_firewalls_sharing_one_rulestack_count_once_in_the_summary():
    body = rulestack_body(fws=[firewall("fw-a"), firewall("fw-b")])
    out = not_evaluated("ipsEnabled", body)
    assert out["additionalInfo"]["transformation"]["inputSummary"]["rulestacks"] == 1


def test_ips_a_bound_rulestack_with_no_describe_record_is_not_evaluated():
    body = rulestack_body(fws=[firewall("fw-a", "rs-zzz")])
    out = not_evaluated("ipsEnabled", body)
    assert "default" not in reason_of(out)


def test_ips_candidate_only_rulestack_is_not_evaluated():
    # a rulestack that was never committed has no running configuration: nothing is enforced yet
    body = rulestack_body(stacks=[ok({"RuleStackName": "rs-a", "RuleStackState": "Uncommitted",
                                      "RuleStackCandidate": {"Profiles": profiles()}})])
    out = not_evaluated("ipsEnabled", body)
    assert "default" not in reason_of(out)


def test_ips_missing_profile_field_is_not_evaluated():
    p = profiles()
    del p["VulnerabilityProfile"]
    not_evaluated("ipsEnabled", rulestack_body(stacks=[rulestack("rs-a", p)]))


def test_ips_no_firewalls_is_not_evaluated():
    not_evaluated("ipsEnabled", rulestack_body(fws=[]))


def test_ips_describe_item_error_is_not_evaluated():
    stacks = [{"error": True, "statusCode": 403, "item": "rs-a"}]
    not_evaluated("ipsEnabled", rulestack_body(stacks=stacks))


def test_ips_truncated_iterate_is_not_evaluated():
    body = rulestack_body()
    body["iterateTruncated"] = True
    not_evaluated("ipsEnabled", body)


def test_ips_vendor_error_code_inside_a_describe_is_not_evaluated():
    stacks = [{"Response": {}, "ResponseStatus": {"ErrorCode": 500, "Reason": "InternalServerError"}}]
    not_evaluated("ipsEnabled", rulestack_body(stacks=stacks))


def test_ips_more_firewalls_than_one_page_is_not_evaluated():
    body = rulestack_body()
    body["firewallList"]["Response"]["NextToken"] = "abc123"
    not_evaluated("ipsEnabled", body)


# --- isURLFilteringProfileEnabled ---------------------------------------------------------

def test_url_filtering_true_for_best_practice_and_custom():
    for value in ("BestPractice", "custom"):
        body = rulestack_body(stacks=[rulestack("rs-a", profiles(url=value))])
        assert run("isURLFilteringProfileEnabled", body) is True


def test_url_filtering_false_when_none():
    body = rulestack_body(stacks=[rulestack("rs-a", profiles(url="None"))])
    assert run("isURLFilteringProfileEnabled", body) is False


def test_url_filtering_false_if_any_bound_rulestack_has_it_off():
    body = rulestack_body(fws=[firewall("fw-a", "rs-a"), firewall("fw-b", "rs-b")],
                          stacks=[rulestack("rs-a", profiles(url="None")), rulestack("rs-b", profiles())],
                          running_names=["rs-a", "rs-b"])
    assert run("isURLFilteringProfileEnabled", body) is False


def test_url_filtering_discriminates():
    on = run("isURLFilteringProfileEnabled", rulestack_body(stacks=[rulestack("rs-a", profiles(url="custom"))]))
    off = run("isURLFilteringProfileEnabled", rulestack_body(stacks=[rulestack("rs-a", profiles(url="None"))]))
    assert (on, off) == (True, False)


def test_url_filtering_a_firewall_bound_to_a_local_and_a_global_rulestack_needs_both_read():
    fws = [firewall("fw-a", rulestack="rs-a", global_rulestack="gs-1")]
    only_local = rulestack_body(fws=fws, stacks=[rulestack("rs-a", profiles())], running_names=["rs-a"])
    not_evaluated("isURLFilteringProfileEnabled", only_local)
    both = rulestack_body(fws=fws, stacks=[rulestack("rs-a", profiles()), rulestack("gs-1", profiles())],
                          running_names=["rs-a", "gs-1"])
    assert run("isURLFilteringProfileEnabled", both) is True
    global_off = rulestack_body(fws=fws, stacks=[rulestack("rs-a", profiles()),
                                                  rulestack("gs-1", profiles(url="None"))],
                                running_names=["rs-a", "gs-1"])
    assert run("isURLFilteringProfileEnabled", global_off) is False


def test_url_filtering_a_listed_firewall_with_no_read_of_its_own_is_not_evaluated():
    body = rulestack_body(fws=[firewall("fw-b")])  # the list names fw-a; only fw-b was read
    not_evaluated("isURLFilteringProfileEnabled", body)


def test_url_filtering_does_not_answer_from_the_ips_profile():
    p = profiles(vuln="BestPractice")
    del p["URLFilteringProfile"]
    not_evaluated("isURLFilteringProfileEnabled", rulestack_body(stacks=[rulestack("rs-a", p)]))


def test_url_filtering_unrecognised_value_is_not_evaluated():
    not_evaluated("isURLFilteringProfileEnabled",
                  rulestack_body(stacks=[rulestack("rs-a", profiles(url="Maybe"))]))


# --- sslDeepInspectionEnabled -----------------------------------------------------------
# OutboundTrustCertificate shows a decryption certificate was chosen, not that any traffic is
# decrypted (decryption rules are not read), so the value cannot be both True and False from the
# reply: Not evaluated.

def ssl_probes():
    two = rulestack_body(fws=[firewall("fw-a", "rs-a"), firewall("fw-b", "rs-b")],
                         stacks=[rulestack("rs-a", profiles()), rulestack("rs-b", profiles(trust=None))],
                         running_names=["rs-a", "rs-b"])
    return [rulestack_body(),
            rulestack_body(stacks=[rulestack("rs-a", profiles(trust=None))]),
            rulestack_body(stacks=[rulestack("rs-a", profiles(trust="  "))]),
            two]


def test_ssl_inspection_discriminates_nothing_so_it_never_answers_true_or_false():
    for body in ssl_probes():
        out = not_evaluated("sslDeepInspectionEnabled", body)
        assert "decryption rules" in reason_of(out)


def test_ssl_inspection_a_certificate_alone_is_not_a_pass():
    assert run("sslDeepInspectionEnabled", rulestack_body()) is None


def test_ssl_inspection_no_certificate_is_not_a_fail():
    body = rulestack_body(stacks=[rulestack("rs-a", profiles(trust=None))])
    assert run("sslDeepInspectionEnabled", body) is None


def test_ssl_inspection_empty_profiles_object_is_not_evaluated():
    body = rulestack_body(stacks=[rulestack("rs-a", {})])
    out = not_evaluated("sslDeepInspectionEnabled", body)
    assert "decryption rules" not in reason_of(out)


# --- isRulestackCommitClean -----------------------------------------------------------
# The reference models the list filters (Uncommitted defaults to false) as a request body on a GET,
# and the vendor Go SDK (cloud-ngfw-aws-go, ngfw/aws/stack.go ListRuleStack) never sends an
# `uncommitted` parameter. So an empty or absent RuleStackUncommitted cannot show "committed": nothing
# proves the filter was honoured. Only a rulestack a firewall uses that the vendor itself lists under
# RuleStackUncommitted is shown: that is False. Everything else is Not evaluated. Never True.

PENDING = [{"RuleStackName": "rs-a", "Operation": "update"}]


def clean_looking_probes():
    fws = [firewall("fw-a", rulestack="", global_rulestack="gs-1")]
    return [rulestack_body(),
            rulestack_body(stacks=[]),
            rulestack_body(uncommitted=[{"RuleStackName": "draft-unused", "Operation": "add"}]),
            rulestack_body(fws=fws, running_names=["gs-1"]),
            rulestack_body(fws=[firewall("fw-a", rulestack="rs-a", global_rulestack="gs-1")],
                           running_names=["rs-a", "gs-1"]),
            {"response": rulestack_body()},
            json.dumps(rulestack_body())]


def test_commit_clean_never_answers_true_because_an_empty_list_does_not_show_the_filter_was_honoured():
    for body in clean_looking_probes():
        out = not_evaluated("isRulestackCommitClean", body)
        assert "filter" in reason_of(out) and "uncommitted" in reason_of(out)


def test_commit_clean_is_not_true_even_when_every_rulestack_in_use_is_listed_running_and_candidate():
    body = rulestack_body()
    assert body["rulestackList"]["Response"]["RuleStackRunning"] == ["rs-a"]
    assert body["rulestackList"]["Response"]["RuleStackCandidate"] == ["rs-a"]
    assert run("isRulestackCommitClean", body) is None


def test_commit_clean_false_when_a_bound_rulestack_has_pending_changes():
    body = rulestack_body(uncommitted=PENDING)
    out = full("isRulestackCommitClean", body)
    assert out["transformedResponse"]["isRulestackCommitClean"] is False
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["evaluation"]["failReasons"]


@pytest.mark.parametrize("operation", ["add", "update", "delete"])
def test_commit_clean_false_for_every_pending_operation_the_reference_lists(operation):
    body = rulestack_body(uncommitted=[{"RuleStackName": "rs-a", "Operation": operation}])
    assert run("isRulestackCommitClean", body) is False


def test_commit_clean_ignores_an_uncommitted_rulestack_no_firewall_uses():
    body = rulestack_body(uncommitted=[{"RuleStackName": "draft-unused", "Operation": "add"}])
    assert run("isRulestackCommitClean", body) is None


def test_commit_clean_without_the_uncommitted_list_is_not_evaluated():
    body = rulestack_body()
    del body["rulestackList"]["Response"]["RuleStackUncommitted"]
    out = not_evaluated("isRulestackCommitClean", body)
    assert "RuleStackUncommitted" in reason_of(out)


def test_commit_clean_an_unreadable_uncommitted_entry_is_not_evaluated():
    for entry in ({"Operation": "update"}, "rs-a", None, {"RuleStackName": ""}):
        body = rulestack_body(uncommitted=[entry])
        not_evaluated("isRulestackCommitClean", body)


def test_commit_clean_truncated_rulestack_list_is_not_evaluated():
    body = rulestack_body(uncommitted=PENDING)
    body["rulestackList"]["Response"]["NextToken"] = "abc123"
    not_evaluated("isRulestackCommitClean", body)


def test_commit_clean_no_firewalls_is_not_evaluated():
    not_evaluated("isRulestackCommitClean", rulestack_body(fws=[], uncommitted=PENDING))


def test_commit_clean_discriminates_only_the_failing_side():
    clean = run("isRulestackCommitClean", rulestack_body())
    dirty = run("isRulestackCommitClean", rulestack_body(uncommitted=PENDING))
    assert (clean, dirty) == (None, False)


def test_commit_clean_a_global_rulestack_named_in_the_uncommitted_list_is_false():
    fws = [firewall("fw-a", rulestack="", global_rulestack="gs-1")]
    dirty = rulestack_body(fws=fws, running_names=["gs-1"],
                           uncommitted=[{"RuleStackName": "gs-1", "Operation": "update"}])
    assert run("isRulestackCommitClean", dirty) is False


def test_commit_clean_reads_both_a_local_and_a_global_rulestack_on_one_firewall():
    fws = [firewall("fw-a", rulestack="rs-a", global_rulestack="gs-1")]
    dirty = rulestack_body(fws=fws, running_names=["rs-a", "gs-1"],
                           uncommitted=[{"RuleStackName": "gs-1", "Operation": "update"}])
    assert run("isRulestackCommitClean", dirty) is False


def test_commit_clean_a_rulestack_named_only_in_the_uncommitted_list_is_false():
    body = rulestack_body(running_names=[], uncommitted=[{"RuleStackName": "rs-a", "Operation": "add"}])
    assert run("isRulestackCommitClean", body) is False


def test_commit_clean_a_listed_firewall_with_no_read_of_its_own_is_not_evaluated():
    # the list names fw-a; only fw-b was read, so which rulestacks are in use is not fully known
    not_evaluated("isRulestackCommitClean", rulestack_body(fws=[firewall("fw-b")], uncommitted=PENDING))


def test_commit_clean_a_firewall_naming_no_rulestack_is_not_evaluated():
    not_evaluated("isRulestackCommitClean",
                  rulestack_body(fws=[firewall("fw-a", rulestack="")], uncommitted=PENDING))


def test_commit_clean_the_reason_for_not_evaluated_carries_the_filter_citation():
    out = not_evaluated("isRulestackCommitClean", rulestack_body())
    text = reason_of(out)
    assert "request body" in text and "SDK" in text


def test_commit_clean_does_not_need_the_describe_records_to_find_a_pending_change():
    assert run("isRulestackCommitClean", rulestack_body(stacks=[], uncommitted=PENDING)) is False


# --- firewallLoggingEnabled -------------------------------------------------------------
# The bundle names traffic, threat and decryption logs; all three need a destination. The vendor
# spells the third type DESCRYPTION in its enum, so both spellings count. An absent or empty
# LogDestinationConfigs is not documented as "no log profile", so it is Not evaluated, not False.

def test_logging_discriminates():
    on = run("firewallLoggingEnabled", log_body([logs_of("TRAFFIC", "THREAT", "DECRYPTION")]))
    off = run("firewallLoggingEnabled", log_body([logs_of("TRAFFIC", "THREAT")]))
    assert (on, off) == (True, False)


def test_logging_true_when_traffic_threat_and_decryption_logs_have_a_destination():
    assert run("firewallLoggingEnabled", log_body()) is True


def test_logging_true_with_the_vendor_spelling_of_decryption():
    assert run("firewallLoggingEnabled", log_body([logs_of("TRAFFIC", "THREAT", "DESCRYPTION")])) is True


def test_logging_false_when_decryption_logs_have_no_destination():
    assert run("firewallLoggingEnabled", log_body([logs_of("TRAFFIC", "THREAT")])) is False


def test_logging_false_when_threat_logs_have_no_destination():
    assert run("firewallLoggingEnabled", log_body([logs_of("TRAFFIC", "DECRYPTION")])) is False


def test_logging_false_when_traffic_logs_have_no_destination():
    assert run("firewallLoggingEnabled", log_body([logs_of("THREAT", "DECRYPTION")])) is False


def test_logging_blank_destination_does_not_count():
    configs = [{"LogType": "TRAFFIC", "LogDestinationType": "S3", "LogDestination": ""},
               {"LogType": "THREAT", "LogDestinationType": "S3", "LogDestination": "b"},
               {"LogType": "DECRYPTION", "LogDestinationType": "S3", "LogDestination": "b"}]
    assert run("firewallLoggingEnabled", log_body([logprofile(configs=configs)])) is False


def test_logging_absent_destination_list_is_not_evaluated():
    out = not_evaluated("firewallLoggingEnabled", log_body([ok({"FirewallName": "fw-a"})]))
    assert "LogDestinationConfigs" in reason_of(out)


def test_logging_empty_destination_list_is_not_evaluated():
    out = not_evaluated("firewallLoggingEnabled", log_body([logprofile(configs=[])]))
    assert "LogDestinationConfigs" in reason_of(out)


def test_logging_false_if_one_of_two_firewalls_is_not_logging():
    body = log_body([logprofile("fw-a"), logs_of("TRAFFIC", name="fw-b")])
    assert run("firewallLoggingEnabled", body) is False


def test_logging_log_profile_with_no_readable_fields_is_not_evaluated():
    not_evaluated("firewallLoggingEnabled", log_body([ok({})]))


def test_logging_item_error_is_not_evaluated():
    not_evaluated("firewallLoggingEnabled", log_body([{"error": True, "statusCode": 403, "item": "fw-a"}]))


def test_logging_no_firewalls_is_not_evaluated():
    not_evaluated("firewallLoggingEnabled", log_body([]))


def test_logging_one_firewall_unreadable_and_one_off_is_false_but_unreadable_alone_is_not_evaluated():
    mixed = log_body([logs_of("TRAFFIC", name="fw-a"), {"error": True, "statusCode": 500, "item": "fw-b"}])
    assert run("firewallLoggingEnabled", mixed) is False
    mixed_ok = log_body([logprofile("fw-a"), {"error": True, "statusCode": 500, "item": "fw-b"}])
    not_evaluated("firewallLoggingEnabled", mixed_ok)


def test_logging_an_empty_list_on_one_firewall_and_an_unreadable_other_is_not_evaluated():
    mixed = log_body([logprofile("fw-a", configs=[]), {"error": True, "statusCode": 500, "item": "fw-b"}])
    not_evaluated("firewallLoggingEnabled", mixed)


def test_logging_a_listed_firewall_with_no_log_profile_read_is_not_evaluated():
    body = log_body([logprofile("fw-a")], listed=["fw-a", "fw-b"])
    out = not_evaluated("firewallLoggingEnabled", body)
    assert "listed firewall" in reason_of(out)


def test_logging_every_listed_firewall_read_and_logging_is_true():
    body = log_body([logprofile("fw-a"), logprofile("fw-b")], listed=["fw-a", "fw-b"])
    assert run("firewallLoggingEnabled", body) is True


def test_logging_a_missing_firewall_is_not_hidden_by_reading_another_one_twice():
    body = log_body([logprofile("fw-a"), logprofile("fw-a")], listed=["fw-a", "fw-b"])
    not_evaluated("firewallLoggingEnabled", body)


def test_logging_a_profile_that_names_another_firewall_does_not_cover_a_listed_one():
    body = log_body([logprofile("fw-other")], listed=["fw-a"])
    not_evaluated("firewallLoggingEnabled", body)


def test_logging_a_profile_with_no_firewall_name_cannot_cover_a_listed_firewall():
    anon = ok({"LogDestinationConfigs": logprofile()["Response"]["LogDestinationConfigs"]})
    not_evaluated("firewallLoggingEnabled", log_body([anon], listed=["fw-a"]))


def test_logging_a_firewall_that_is_off_is_false_even_when_another_listed_one_is_missing():
    body = log_body([logs_of("TRAFFIC", name="fw-a")], listed=["fw-a", "fw-b"])
    assert run("firewallLoggingEnabled", body) is False


def test_logging_without_the_firewall_list_is_not_evaluated():
    body = log_body()
    del body["firewallList"]
    out = not_evaluated("firewallLoggingEnabled", body)
    assert "firewall list" in reason_of(out)


def test_logging_a_firewall_list_with_no_firewalls_is_not_evaluated():
    not_evaluated("firewallLoggingEnabled", log_body([logprofile("fw-a")], listed=[]))


def test_logging_a_firewall_list_entry_with_no_name_is_not_evaluated():
    body = log_body([logprofile("fw-a")], listed=["fw-a"])
    body["firewallList"]["Response"]["Firewalls"].append({"AccountId": "111122223333"})
    not_evaluated("firewallLoggingEnabled", body)


def test_logging_a_firewall_list_with_more_pages_is_not_evaluated():
    body = log_body()
    body["firewallList"]["Response"]["NextToken"] = "abc123"
    not_evaluated("firewallLoggingEnabled", body)


def test_logging_a_refused_firewall_list_is_not_evaluated():
    body = log_body()
    body["firewallList"] = {"error": True, "statusCode": 403, "message": "Forbidden"}
    not_evaluated("firewallLoggingEnabled", body)


def test_logging_a_firewall_list_without_a_firewalls_array_is_not_evaluated():
    body = log_body()
    body["firewallList"] = ok({})
    not_evaluated("firewallLoggingEnabled", body)


# --- hasCertificatesManagedExternally ---------------------------------------------------

def test_certificates_true_when_every_certificate_signer_is_a_secrets_manager_secret():
    assert run("hasCertificatesManagedExternally", cert_body()) is True


def test_certificates_true_in_a_govcloud_partition():
    arn = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:ca-XyZ"
    assert run("hasCertificatesManagedExternally", cert_body([cert(arn)])) is True


def test_certificates_false_when_a_certificate_is_referenced_from_another_store():
    arn = "arn:aws:acm:us-east-1:111122223333:certificate/abcd"
    assert run("hasCertificatesManagedExternally", cert_body([cert(arn)])) is False


def test_certificates_discriminates():
    on = run("hasCertificatesManagedExternally", cert_body([cert(SM_ARN)]))
    off = run("hasCertificatesManagedExternally", cert_body([cert("arn:aws:acm:us-east-1:111122223333:certificate/abcd")]))
    assert (on, off) == (True, False)


def test_certificates_an_absent_signer_arn_is_not_evaluated():
    # CertificateSignerArn is optional in every certificate answer; absent is not documented as
    # "held outside a secrets manager", so it is Not evaluated, not False
    c = ok({"Name": "c", "RuleStackName": "rs-a", "CertificateObjectRunning": {"CertificateSelfSigned": True}})
    out = not_evaluated("hasCertificatesManagedExternally", cert_body([c]))
    assert "CertificateSignerArn" in reason_of(out)


def test_certificates_a_blank_signer_arn_is_not_evaluated():
    not_evaluated("hasCertificatesManagedExternally", cert_body([cert("  ")]))


def test_certificates_one_not_in_a_secrets_manager_and_one_without_an_arn_is_false():
    other = cert("arn:aws:acm:us-east-1:111122223333:certificate/abcd", "other")
    bare = ok({"Name": "c", "RuleStackName": "rs-a", "CertificateObjectRunning": {"CertificateSelfSigned": True}})
    assert run("hasCertificatesManagedExternally", cert_body([other, bare])) is False


def test_certificates_none_configured_is_not_evaluated():
    stacks = [rulestack("rs-a", profiles(trust=None))]
    not_evaluated("hasCertificatesManagedExternally", cert_body(certs=[], stacks=stacks))


def test_certificates_item_error_is_not_evaluated():
    not_evaluated("hasCertificatesManagedExternally",
                  cert_body([{"error": True, "statusCode": 404, "item": "decrypt-cert"}]))


def test_certificates_no_running_certificate_object_is_not_evaluated():
    c = ok({"Name": "c", "RuleStackName": "rs-a",
            "CertificateObjectCandidate": {"CertificateSignerArn": SM_ARN}})
    not_evaluated("hasCertificatesManagedExternally", cert_body([c]))


RECOGNISED_OTHER_STORES = [
    "arn:aws:acm:us-east-1:111122223333:certificate/abcd-1234",
    "arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/abcd-1234",
    "arn:aws:iam::111122223333:server-certificate/ca",
    "arn:aws:kms:us-east-1:111122223333:key/abcd-1234",
    "arn:aws:s3:::my-cert-bucket/ca.pem",
    "arn:aws-us-gov:acm:us-gov-west-1:111122223333:certificate/abcd-1234",
    "arn:aws-cn:acm:cn-north-1:111122223333:certificate/abcd-1234",
]

JUNK_SIGNERS = [
    "not-an-arn",
    "ca",
    "https://example.invalid/ca.pem",
    "arn",
    "arn:aws",
    "arn:aws:acm",
    "arn:aws:acm:us-east-1:111122223333",
    "arn:aws:banana:us-east-1:111122223333:thing/abcd",
    "arn:aws:::::",
    "arn:garbage:acm:us-east-1:111122223333:certificate/abcd",
    "arn:aws:acm:us-east-1:1234:certificate/abcd",
    "arn:aws:acm:us-east-1:not-an-account:certificate/abcd",
    "ARN:AWS:ACM:us-east-1:111122223333:certificate/abcd",
    "arn:aws:acm:us-east-1:111122223333:",
    "arn:aws:secretsmanager:us-east-1:111122223333:",
    "arn:aws:secretsmanager:us-east-1:111122223333:notasecret:abcd",
    "arn:garbage:secretsmanager:us-east-1:111122223333:secret:abcd",
    "arn:aws:secretsmanager:us-east-1:1234:secret:abcd",
    "arn:aws:secretsmanager::111122223333:secret:abcd",
    "arn:aws:secretsmanager:us-east-1::secret:abcd",
    "arn:aws:secretsmanager:::secret:abcd",
    "null",
    "0",
    "false",
    "<script>alert(1)</script>",
    "arn:aws:acm:us-east-1:111122223333:certificate/abcd\narn:aws:acm",
]


@pytest.mark.parametrize("arn", RECOGNISED_OTHER_STORES)
def test_certificates_a_recognised_non_secrets_manager_signer_is_false(arn):
    assert run("hasCertificatesManagedExternally", cert_body([cert(arn)])) is False


@pytest.mark.parametrize("arn", JUNK_SIGNERS)
def test_certificates_an_unrecognised_or_junk_signer_is_not_evaluated_never_false(arn):
    out = not_evaluated("hasCertificatesManagedExternally", cert_body([cert(arn)]))
    assert "recognis" in reason_of(out)


@pytest.mark.parametrize("value", [123, 1.5, True, False, ["arn:aws:acm:us-east-1:111122223333:certificate/a"],
                                   {"arn": "x"}])
def test_certificates_a_signer_that_is_not_text_is_not_evaluated(value):
    c = ok({"Name": "c", "RuleStackName": "rs-a", "CertificateObjectRunning": {"CertificateSignerArn": value}})
    not_evaluated("hasCertificatesManagedExternally", cert_body([c]))


def test_certificates_junk_next_to_a_secrets_manager_signer_is_not_true():
    body = cert_body([cert(SM_ARN, "a"), cert("not-an-arn", "b")])
    not_evaluated("hasCertificatesManagedExternally", body)


def test_certificates_a_recognised_other_store_still_fails_the_key_next_to_junk():
    body = cert_body([cert("not-an-arn", "a"), cert(RECOGNISED_OTHER_STORES[0], "b")])
    assert run("hasCertificatesManagedExternally", body) is False


def test_certificates_junk_alone_never_fails_the_key():
    for arn in JUNK_SIGNERS:
        assert run("hasCertificatesManagedExternally", cert_body([cert(arn)])) is None


@pytest.mark.parametrize("arn", [
    "arn:aws:secretsmanager::111122223333:secret:ca-AbCdEf",
    "arn:aws:secretsmanager:us-east-1::secret:ca-AbCdEf",
    "arn:aws:secretsmanager:::secret:ca-AbCdEf",
])
def test_certificates_a_secrets_manager_arn_with_an_empty_region_or_account_is_not_true(arn):
    # A real Secrets Manager secret ARN always carries both a region and an account.
    assert run("hasCertificatesManagedExternally", cert_body([cert(arn)])) is None
    not_evaluated("hasCertificatesManagedExternally", cert_body([cert(SM_ARN, "a"), cert(arn, "b")]))


def test_certificates_a_secrets_manager_signer_in_each_partition_is_true():
    for arn in ("arn:aws:secretsmanager:us-east-1:111122223333:secret:ca-AbCdEf",
                "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:ca-AbCdEf",
                "arn:aws-cn:secretsmanager:cn-north-1:111122223333:secret:ca-AbCdEf"):
        assert run("hasCertificatesManagedExternally", cert_body([cert(arn)])) is True


# --- the four keys that are not wired -----------------------------------------------------
# ipsEnabled, sslDeepInspectionEnabled, restApiTokenExpiryEnforced and isRulestackCommitClean are not
# in the Integration-Service retrievalTransformationArray, so they show as not covered. Each file
# says so at the top, so nobody reads it as a live check.

NOT_WIRED_KEYS = ["ipsEnabled", "sslDeepInspectionEnabled", "restApiTokenExpiryEnforced",
                  "isRulestackCommitClean"]


@pytest.mark.parametrize("name", NOT_WIRED_KEYS)
def test_a_not_wired_key_file_says_not_wired_in_its_docstring(name):
    assert "NOT WIRED" in (load(name).__doc__ or "")


def test_the_commit_clean_file_names_the_condition_for_wiring_it_again():
    doc = load("isRulestackCommitClean").__doc__
    assert "real read-only connection" in doc and "re-wire" in doc


# --- restApiTokenExpiryEnforced ---------------------------------------------------------
# The reference bounds the tenant ceiling MaxExpiryTime to 480 through 1440, so any value the
# vendor can return is inside it and the key would always be True. Not evaluated until a read
# can show otherwise.

@pytest.mark.parametrize("ceiling", [480, 700, 1440, 100000, 0, -5])
def test_token_expiry_is_not_evaluated_whatever_the_tenant_ceiling_is(ceiling):
    out = not_evaluated("restApiTokenExpiryEnforced", token_body(True, ceiling))
    assert "480" in reason_of(out) and "1440" in reason_of(out)


def test_token_expiry_discriminates_nothing_so_it_never_answers_true_or_false():
    probes = [token_body(True, 480), token_body(True, 1440), token_body(True, 100000),
              token_body(True, 0), {"apiResponse": token_body(True, 480)},
              json.dumps(token_body(True, 1440))]
    for body in probes:
        assert run("restApiTokenExpiryEnforced", body) is None


def test_token_expiry_a_bool_or_text_ceiling_is_not_evaluated():
    out = not_evaluated("restApiTokenExpiryEnforced", token_body(True, True))
    assert "480" not in reason_of(out)
    not_evaluated("restApiTokenExpiryEnforced", token_body(True, "1440"))


def test_token_expiry_missing_ceiling_is_not_evaluated():
    out = not_evaluated("restApiTokenExpiryEnforced", token_body(True, None))
    assert "480" not in reason_of(out)


def test_token_expiry_programmatic_access_disabled_is_not_evaluated():
    out = not_evaluated("restApiTokenExpiryEnforced", token_body(False, 1440))
    assert "480" not in reason_of(out)


def test_token_expiry_survives_the_integration_wrapper():
    out = not_evaluated("restApiTokenExpiryEnforced", {"apiResponse": token_body(True, 480)})
    assert out["additionalInfo"]["transformation"]["inputSummary"]["maxExpiryTime"] == 480


# --- each key reads only what it protects ----------------------------------------------

def test_a_rulestack_body_never_answers_the_logging_or_token_keys():
    body = rulestack_body()
    not_evaluated("firewallLoggingEnabled", body)
    not_evaluated("restApiTokenExpiryEnforced", body)
    not_evaluated("hasCertificatesManagedExternally", body)


def test_a_log_body_never_answers_a_rulestack_key():
    body = log_body()
    for key in RULESTACK_KEYS:
        not_evaluated(key, body)


def test_the_poisoned_body_that_raises_on_every_read_is_not_evaluated():
    class Boom(dict):
        def get(self, *a, **k):
            raise RuntimeError("boom")

        def __getitem__(self, k):
            raise RuntimeError("boom")

        def __contains__(self, k):
            raise RuntimeError("boom")

        def items(self):
            raise RuntimeError("boom")

        def keys(self):
            raise RuntimeError("boom")

        def __iter__(self):
            raise RuntimeError("boom")

    for key in KEYS:
        out = load(key).transform(Boom())
        assert out["transformedResponse"][key] is None
        assert out["additionalInfo"]["dataCollection"]["status"] == "error"
