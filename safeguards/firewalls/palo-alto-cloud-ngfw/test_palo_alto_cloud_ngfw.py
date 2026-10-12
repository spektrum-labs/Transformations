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
                   {"LogType": "THREAT", "LogDestinationType": "S3", "LogDestination": "logs-bucket"}]
    return ok({"FirewallName": name, "LogDestinationConfigs": configs})


def log_body(profiles_list=None):
    profiles_list = profiles_list if profiles_list is not None else [logprofile()]
    return {"firewallList": ok({"Firewalls": [{"FirewallName": "fw-a"}]}), "logProfiles": profiles_list}


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

def test_ips_true_when_every_bound_rulestack_runs_a_vulnerability_profile():
    assert run("ipsEnabled", rulestack_body()) is True


def test_ips_true_for_a_custom_profile_and_for_a_json_string_body_inside_the_wrapper():
    body = {"response": rulestack_body(stacks=[rulestack("rs-a", profiles(vuln="custom"))])}
    assert run("ipsEnabled", json.dumps(body)) is True


def test_ips_false_when_the_vulnerability_profile_is_none():
    assert run("ipsEnabled", rulestack_body(stacks=[rulestack("rs-a", profiles(vuln="None"))])) is False


def test_ips_false_when_one_of_two_rulestacks_lacks_it():
    body = rulestack_body(fws=[firewall("fw-a", "rs-a"), firewall("fw-b", "rs-b")],
                          stacks=[rulestack("rs-a", profiles()), rulestack("rs-b", profiles(vuln="None"))],
                          running_names=["rs-a", "rs-b"])
    assert run("ipsEnabled", body) is False


def test_ips_two_firewalls_sharing_one_rulestack_count_once():
    body = rulestack_body(fws=[firewall("fw-a"), firewall("fw-b")])
    out = full("ipsEnabled", body)
    assert out["transformedResponse"]["ipsEnabled"] is True
    assert out["additionalInfo"]["transformation"]["inputSummary"]["rulestacks"] == 1


def test_ips_global_rulestack_binding_is_read_by_its_name():
    body = rulestack_body(fws=[firewall("fw-a", rulestack="", global_rulestack="gs-1")],
                          stacks=[rulestack("gs-1", profiles())], running_names=["gs-1"])
    assert run("ipsEnabled", body) is True


def test_ips_a_bound_rulestack_with_no_describe_record_is_not_evaluated():
    body = rulestack_body(fws=[firewall("fw-a", "rs-zzz")])
    not_evaluated("ipsEnabled", body)


def test_ips_candidate_only_rulestack_is_not_a_pass():
    # a rulestack that was never committed has no running configuration: nothing is enforced yet
    body = rulestack_body(stacks=[ok({"RuleStackName": "rs-a", "RuleStackState": "Uncommitted",
                                      "RuleStackCandidate": {"Profiles": profiles()}})])
    not_evaluated("ipsEnabled", body)


def test_ips_unrecognised_profile_value_is_not_evaluated():
    not_evaluated("ipsEnabled", rulestack_body(stacks=[rulestack("rs-a", profiles(vuln="Strict"))]))


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


def test_url_filtering_does_not_answer_from_the_ips_profile():
    p = profiles(vuln="BestPractice")
    del p["URLFilteringProfile"]
    not_evaluated("isURLFilteringProfileEnabled", rulestack_body(stacks=[rulestack("rs-a", p)]))


def test_url_filtering_unrecognised_value_is_not_evaluated():
    not_evaluated("isURLFilteringProfileEnabled",
                  rulestack_body(stacks=[rulestack("rs-a", profiles(url="Maybe"))]))


# --- sslDeepInspectionEnabled -----------------------------------------------------------

def test_ssl_inspection_true_with_an_outbound_trust_certificate():
    assert run("sslDeepInspectionEnabled", rulestack_body()) is True


def test_ssl_inspection_false_when_no_outbound_trust_certificate_is_set():
    body = rulestack_body(stacks=[rulestack("rs-a", profiles(trust=None))])
    assert run("sslDeepInspectionEnabled", body) is False


def test_ssl_inspection_false_when_the_certificate_name_is_blank():
    body = rulestack_body(stacks=[rulestack("rs-a", profiles(trust="  "))])
    assert run("sslDeepInspectionEnabled", body) is False


def test_ssl_inspection_empty_profiles_object_is_not_evaluated():
    body = rulestack_body(stacks=[rulestack("rs-a", {})])
    not_evaluated("sslDeepInspectionEnabled", body)


def test_ssl_inspection_false_if_one_of_two_rulestacks_has_no_certificate():
    body = rulestack_body(fws=[firewall("fw-a", "rs-a"), firewall("fw-b", "rs-b")],
                          stacks=[rulestack("rs-a", profiles()), rulestack("rs-b", profiles(trust=None))],
                          running_names=["rs-a", "rs-b"])
    assert run("sslDeepInspectionEnabled", body) is False


# --- isRulestackCommitClean -----------------------------------------------------------

def test_commit_clean_true_when_no_bound_rulestack_is_uncommitted():
    assert run("isRulestackCommitClean", rulestack_body()) is True


def test_commit_clean_false_when_a_bound_rulestack_has_pending_changes():
    body = rulestack_body(uncommitted=[{"RuleStackName": "rs-a", "Operation": "update"}])
    assert run("isRulestackCommitClean", body) is False


def test_commit_clean_ignores_an_uncommitted_rulestack_no_firewall_uses():
    body = rulestack_body(uncommitted=[{"RuleStackName": "draft-unused", "Operation": "add"}])
    assert run("isRulestackCommitClean", body) is True


def test_commit_clean_without_the_uncommitted_list_is_not_evaluated():
    body = rulestack_body()
    del body["rulestackList"]["Response"]["RuleStackUncommitted"]
    not_evaluated("isRulestackCommitClean", body)


def test_commit_clean_truncated_rulestack_list_is_not_evaluated():
    body = rulestack_body()
    body["rulestackList"]["Response"]["NextToken"] = "abc123"
    not_evaluated("isRulestackCommitClean", body)


def test_commit_clean_no_firewalls_is_not_evaluated():
    not_evaluated("isRulestackCommitClean", rulestack_body(fws=[]))


def test_commit_clean_does_not_need_the_describe_records():
    body = rulestack_body(stacks=[])
    assert run("isRulestackCommitClean", body) is True


# --- firewallLoggingEnabled -------------------------------------------------------------

def test_logging_true_when_traffic_and_threat_logs_have_a_destination():
    assert run("firewallLoggingEnabled", log_body()) is True


def test_logging_false_when_the_log_profile_has_no_destinations():
    assert run("firewallLoggingEnabled", log_body([logprofile(configs=[])])) is False


def test_logging_false_when_threat_logs_have_no_destination():
    configs = [{"LogType": "TRAFFIC", "LogDestinationType": "S3", "LogDestination": "b"}]
    assert run("firewallLoggingEnabled", log_body([logprofile(configs=configs)])) is False


def test_logging_blank_destination_does_not_count():
    configs = [{"LogType": "TRAFFIC", "LogDestinationType": "S3", "LogDestination": ""},
               {"LogType": "THREAT", "LogDestinationType": "S3", "LogDestination": "b"}]
    assert run("firewallLoggingEnabled", log_body([logprofile(configs=configs)])) is False


def test_logging_false_if_one_of_two_firewalls_is_not_logging():
    body = log_body([logprofile("fw-a"), logprofile("fw-b", configs=[])])
    assert run("firewallLoggingEnabled", body) is False


def test_logging_decryption_logs_are_not_required():
    # the bundle's decryption logs only matter where decryption is on; traffic + threat decide
    assert run("firewallLoggingEnabled", log_body([logprofile()])) is True


def test_logging_log_profile_with_no_readable_fields_is_not_evaluated():
    not_evaluated("firewallLoggingEnabled", log_body([ok({})]))


def test_logging_item_error_is_not_evaluated():
    not_evaluated("firewallLoggingEnabled", log_body([{"error": True, "statusCode": 403, "item": "fw-a"}]))


def test_logging_no_firewalls_is_not_evaluated():
    not_evaluated("firewallLoggingEnabled", log_body([]))


def test_logging_one_firewall_unreadable_and_one_off_is_false_but_unreadable_alone_is_not_evaluated():
    mixed = log_body([logprofile("fw-a", configs=[]), {"error": True, "statusCode": 500, "item": "fw-b"}])
    assert run("firewallLoggingEnabled", mixed) is False
    mixed_ok = log_body([logprofile("fw-a"), {"error": True, "statusCode": 500, "item": "fw-b"}])
    not_evaluated("firewallLoggingEnabled", mixed_ok)


# --- hasCertificatesManagedExternally ---------------------------------------------------

def test_certificates_true_when_every_certificate_signer_is_a_secrets_manager_secret():
    assert run("hasCertificatesManagedExternally", cert_body()) is True


def test_certificates_true_in_a_govcloud_partition():
    arn = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:ca-XyZ"
    assert run("hasCertificatesManagedExternally", cert_body([cert(arn)])) is True


def test_certificates_false_when_a_certificate_is_referenced_from_another_store():
    arn = "arn:aws:acm:us-east-1:111122223333:certificate/abcd"
    assert run("hasCertificatesManagedExternally", cert_body([cert(arn)])) is False


def test_certificates_false_when_a_certificate_has_no_signer_arn():
    c = ok({"Name": "c", "RuleStackName": "rs-a", "CertificateObjectRunning": {"CertificateSelfSigned": True}})
    assert run("hasCertificatesManagedExternally", cert_body([c])) is False


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


# --- restApiTokenExpiryEnforced ---------------------------------------------------------

def test_token_expiry_true_when_the_tenant_ceiling_is_a_bounded_number():
    assert run("restApiTokenExpiryEnforced", token_body(True, 480)) is True
    assert run("restApiTokenExpiryEnforced", token_body(True, 1440)) is True


def test_token_expiry_false_when_the_ceiling_is_beyond_the_documented_maximum():
    assert run("restApiTokenExpiryEnforced", token_body(True, 100000)) is False


def test_token_expiry_false_when_the_ceiling_is_zero_or_negative():
    assert run("restApiTokenExpiryEnforced", token_body(True, 0)) is False
    assert run("restApiTokenExpiryEnforced", token_body(True, -5)) is False


def test_token_expiry_a_bool_or_text_ceiling_is_not_evaluated():
    not_evaluated("restApiTokenExpiryEnforced", token_body(True, True))
    not_evaluated("restApiTokenExpiryEnforced", token_body(True, "1440"))


def test_token_expiry_missing_ceiling_is_not_evaluated():
    not_evaluated("restApiTokenExpiryEnforced", token_body(True, None))


def test_token_expiry_programmatic_access_disabled_is_not_evaluated():
    not_evaluated("restApiTokenExpiryEnforced", token_body(False, 1440))


def test_token_expiry_survives_the_integration_wrapper():
    assert run("restApiTokenExpiryEnforced", {"apiResponse": token_body(True, 480)}) is True


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
