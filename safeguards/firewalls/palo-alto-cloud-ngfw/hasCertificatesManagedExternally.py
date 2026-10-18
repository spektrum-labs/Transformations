"""
Transformation: hasCertificatesManagedExternally
Vendor: Palo Alto Networks Cloud NGFW (AWS)  |  Category: Firewalls

Integration-Service workflow getNgfwDecryptionCertificates, leg used:
  certificates <- describeCertificate: GET /v1/config/rulestacks/{rulestack}/certificates/{name},
                  once per running rulestack, for the rulestack's outbound trust certificate

Value: True when every certificate object read has a running CertificateSignerArn that is an
AWS Secrets Manager secret (arn:<partition>:secretsmanager:<region>:<account>:secret:<name>); False
when one is a well-formed ARN of another AWS service that holds certificates or key material
(acm, acm-pca, iam, kms, s3, ssm). The reference types the field only as "Certificate signer ARN"
and says certificate objects are stored in AWS Secrets Manager. Any value that is not a well-formed
AWS ARN of one of those services (free text, a URL, a malformed or unknown-service ARN, a Secrets
Manager ARN that is not a secret, or that has an empty region or account) is not recognised and is null, never False. The certificate read
is the rulestack's outbound trust certificate, so the answer speaks for that certificate, not for
every certificate in the account.

Fail closed (Not evaluated, never a pass): a refused (401/403), expired-token, error-shaped, empty,
unrecognised or possibly cut-off read, a failed per-certificate read, a certificate object with no
running configuration, a running configuration with no CertificateSignerArn (the field is optional
in every certificate answer, and the reference does not say absent means "held elsewhere"), a signer
that is not a recognised ARN (above), or no certificate configured at all (nothing was measured) is
null. One recognised non-Secrets-Manager signer still makes the answer False when another signer is
unrecognised.

Source: public OpenAPI reference for Cloud NGFW for AWS (pan.dev, ManageCertificateObjects).
"""

import json
import re
from datetime import datetime, timezone

VENDOR = "Palo Alto Networks Cloud NGFW"
CATEGORY = "Firewalls"
WRAPPERS = ("data", "response", "result", "apiResponse", "Output")


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value) if value.strip() else None
    return value


def unwrap(data, keys):
    """The first dict (under the usual Integration-Service wrappers) that carries one of keys."""
    for depth in range(6):
        if not isinstance(data, dict):
            return None
        for key in keys:
            if key in data:
                return data
        nxt = None
        for key in WRAPPERS:
            if isinstance(data.get(key), dict):
                nxt = data[key]
                break
        if nxt is None:
            return None
        data = nxt
    return None


def error_text(body):
    """Why a body is an error, or None."""
    if not isinstance(body, dict):
        return None
    if body.get("error") is True or body.get("errorType"):
        return "Integration-Service error " + str(body.get("statusCode") or "") + ": " + str(
            body.get("message") or body.get("errorMessage") or "")[:200]
    code = body.get("statusCode")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "HTTP " + str(code)
    if body.get("message") and "Response" not in body:
        return "vendor error: " + str(body.get("message"))[:200]
    return None


def response_problem(resp, label):
    """Why one vendor answer cannot be read, or None. Every answer is
    {"Response": {...}, "ResponseStatus": {"ErrorCode": 0}}; any other ErrorCode is a failure."""
    if not isinstance(resp, dict):
        return label + ": the response is not an object"
    text = error_text(resp)
    if text:
        return label + ": " + text
    status = resp.get("ResponseStatus")
    if isinstance(status, dict):
        code = status.get("ErrorCode")
        if code is not None and str(code).strip() not in ("0", ""):
            return label + ": vendor error " + str(code) + " " + str(status.get("Reason") or "")[:120]
    if not isinstance(resp.get("Response"), dict):
        return label + ": no Response object in the answer"
    return None


def build_response(result, pass_reasons=None, fail_reasons=None, errors=None, summary=None,
                   recommendations=None, transform_id=""):
    errors = errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": errors},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors,
                               "inputSummary": summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "1.0",
                         "transformationId": transform_id, "vendor": VENDOR, "category": CATEGORY},
        },
    }


def text_of(value):
    return value.strip() if isinstance(value, str) else ""


def top_problem(top, label):
    """A cut-off or partly failed fan-out is never a smaller estate."""
    if top.get("iterateTruncated"):
        return label + ": more items exist than were read"
    count = top.get("itemErrors")
    if isinstance(count, int) and not isinstance(count, bool) and count > 0:
        return label + ": " + str(count) + " item read(s) failed"
    return None


def list_problem(listing, label):
    """One page of a vendor list: refused, unreadable, or with a NextToken (more behind it)."""
    problem = response_problem(listing, label)
    if problem:
        return problem
    if listing["Response"].get("NextToken"):
        return label + ": the list has more pages than were read"
    return None


KEY = "hasCertificatesManagedExternally"

# AWS services that hold certificates or key material; an ARN of one of these that is not Secrets
# Manager is a recognised "held somewhere else". Any other service name is not recognised.
OTHER_STORE_SERVICES = ("acm", "acm-pca", "iam", "kms", "s3", "ssm")
PARTITION = re.compile(r"aws(-[a-z]+)*")
SERVICE = re.compile(r"[a-z0-9-]+")
ACCOUNT = re.compile(r"[0-9]{12}")


def arn_service(text):
    """(service, resource, region, account) when text is a well-formed AWS ARN (arn:partition:service:
    region:account:resource, no whitespace anywhere), else None. Region and account may be empty
    here (an S3 ARN has neither); the Secrets Manager check requires both."""
    if not text or any(ch in text for ch in " \t\r\n"):
        return None
    parts = text.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or not PARTITION.fullmatch(parts[1]):
        return None
    service, region, account, resource = parts[2], parts[3], parts[4], parts[5]
    if not SERVICE.fullmatch(service) or (region and not SERVICE.fullmatch(region)):
        return None
    if account and not ACCOUNT.fullmatch(account):
        return None
    if not resource:
        return None
    return service, resource, region, account


def judge(resp):
    problem = response_problem(resp, "certificate read")
    if problem:
        return None, problem
    data = resp["Response"]
    running = data.get("CertificateObjectRunning")
    name = text_of(data.get("Name")) or "a certificate"
    if not isinstance(running, dict):
        return None, "certificate " + name + ": no running configuration was returned"
    arn = text_of(running.get("CertificateSignerArn"))
    if not arn:
        return None, ("certificate " + name + ": the running configuration returned no CertificateSignerArn, "
                      "and the reference does not say that means it is held outside a secrets manager")
    found = arn_service(arn)
    if found is not None:
        service, resource, region, account = found
        if service == "secretsmanager":
            # A real secret ARN carries both a region and an account; with either one empty it is not
            # shown to be Secrets Manager, so it never counts as True.
            if region and account and resource.startswith("secret:") and len(resource) > len("secret:"):
                return True, ""
        elif service in OTHER_STORE_SERVICES:
            return False, ("certificate " + name + ": signer is an AWS " + service
                           + " resource, not an AWS Secrets Manager secret")
    return None, ("certificate " + name + ": the CertificateSignerArn is not a recognised AWS ARN for Secrets "
                  "Manager or another AWS certificate store, so it is not shown whether the certificate is held "
                  "in a secrets manager")


def transform(input):
    try:
        data = parse(input)
        top = unwrap(data, ("certificates",))
        if top is None:
            return build_response({KEY: None}, errors=[error_text(data) or "no certificates in the response"],
                                  transform_id=KEY)
        problem = top_problem(top, "certificates")
        if problem:
            return build_response({KEY: None}, errors=[problem], transform_id=KEY)
        certs = top.get("certificates")
        if not isinstance(certs, list) or not certs:
            return build_response({KEY: None}, errors=[
                "certificates: no decryption certificate is configured, so nothing was measured"],
                transform_id=KEY)
        results = [judge(resp) for resp in certs]
        off = [reason for flag, reason in results if flag is False]
        unread = [reason for flag, reason in results if flag is None]
        summary = {"certificates": len(certs), "notExternal": len(off), "unreadable": len(unread)}
        if off:
            return build_response({KEY: False}, fail_reasons=off, summary=summary,
                                  recommendations=["Reference each decryption certificate from AWS Secrets Manager."],
                                  transform_id=KEY)
        if unread:
            return build_response({KEY: None}, errors=unread[:5], summary=summary, transform_id=KEY)
        return build_response({KEY: True}, pass_reasons=[
            str(len(certs)) + " decryption certificate(s) are AWS Secrets Manager secrets"],
            summary=summary, transform_id=KEY)
    except Exception as error:
        return build_response({KEY: None}, errors=[str(error)[:300]], transform_id=KEY)
