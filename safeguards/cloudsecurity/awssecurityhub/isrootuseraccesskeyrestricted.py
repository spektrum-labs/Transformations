"""
Transformation: isRootUserAccessKeyRestricted
Vendor: AWS (Security Hub connection, IAM read)  |  Category: Cloud Security

CLAIM. The AWS account's root user has no active access keys.

RULE. True only when a body that reads the root user's keys shows none active:

  1. IAM credential report (GetCredentialReport; preferred). The `<root_account>` row must
     carry access_key_1_active and access_key_2_active, each "true" or "false". True when both
     are "false"; False when either is "true".
     https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html
  2. IAM account summary (GetAccountSummary). SummaryMap.AccountAccessKeysPresent 0 -> True,
     1 -> False. https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html
  3. Security Hub findings (method getSecurityHubComplianceAWS, AWS Foundational Security Best
     Practices). Control IAM.4 "IAM root user access key should not exist": every active IAM.4
     finding PASSED -> True; any FAILED -> False. This needs no permission beyond the Security
     Hub read the connection already holds.
     https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-4

When more than one source is present the first in that order decides.

FAIL CLOSED. An empty body, an AWS or Integration-Service error, a report with no root row, a
root row missing either key column or holding any other value, a summary without the key, and
a findings list with no PASSED/FAILED IAM.4 finding all return None with
additionalInfo.dataCollection.status "error" (not evaluated). None of them is a pass.

Integration-Service parses the IAM Query API's XML, so the report arrives as
GetCredentialReportResponse.GetCredentialReportResult.Content (base64 CSV) and the summary as
SummaryMap.entry [{key, value}]. JSON-protocol shapes (Content as text or base64, SummaryMap as
a flat object) are read too. base64 is decoded by hand: the sandbox cannot import base64.
"""

import json
from datetime import datetime

CRITERIA_KEY = "isRootUserAccessKeyRestricted"
TRANSFORM_ID = "isrootuseraccesskeyrestricted"
SH_CONTROL = "IAM.4"
B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
WRAPPERS = ["api_response", "response", "result", "apiResponse", "Output", "data"]


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {"status": validation.get("status", "unknown"),
                           "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if transform_err_list else "success",
                               "errors": transform_err_list, "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [],
                           "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": TRANSFORM_ID, "vendor": "AWS",
                         "category": "Cloud Security"},
        },
    }


def not_evaluated(reason, summary=None):
    return create_response(result={CRITERIA_KEY: None}, api_errors=[reason],
                           fail_reasons=["Not evaluated: " + reason],
                           input_summary=summary or {})


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        return json.loads(text)
    return value


def error_reason(data):
    """A reason when the body is an AWS or Integration-Service error, else None."""
    if not isinstance(data, dict):
        return None
    if data.get("error") is True:
        return "Integration-Service returned an error: " + str(data.get("message") or "")[:200]
    if data.get("__type"):
        return "AWS error " + str(data.get("__type"))[:200]
    err = data.get("ErrorResponse")
    if isinstance(err, dict):
        inner = err.get("Error")
        code = inner.get("Code") if isinstance(inner, dict) else inner
        return "AWS error " + str(code)[:200]
    if isinstance(data.get("Error"), dict) and data["Error"].get("Code"):
        return "AWS error " + str(data["Error"].get("Code"))[:200]
    if isinstance(data.get("error"), (dict, str)) and data.get("error"):
        return "error body: " + json.dumps(data.get("error"))[:200]
    for key in ("statusCode", "status_code", "httpStatus"):
        code = data.get(key)
        if isinstance(code, int) and code >= 400:
            return "HTTP " + str(code)
    return None


def find_key(data, wanted, depth):
    """Breadth-limited search for the first dict holding `wanted`; returns that dict."""
    if depth < 0:
        return None
    if isinstance(data, dict):
        if wanted in data:
            return data
        for value in data.values():
            if isinstance(value, (dict, list)):
                hit = find_key(value, wanted, depth - 1)
                if hit is not None:
                    return hit
    elif isinstance(data, list):
        for value in data[:50]:
            if isinstance(value, (dict, list)):
                hit = find_key(value, wanted, depth - 1)
                if hit is not None:
                    return hit
    return None


def b64_decode_prefix(text, limit):
    """Decode at most `limit` base64 characters (rounded down to a multiple of 4)."""
    clean = "".join([c for c in text if c not in "\r\n\t "])
    if len(clean) % 4 != 0:
        raise ValueError("credential report Content is not valid base64")
    end = len(clean) if limit is None or limit >= len(clean) else limit - (limit % 4)
    out = []
    for i in range(0, end, 4):
        chunk = clean[i:i + 4]
        pad = chunk.count("=")
        vals = []
        for c in chunk:
            if c == "=":
                vals.append(0)
            else:
                pos = B64_ALPHABET.find(c)
                if pos < 0:
                    raise ValueError("credential report Content is not valid base64")
                vals.append(pos)
        n = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3]
        triple = [(n >> 16) & 255, (n >> 8) & 255, n & 255]
        out.extend(triple[:3 - pad])
    return bytes(out).decode("utf-8", "ignore"), end >= len(clean)


def root_row_from_csv(text):
    """(header list, root row dict) or raises ValueError; None row when absent."""
    lines = [ln for ln in text.replace("\r\n", "\n").split("\n")]
    if not lines or not lines[0].startswith("user,"):
        raise ValueError("credential report has no CSV header")
    header = lines[0].split(",")
    for line in lines[1:]:
        if line.startswith("<root_account>,"):
            values = line.split(",")
            if len(values) != len(header):
                raise ValueError("root row is incomplete (" + str(len(values)) + " of "
                                 + str(len(header)) + " columns)")
            return header, dict(zip(header, values))
    return header, None


def report_text(holder):
    """Decoded CSV from a dict that carries Content; decodes only what it needs."""
    content = holder.get("Content")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("credential report Content is empty")
    stripped = content.strip()
    if stripped.startswith("user,"):
        return stripped
    limit = 8192
    while True:
        text, complete = b64_decode_prefix(stripped, limit)
        if complete:
            return text
        marker = text.find("<root_account>,")
        if marker >= 0 and text.find("\n", marker) >= 0:
            return text[:text.find("\n", marker) + 1]
        limit = limit * 4


def summary_value(holder, name):
    smap = holder.get("SummaryMap")
    if isinstance(smap, dict) and "entry" in smap:
        entries = smap.get("entry")
        if isinstance(entries, dict):
            entries = [entries]
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict) and entry.get("key") == name:
                    return entry.get("value")
        return None
    if isinstance(smap, dict):
        return smap.get(name)
    return None


def findings_list(data):
    holder = find_key(data, "Findings", 6)
    if holder is not None and isinstance(holder.get("Findings"), list):
        return holder["Findings"]
    if isinstance(data, list) and data and isinstance(data[0], dict) and "Compliance" in data[0]:
        return data
    return None


def evaluate_report(holder):
    text = report_text(holder)
    header, row = root_row_from_csv(text)
    if row is None:
        return None, "credential report has no <root_account> row", {}
    k1 = str(row.get("access_key_1_active", "")).strip().lower()
    k2 = str(row.get("access_key_2_active", "")).strip().lower()
    summary = {"source": "credentialReport", "accessKey1Active": k1, "accessKey2Active": k2,
               "generatedTime": holder.get("GeneratedTime")}
    if k1 not in ("true", "false") or k2 not in ("true", "false"):
        return None, "root row access-key columns are not true/false", summary
    return (k1 == "false" and k2 == "false"), None, summary


def evaluate_summary(holder):
    raw = summary_value(holder, "AccountAccessKeysPresent")
    summary = {"source": "accountSummary", "AccountAccessKeysPresent": raw}
    if str(raw).strip() in ("0", "0.0"):
        return True, None, summary
    if str(raw).strip() in ("1", "1.0"):
        return False, None, summary
    return None, "account summary has no AccountAccessKeysPresent value", summary


def evaluate_findings(findings):
    statuses = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        comp = f.get("Compliance") if isinstance(f.get("Compliance"), dict) else {}
        if comp.get("SecurityControlId") != SH_CONTROL:
            continue
        status = str(comp.get("Status") or "").upper()
        if status in ("PASSED", "FAILED"):
            statuses.append(status)
    summary = {"source": "securityHub", "control": SH_CONTROL, "findings": len(statuses),
               "failed": len([s for s in statuses if s == "FAILED"])}
    if not statuses:
        return None, "no PASSED or FAILED Security Hub finding for control " + SH_CONTROL, summary
    return ("FAILED" not in statuses), None, summary


def transform(input):
    try:
        data = parse(input)
        if isinstance(data, dict) and "data" in data and "validation" in data:
            data = data["data"]
        if data is None or data == {} or data == []:
            return not_evaluated("empty response: nothing about the root user was read")
        reason = error_reason(data)
        if reason:
            return not_evaluated(reason)

        verdict, why, summary = None, None, {}
        report = find_key(data, "Content", 6)
        account = find_key(data, "SummaryMap", 6)
        findings = findings_list(data)
        if report is not None:
            verdict, why, summary = evaluate_report(report)
        elif account is not None:
            verdict, why, summary = evaluate_summary(account)
        elif findings is not None:
            verdict, why, summary = evaluate_findings(findings)
        else:
            inner_error = None
            if isinstance(data, dict):
                for value in data.values():
                    inner_error = inner_error or error_reason(value)
            return not_evaluated(inner_error or "no credential report, account summary or "
                                 "Security Hub findings in the response")

        if verdict is None:
            return not_evaluated(why, summary)
        if verdict:
            return create_response(
                result={CRITERIA_KEY: True}, input_summary=summary,
                pass_reasons=["The root user has no active access keys (" + summary.get("source", "") + ")"])
        return create_response(
            result={CRITERIA_KEY: False}, input_summary=summary,
            fail_reasons=["The root user has at least one active access key (" + summary.get("source", "") + ")"],
            recommendations=["Delete the root user's access keys (IAM > Security credentials, signed in "
                             "as root) and use IAM roles or IAM Identity Center for programmatic access"])
    except Exception as error:
        return create_response(result={CRITERIA_KEY: None}, transformation_errors=[str(error)],
                               api_errors=["transformation error: " + str(error)[:200]],
                               fail_reasons=["Not evaluated: " + str(error)[:200]])
