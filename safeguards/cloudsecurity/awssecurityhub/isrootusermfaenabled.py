"""
Transformation: isRootUserMFAEnabled
Vendor: AWS (Security Hub connection, IAM read)  |  Category: Cloud Security

CLAIM. The AWS account's root user has MFA enabled AND has not been used to sign in to the
console within the last 90 days (it is not an everyday identity).

RULE. Read from the IAM credential report (GetCredentialReport), `<root_account>` row:
  * mfa_active must be "true"; "false" fails.
  * password_last_used is the root user's last console sign-in. "N/A" (never signed in) and
    "no_information" (no sign-in since IAM began tracking, Oct 2014) count as not used. An ISO
    8601 timestamp fails when it is within 90 days of the report's GeneratedTime (the clock the
    report was taken at; the evaluation clock only when GeneratedTime is absent). The window is
    inclusive: a sign-in exactly 90 days before is still a use.
  * Root access-key use is NOT judged here: any active root key already fails
    isRootUserAccessKeyRestricted. The last-used dates are reported as findings.
  https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html

The IAM account summary (GetAccountSummary) can only fail this claim: AccountMFAEnabled 0 is a
definite False, but it carries no sign-in history, so AccountMFAEnabled 1 alone is not
evaluated (None) rather than a pass.

FAIL CLOSED. An empty body, an AWS or Integration-Service error, a report with no root row or
an incomplete one, mfa_active or password_last_used in any unrecognised form, and a summary
without the key all return None with additionalInfo.dataCollection.status "error" (not
evaluated). None of them is a pass.

Integration-Service parses the IAM Query API's XML, so the report arrives as
GetCredentialReportResponse.GetCredentialReportResult.Content (base64 CSV) with GeneratedTime
beside it. base64 is decoded by hand: the sandbox cannot import base64.
"""

import json
from datetime import datetime, timedelta

CRITERIA_KEY = "isRootUserMFAEnabled"
TRANSFORM_ID = "isrootusermfaenabled"
WINDOW_DAYS = 90
NOT_USED = ("n/a", "no_information")
B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


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


def parse_time(value):
    """ISO 8601 (credential report / GeneratedTime) to a naive UTC datetime, or None."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if len(text) < 19 or text[4] != "-" or text[7] != "-" or text[10] not in ("T", " "):
        return None
    try:
        year, month, day = int(text[0:4]), int(text[5:7]), int(text[8:10])
        hour, minute, second = int(text[11:13]), int(text[14:16]), int(text[17:19])
        moment = datetime(year, month, day, hour, minute, second)
    except ValueError:
        return None
    rest = text[19:]
    if "." in rest[:1]:
        cut = 1
        while cut < len(rest) and rest[cut].isdigit():
            cut = cut + 1
        rest = rest[cut:]
    if rest in ("", "Z", "z", "+00:00", "-00:00", "+0000"):
        return moment
    if len(rest) == 6 and rest[0] in ("+", "-") and rest[3] == ":":
        try:
            offset = timedelta(hours=int(rest[1:3]), minutes=int(rest[4:6]))
        except ValueError:
            return None
        return moment - offset if rest[0] == "+" else moment + offset
    return None


def evaluate_report(holder):
    text = report_text(holder)
    header, row = root_row_from_csv(text)
    if row is None:
        return None, "credential report has no <root_account> row", {}, []
    mfa = str(row.get("mfa_active", "")).strip().lower()
    last_used_raw = str(row.get("password_last_used", "")).strip()
    generated_raw = holder.get("GeneratedTime")
    reference = parse_time(generated_raw) if generated_raw else None
    clock = "report GeneratedTime"
    if reference is None:
        if generated_raw:
            return None, "GeneratedTime is not a timestamp: " + str(generated_raw)[:40], {}, []
        reference = datetime.utcnow()
        clock = "evaluation time"
    summary = {"source": "credentialReport", "mfaActive": mfa, "passwordLastUsed": last_used_raw,
               "generatedTime": generated_raw, "windowDays": WINDOW_DAYS}
    findings = []
    for n in ("1", "2"):
        used = str(row.get("access_key_" + n + "_last_used_date", "")).strip()
        if used and used.lower() not in NOT_USED:
            findings.append("root access key " + n + " last used " + used)
    if mfa not in ("true", "false"):
        return None, "root row mfa_active is not true/false", summary, findings
    if mfa == "false":
        return False, "MFA is not enabled on the root user", summary, findings
    if last_used_raw.lower() in NOT_USED:
        return True, "root MFA is enabled and the root user has no recorded console sign-in", summary, findings
    last_used = parse_time(last_used_raw)
    if last_used is None:
        return None, "root password_last_used is not a timestamp: " + last_used_raw[:40], summary, findings
    age_days = (reference - last_used).days
    summary["daysSinceRootSignIn"] = age_days
    if last_used >= reference - timedelta(days=WINDOW_DAYS):
        return False, ("the root user signed in " + str(age_days) + " day(s) before the "
                       + clock + ", inside the " + str(WINDOW_DAYS) + "-day window"), summary, findings
    return True, ("root MFA is enabled and the last root sign-in was " + str(age_days)
                  + " day(s) before the " + clock), summary, findings


def evaluate_summary(holder):
    raw = summary_value(holder, "AccountMFAEnabled")
    summary = {"source": "accountSummary", "AccountMFAEnabled": raw}
    if str(raw).strip() in ("0", "0.0"):
        return False, "MFA is not enabled on the root user (AccountMFAEnabled 0)", summary, []
    if str(raw).strip() in ("1", "1.0"):
        return None, ("root MFA is enabled, but the account summary carries no sign-in history, so "
                      "the 90-day root-use half of the claim cannot be read; use the credential report"), summary, []
    return None, "account summary has no AccountMFAEnabled value", summary, []


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

        report = find_key(data, "Content", 6)
        account = find_key(data, "SummaryMap", 6)
        if report is not None:
            verdict, why, summary, findings = evaluate_report(report)
        elif account is not None:
            verdict, why, summary, findings = evaluate_summary(account)
        else:
            inner_error = None
            if isinstance(data, dict):
                for value in data.values():
                    inner_error = inner_error or error_reason(value)
            return not_evaluated(inner_error or "no credential report or account summary in the response")

        if verdict is None:
            return not_evaluated(why, summary)
        if verdict:
            return create_response(result={CRITERIA_KEY: True}, input_summary=summary,
                                   pass_reasons=[why], additional_findings=findings)
        return create_response(
            result={CRITERIA_KEY: False}, input_summary=summary, fail_reasons=[why],
            additional_findings=findings,
            recommendations=["Enable MFA on the root user (a hardware or passkey device), stop using the "
                             "root user for routine work, and sign in with IAM Identity Center or IAM roles"])
    except Exception as error:
        return create_response(result={CRITERIA_KEY: None}, transformation_errors=[str(error)],
                               api_errors=["transformation error: " + str(error)[:200]],
                               fail_reasons=["Not evaluated: " + str(error)[:200]])
