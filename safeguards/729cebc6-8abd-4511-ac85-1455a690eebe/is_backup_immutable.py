"""
Transformation: isBackupImmutable
Vendor: Microsoft (Azure Backup)
Category: Backup / Data Protection

Input: the Recovery Services and Backup vaults Resource Graph lists for the connected
subscription, with each vault's `properties` projected (Integration-Service workflow
isBackupImmutable -> getBackupVaultLockConfiguration, resultFormat objectArray).

Reads each vault's immutable-vault setting, properties.securitySettings.immutabilitySettings.state:

    Unlocked or Locked   immutability on (Locked can no longer be turned off; Unlocked can)
    Disabled, or no immutabilitySettings in readable vault properties   off
    anything else, or vault properties unreadable                       unknown

    True   every vault read from a complete list has immutability on
    False  at least one vault read has immutability off (each such vault is named)
    null   Not evaluated: an error, an empty list, an unreadable or unrecognised body, or no
           vault off but one unknown or the list truncated (dataCollection.status "error")

Soft delete is not immutability and is not read here. The query's computed isImmutable column
is a soft-delete test, so it is ignored.

Why this was rewritten: this file was a copy of the AWS Backup Vault Lock transform
(BackupVaultLockConfiguration.LockState). On Azure rows it raised, and the error was
reported as a failed control.
"""

import ast
import json
from datetime import datetime, timezone

VAULT_TYPES = ("microsoft.recoveryservices/vaults", "microsoft.dataprotection/backupvaults")
VAULT_ID_MARKERS = ("/providers/microsoft.recoveryservices/vaults/", "/providers/microsoft.dataprotection/backupvaults/")
POLICY_MARKERS = ("/backuppolicies",)
ENVELOPE_KEYS = ("response", "result", "apiResponse", "api_response", "Output", "data", "value")


def parse(value):
    """Decode a JSON (or Python-literal) string; anything else is returned unchanged.

    Token-Service hands a transform typed JSON, but a stored response has every leaf as a
    string, so a nested object can arrive as text. Empty text, "None" and "null" read as
    nothing."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text or text in ("None", "null"):
        return None
    if text[0] not in "{[":
        return value
    try:
        return json.loads(text)
    except ValueError:
        pass
    try:
        return ast.literal_eval(text)
    except (ValueError, SyntaxError):
        return value


def text_of(value):
    value = parse(value)
    if value is None:
        return ""
    return str(value).strip()


def flag_on(value):
    return text_of(value).lower() in ("true", "1", "yes")


def error_text(body):
    """Why this body is an error rather than data, or None."""
    if not isinstance(body, dict):
        return None
    err = parse(body.get("error"))
    if isinstance(err, dict) and err:
        code = text_of(err.get("code") or err.get("statusCode") or err.get("status"))
        message = text_of(err.get("message") or err.get("Message"))
        return ("Azure error " + code + ": " + message)[:240].strip()
    if err not in (None, False, "", "false", "False", "0", 0, [], {}):
        return ("error response: " + text_of(body.get("message") or err))[:240]
    for key in ("errors", "errorMessage", "errorType", "fault", "Message"):
        if parse(body.get(key)) not in (None, "", [], {}):
            return ("error response: " + text_of(body.get(key)))[:240]
    for key in ("statusCode", "status_code", "httpStatus"):
        code = text_of(body.get(key))
        if code.isdigit() and int(code) >= 400:
            return "HTTP " + code + " from the vendor"
    return None


def table_rows(table):
    """Rows of a Resource Graph `table` result as dicts, or None when malformed.

    A single packed column (`project result=pack(...)`) yields the packed object itself."""
    columns = parse(table.get("columns"))
    rows = parse(table.get("rows"))
    if not isinstance(columns, list) or not isinstance(rows, list):
        return None
    names = []
    for column in columns:
        column = parse(column)
        name = column.get("name") if isinstance(column, dict) else column
        if name is None:
            return None
        names.append(str(name))
    out = []
    for row in rows:
        row = parse(row)
        if not isinstance(row, list) or len(row) != len(names):
            return None
        record = {}
        for name, cell in zip(names, row):
            record[name] = parse(cell)
        if len(names) == 1 and isinstance(record.get(names[0]), dict):
            record = record.get(names[0])
        out.append(record)
    return out


def read_rows(payload):
    """(rows, truncated, problem) from a Resource Graph response, however it arrives.

    Production Token-Service drills a legacy transform's input through response, result,
    apiResponse, Output and data, so a Resource Graph body {totalRecords, data: [...]}
    reaches the transform as the bare row list, and a `table` body as {columns, rows}. A
    stored or replayed response arrives undrilled, possibly wrapped by Integration-Service,
    possibly with every leaf a string. All of these read the same. problem is set (and rows
    None) for an error, an unreadable body or an unrecognised shape."""
    body = parse(payload)
    truncated = False
    depth = 0
    while not isinstance(body, list):
        depth = depth + 1
        if depth > 8 or not isinstance(body, dict):
            return None, truncated, "unreadable response (no Resource Graph rows found)"
        problem = error_text(body)
        if problem:
            return None, truncated, problem
        if flag_on(body.get("resultTruncated")) or text_of(body.get("$skipToken")) or text_of(body.get("skipToken")):
            truncated = True
        if "columns" in body and "rows" in body:
            rows = table_rows(body)
            if rows is None:
                return None, truncated, "unreadable Resource Graph table (columns and rows do not match)"
            body = rows
            break
        found = None
        for key in ENVELOPE_KEYS:
            if key in body:
                found = parse(body.get(key))
                break
        if found is None:
            return None, truncated, "unrecognised response shape (no Resource Graph rows found)"
        body = found
    rows = []
    for item in body:
        item = parse(item)
        if not isinstance(item, dict):
            return None, truncated, "unreadable row in the Resource Graph response"
        problem = error_text(item)
        if problem:
            return None, truncated, problem
        rows.append(item)
    return rows, truncated, None


def is_vault(row):
    kind = text_of(row.get("type")).lower()
    ident = text_of(row.get("id")).lower()
    if kind in VAULT_TYPES:
        return True
    return any(marker in ident for marker in VAULT_ID_MARKERS)


def vault_label(row):
    name = text_of(row.get("name")) or "unnamed vault"
    group = text_of(row.get("resourceGroup"))
    return name + (" (resource group " + group + ")" if group else "")


def create_response(criteria_key, value, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, not_evaluated=None, findings=None):
    """The five-section response. not_evaluated (a reason) makes the verdict null with
    dataCollection.status "error", which Token-Service records as Not evaluated."""
    errors = [not_evaluated] if not_evaluated else []
    return {
        "transformedResponse": {criteria_key: None if not_evaluated else value},
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": errors},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": findings or [],
            },
            "metadata": {
                "evaluatedAt": datetime.now(timezone.utc).isoformat(),
                "schemaVersion": "1.0",
                "transformationId": criteria_key,
                "vendor": "Microsoft",
                "category": "Backup",
            },
        },
    }


CRITERIA_KEY = "isBackupImmutable"


def immutability_state(row):
    """("on" | "off" | "unknown", reason) for one vault row."""
    props = parse(row.get("properties"))
    if not isinstance(props, dict) or not props:
        return "unknown", "vault properties were not returned"
    security = parse(props.get("securitySettings"))
    if security is None:
        return "off", "no immutability setting on the vault"
    if not isinstance(security, dict):
        return "unknown", "vault security settings are unreadable"
    settings = parse(security.get("immutabilitySettings"))
    if settings is None:
        return "off", "immutable vault is not configured"
    if not isinstance(settings, dict):
        return "unknown", "immutability settings are unreadable"
    state = text_of(settings.get("state"))
    lowered = state.lower()
    if lowered in ("locked", "unlocked"):
        return "on", "immutable vault " + state
    if lowered == "disabled":
        return "off", "immutable vault Disabled"
    return "unknown", "unrecognised immutability state " + (state or "(empty)")


def transform(input):
    try:
        rows, truncated, problem = read_rows(input)
        if problem:
            return create_response(
                CRITERIA_KEY, None,
                not_evaluated="Backup vaults could not be read: " + problem,
                recommendations=["Confirm the connection's app registration holds the Reader role on the "
                                 "backup subscription, then re-run the evaluation."])
        if not rows:
            return create_response(
                CRITERIA_KEY, None,
                not_evaluated="No Recovery Services or Backup vault was returned for the connected "
                              "subscription, so there is no backup to evaluate.")
        vaults = [row for row in rows if is_vault(row)]
        if not vaults:
            return create_response(
                CRITERIA_KEY, None,
                not_evaluated="The response rows are not recognisable backup vaults (no vault type or resource id).")
        on, off, unknown, findings = [], [], [], []
        for vault in vaults:
            state, reason = immutability_state(vault)
            label = vault_label(vault)
            findings.append(label + ": " + reason)
            if state == "on":
                on.append(label)
            elif state == "off":
                off.append(label + " (" + reason + ")")
            else:
                unknown.append(label + " (" + reason + ")")
        summary = {"vaultCount": len(vaults), "immutableVaults": len(on), "mutableVaults": len(off),
                   "unreadableVaults": len(unknown), "truncated": truncated}
        if off:
            return create_response(
                CRITERIA_KEY, False,
                fail_reasons=["Immutable vault is not enabled on " + str(len(off)) + " of " + str(len(vaults))
                              + " backup vault(s): " + "; ".join(off[:10])],
                recommendations=["Enable immutable vault on each Recovery Services or Backup vault "
                                 "(vault Properties > Immutable vault), then lock it once retention is "
                                 "confirmed. Locking cannot be undone."],
                input_summary=summary, findings=findings[:25])
        if unknown:
            return create_response(
                CRITERIA_KEY, None,
                not_evaluated="Immutability could not be read for " + str(len(unknown)) + " vault(s): "
                              + "; ".join(unknown[:10]),
                input_summary=summary, findings=findings[:25])
        if truncated:
            return create_response(
                CRITERIA_KEY, None,
                not_evaluated="The vault list was truncated, so not every vault was read.",
                input_summary=summary, findings=findings[:25])
        return create_response(
            CRITERIA_KEY, True,
            pass_reasons=["Immutable vault is enabled on all " + str(len(on)) + " backup vault(s): "
                          + ", ".join(on[:10])],
            input_summary=summary, findings=findings[:25])
    except Exception as exc:
        return create_response(CRITERIA_KEY, None, not_evaluated="Transformation error: " + str(exc)[:200])
