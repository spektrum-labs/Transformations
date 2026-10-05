"""
Transformation: isBackupEncrypted
Vendor: Microsoft (Azure Backup)
Category: Backup / Data Protection

Input: the Recovery Services vaults Resource Graph lists for the connected subscription
(Integration-Service workflow isBackupEncrypted -> listVaults, resultFormat objectArray).

Azure Backup encrypts all backup data at rest with platform-managed keys, and that encryption
cannot be turned off; customer-managed keys are an optional addition. So a complete, readable
vault list with at least one vault is the evidence that the vault's backups are encrypted.

    True   at least one backup vault read from a complete list
    null   Not evaluated: an error, an empty list, an unreadable or unrecognised body, or a
           truncated list (dataCollection.status "error" carries the reason)
    False  not reachable from Azure data: the platform has no unencrypted mode

Why this was rewritten: the previous version required the Resource Graph envelope's
totalRecords field. Production Token-Service drills a legacy transform's input through
response / result / apiResponse / Output / data, so the transform receives the bare row list
and never sees totalRecords. Every production evaluation therefore answered False ("no record
count") while a replay of the stored, undrilled body answered True.
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


CRITERIA_KEY = "isBackupEncrypted"


def key_uri(container):
    container = parse(container)
    if not isinstance(container, dict):
        return ""
    key_vault = parse(container.get("keyVaultProperties"))
    if isinstance(key_vault, dict):
        return text_of(key_vault.get("keyUri"))
    return ""


def uses_customer_key(row):
    if text_of(row.get("encryptionMode")).upper() == "CMK" or text_of(row.get("keyUri")):
        return True
    props = parse(row.get("properties"))
    if not isinstance(props, dict):
        return False
    if key_uri(props.get("encryption")):
        return True
    security = parse(props.get("securitySettings"))
    return isinstance(security, dict) and bool(key_uri(security.get("encryptionSettings")))


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
                              "subscription, so there is no backup to evaluate.",
                recommendations=["Confirm the connected subscription is the one that holds the backup vaults."])
        vaults = [row for row in rows if is_vault(row)]
        if not vaults:
            return create_response(
                CRITERIA_KEY, None,
                not_evaluated="The response rows are not recognisable backup vaults (no vault type or resource id).")
        labels = [vault_label(vault) for vault in vaults]
        if truncated:
            return create_response(
                CRITERIA_KEY, None,
                not_evaluated="The vault list was truncated, so not every vault was read.",
                input_summary={"vaultsRead": len(vaults), "truncated": True})
        customer_keys = [vault_label(vault) for vault in vaults if uses_customer_key(vault)]
        pass_reasons = [
            str(len(vaults)) + " backup vault(s) read (" + ", ".join(labels[:10])
            + (", ..." if len(labels) > 10 else "") + "). Azure Backup encrypts all backup data at rest "
            "with platform-managed keys by default, and this cannot be turned off."
        ]
        if customer_keys:
            pass_reasons.append("Customer-managed keys are configured on: " + ", ".join(customer_keys[:10]))
        return create_response(
            CRITERIA_KEY, True,
            pass_reasons=pass_reasons,
            input_summary={"vaultCount": len(vaults), "customerManagedKeyVaults": len(customer_keys),
                           "vaults": labels[:25]})
    except Exception as exc:
        return create_response(CRITERIA_KEY, None, not_evaluated="Transformation error: " + str(exc)[:200])
