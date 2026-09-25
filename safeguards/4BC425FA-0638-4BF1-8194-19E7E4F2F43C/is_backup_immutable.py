"""
Transformation: isBackupImmutable
Vendor: AWS Backup
Category: Backups

Evidence: AWS Backup ListBackupVaults (GET https://backup.{region}.amazonaws.com/backup-vaults/),
which returns every vault with Locked, LockDate, MinRetentionDays, MaxRetentionDays and
NumberOfRecoveryPoints.

Rule (fail closed):
  * Only vaults that hold recovery points are judged. At least one must exist.
  * Every judged vault must be locked in COMPLIANCE mode: Locked is true AND LockDate is set and in
    the past (the grace period is over, so nobody, including the root user, can remove the lock or
    delete recovery points early). A logically air-gapped vault is compliance-locked by design.
  * GOVERNANCE mode (Locked true, no LockDate) fails: a principal with
    backup:DeleteBackupVaultLockConfiguration can remove it, so it is not WORM.
  * A vendor error, or a body without BackupVaultList, is reported as a data-collection error so
    Token-Service marks the check unevaluated instead of recording a finding.

Scope: one region (the integration's configured region), first page of vaults. RDS automated
backups and manual snapshots never live in an AWS Backup vault, so they are not covered here.

Previously this key read an RDS DescribeDBInstanceAutomatedBackups body that can never contain a
vault lock, so every result was "not locked" without anything having been measured.
"""

import json
from datetime import datetime, timezone

CRITERIA_KEY = "isBackupImmutable"
AIR_GAPPED = "LOGICALLY_AIR_GAPPED_BACKUP_VAULT"


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": CRITERIA_KEY,
                "vendor": "AWS Backup",
                "category": "Backups"
            }
        }
    }


def vendor_error(data):
    """The vendor's own error message when the body is an error envelope, else None."""
    if data is None:
        return "No response body"
    if not isinstance(data, dict):
        return None
    for key in ["error", "errors", "Error", "ErrorResponse", "__type", "errorType", "errorCode"]:
        value = data.get(key)
        if value:
            if isinstance(value, dict):
                inner = value.get("Error") if isinstance(value.get("Error"), dict) else value
                return str(inner.get("Message") or inner.get("message") or inner.get("Code") or value)
            return "%s: %s" % (value, data.get("Message") or data.get("message") or "")
    code = data.get("statusCode", data.get("status_code"))
    try:
        if code is not None and int(code) >= 400:
            return "HTTP %s" % code
    except (TypeError, ValueError):
        pass
    return None


def is_true(value):
    return value is True or str(value).strip().lower() == "true"


def parse_time(value):
    """AWS JSON timestamps are epoch seconds; accept ISO-8601 strings as well."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), timezone.utc)
    text = str(value).strip()
    try:
        return datetime.fromtimestamp(float(text), timezone.utc)
    except ValueError:
        pass
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def to_int(value):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        error = vendor_error(data)
        if error is None and not (isinstance(data, dict) and isinstance(data.get("BackupVaultList"), list)):
            error = "Response has no BackupVaultList; AWS Backup vaults were not read"
        if error is not None:
            return create_response(
                result={CRITERIA_KEY: False},
                validation=validation,
                api_errors=[error],
                fail_reasons=["Not measured: " + error],
                recommendations=["Grant backup:ListBackupVaults to the integration's IAM identity and re-evaluate"]
            )

        now = datetime.now(timezone.utc)
        vaults = [v for v in data["BackupVaultList"] if isinstance(v, dict)]
        judged = [v for v in vaults if to_int(v.get("NumberOfRecoveryPoints")) > 0]

        findings = []
        not_immutable = []
        for vault in judged:
            name = str(vault.get("BackupVaultName") or "unknown")
            lock_date = parse_time(vault.get("LockDate"))
            if str(vault.get("VaultType") or "") == AIR_GAPPED:
                mode = "air-gapped (compliance)"
            elif not is_true(vault.get("Locked")):
                mode = "not locked"
            elif lock_date is None:
                mode = "governance"
            elif lock_date > now:
                mode = "compliance, still in grace period"
            else:
                mode = "compliance"
            immutable = mode in ("compliance", "air-gapped (compliance)")
            if not immutable:
                not_immutable.append("%s (%s)" % (name, mode))
            findings.append({
                "metric": name,
                "value": immutable,
                "reason": "%s; %d recovery points; MinRetentionDays=%s" % (
                    mode, to_int(vault.get("NumberOfRecoveryPoints")), vault.get("MinRetentionDays"))
            })

        is_immutable = len(judged) > 0 and len(not_immutable) == 0

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if is_immutable:
            pass_reasons.append("All %d AWS Backup vaults holding recovery points are compliance-locked" % len(judged))
        elif len(judged) == 0:
            fail_reasons.append("No AWS Backup vault in this region holds recovery points (%d vaults listed)" % len(vaults))
            recommendations.append("Store backups in an AWS Backup vault with Vault Lock in compliance mode")
        else:
            fail_reasons.append("%d of %d vaults holding recovery points are not compliance-locked: %s" % (
                len(not_immutable), len(judged), ", ".join(not_immutable)))
            recommendations.append("Apply AWS Backup Vault Lock in compliance mode (set ChangeableForDays) to every vault holding recovery points")
        if data.get("NextToken"):
            validation = {"status": "unknown", "errors": [], "warnings": ["Only the first page of vaults was returned"]}

        return create_response(
            result={CRITERIA_KEY: is_immutable, "vaultsJudged": len(judged), "vaultsNotImmutable": len(not_immutable)},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=findings,
            input_summary={"vaultsListed": len(vaults), "vaultsWithRecoveryPoints": len(judged)}
        )

    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % str(e)]
        )
