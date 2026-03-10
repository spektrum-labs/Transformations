"""
Transformation: isBackupImmutable
Vendor: Commvault  |  Category: Backups
Evaluates: Whether WORM (Write Once Read Many) / Retention Lock / Compliance Lock /
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupImmutable", "vendor": "Commvault", "category": "Backups"}
        }
    }


def _evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:
        result = False
        immutable_pools = 0
        total_pools = 0

        pools = (
            data.get("storagePoolList") or
            data.get("storagePool") or
            data.get("storagePolicies") or
            []
        )

        if not isinstance(pools, list):
            return {"isBackupImmutable": False, "error": "Unexpected response format"}

        total_pools = len(pools)

        # Immutability indicator field names across Commvault API versions
        IMMUTABILITY_FIELDS = [
            "wormStorageEnabled",    # v4 StoragePool WORM flag
            "isWormEnabled",
            "complianceLock",        # Compliance Lock (software-level)
            "isComplianceLocked",
            "retentionLock",         # HyperScale X Retention Lock
            "isRetentionLocked",
            "isAirGapProtect",       # Air Gap Protect
            "airGapProtectEnabled",
            "immutabilityEnabled",
            "isImmutable",
            "objectLockEnabled",     # Cloud object lock (S3/Azure)
        ]

        for pool in pools:
            pool_immutable = False

            for field in IMMUTABILITY_FIELDS:
                val = pool.get(field)
                if val is True or str(val).lower() in ("true", "1", "yes", "enabled"):
                    pool_immutable = True
                    break

            # Also check in copy-level properties
            if not pool_immutable:
                copies = pool.get("copyInfo", pool.get("storagePolicyCopies", []))
                if isinstance(copies, list):
                    for copy in copies:
                        for field in IMMUTABILITY_FIELDS:
                            val = copy.get(field)
                            if val is True or str(val).lower() in ("true", "1", "yes", "enabled"):
                                pool_immutable = True
                                break
                        if pool_immutable:
                            break

            if pool_immutable:
                immutable_pools += 1

        result = immutable_pools > 0
    except Exception as e:
        return {"isBackupImmutable": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupImmutable"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        # Run core evaluation
        eval_result = _evaluate(data)

        # Extract the boolean result and any extra fields
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(f"Review Commvault configuration for {criteriaKey}")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
