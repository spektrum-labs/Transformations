"""
Transformation: isBackupEncrypted
Vendor: Rubrik  |  Category: Backup
Evaluates: Whether encryptionEnabled is true on connected Rubrik clusters,
confirming that data-at-rest encryption is active for backed-up workloads.
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
                "transformationId": "isBackupEncrypted",
                "vendor": "Rubrik",
                "category": "Backup"
            }
        }
    }


ACTIVE_STATUSES = ["CONNECTED", "ACTIVE", "OK", "RUNNING"]


def is_cluster_active(status):
    if not isinstance(status, str):
        return False
    return status.upper() in ACTIVE_STATUSES


def evaluate(data):
    try:
        clusters = []
        raw_nodes = data.get("nodes", [])
        if isinstance(raw_nodes, list):
            for node in raw_nodes:
                if isinstance(node, dict) and ("encryptionEnabled" in node or "productType" in node):
                    clusters.append(node)
        if not clusters:
            cluster_data = data.get("clusterConnection", {})
            if isinstance(cluster_data, dict):
                raw_nodes = cluster_data.get("nodes", [])
                if isinstance(raw_nodes, list):
                    clusters = raw_nodes

        total_clusters = len(clusters)
        encrypted_clusters = []
        unencrypted_clusters = []

        for cluster in clusters:
            name = cluster.get("name", "unknown")
            enc = cluster.get("encryptionEnabled")
            if enc is True:
                encrypted_clusters.append(name)
            else:
                unencrypted_clusters.append(name)

        encrypted_count = len(encrypted_clusters)
        is_encrypted = total_clusters > 0 and encrypted_count == total_clusters

        score = 0
        if total_clusters > 0:
            score = int((encrypted_count * 100) / total_clusters)

        return {
            "isBackupEncrypted": is_encrypted,
            "totalClusters": total_clusters,
            "encryptedClusters": encrypted_count,
            "unencryptedClusters": len(unencrypted_clusters),
            "unencryptedClusterNames": unencrypted_clusters,
            "encryptionScoreInPercentage": score
        }
    except Exception as e:
        return {"isBackupEncrypted": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupEncrypted"
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
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        findings = []
        if result_value:
            pass_reasons.append(
                "Backup encryption is enabled on all " +
                str(eval_result.get("totalClusters", 0)) +
                " cluster(s) — encryptionEnabled is true across the board"
            )
            pass_reasons.append(
                "Encryption coverage: " + str(eval_result.get("encryptionScoreInPercentage", 100)) + "%"
            )
        else:
            if eval_result.get("totalClusters", 0) == 0:
                fail_reasons.append("No Rubrik clusters found in RSC; encryption status cannot be determined")
            else:
                unenc = eval_result.get("unencryptedClusters", 0)
                fail_reasons.append(
                    str(unenc) + " cluster(s) do not have encryptionEnabled set to true"
                )
                bad_names = eval_result.get("unencryptedClusterNames", [])
                if bad_names:
                    findings.append("Clusters without encryption: " + ", ".join(bad_names))
                findings.append(
                    "Encryption coverage: " + str(eval_result.get("encryptionScoreInPercentage", 0)) + "%"
                )
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Enable data-at-rest encryption on all Rubrik clusters via the RSC cluster settings. "
                "Refer to Rubrik documentation for cluster encryption configuration steps."
            )
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=findings,
            input_summary={
                "totalClusters": eval_result.get("totalClusters", 0),
                "encryptedClusters": eval_result.get("encryptedClusters", 0),
                "encryptionScoreInPercentage": eval_result.get("encryptionScoreInPercentage", 0)
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
