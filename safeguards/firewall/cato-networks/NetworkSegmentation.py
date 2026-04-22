"""
Transformation: NetworkSegmentation
Vendor: Cato Networks  |  Category: Firewall
Evaluates: Network segmentation by querying entityLookup for networkInterface entities.
Checks that two or more distinct network interfaces/segments are defined, indicating
that the network is divided into separate zones or VLANs rather than a flat topology.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "NetworkSegmentation", "vendor": "Cato Networks", "category": "Firewall"}
        }
    }


def collect_segment_names(items):
    """Collect unique segment names from entityLookup items."""
    seen = {}
    names = []
    for item in items:
        entity = item.get("entity", {})
        entity_id = entity.get("id", "")
        entity_name = entity.get("name", "")
        if entity_id and entity_id not in seen:
            seen[entity_id] = True
            names.append(entity_name)
    return names


def evaluate(data):
    """Core evaluation logic for NetworkSegmentation."""
    try:
        # returnSpec for getSiteNetworkRanges resolves to data.entityLookup.items
        # Shape: list of { "entity": { "id": str, "name": str, "type": str }, "description": str }
        items = data

        if isinstance(data, dict):
            if "entityLookup" in data:
                lookup = data.get("entityLookup", {})
                items = lookup.get("items", [])
            elif "items" in data:
                items = data.get("items", [])

        if not isinstance(items, list):
            items = []

        segment_names = collect_segment_names(items)
        segment_count = len(segment_names)

        # Network segmentation requires at least 2 distinct interfaces/segments
        is_segmented = segment_count >= 2

        return {
            "NetworkSegmentation": is_segmented,
            "totalNetworkSegments": segment_count,
            "segmentNames": segment_names
        }
    except Exception as e:
        return {"NetworkSegmentation": False, "error": str(e)}


def transform(input):
    criteriaKey = "NetworkSegmentation"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation,
                                   fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        segment_count = eval_result.get("totalNetworkSegments", 0)
        segment_names = eval_result.get("segmentNames", [])
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append("Network segmentation is in place with " + str(segment_count) + " distinct network interface segments")
            pass_reasons.append("Multiple network zones reduce lateral movement risk within the environment")
        else:
            if "error" in eval_result:
                fail_reasons.append("Transformation error: " + eval_result["error"])
            else:
                if segment_count == 0:
                    fail_reasons.append("No network interface segments found in Cato Networks account")
                else:
                    fail_reasons.append("Only " + str(segment_count) + " network interface segment found; at least 2 are required for segmentation")
            recommendations.append("Configure multiple network interfaces or VLANs in Cato Networks to segment your network")
            recommendations.append("Separate at minimum corporate LAN, DMZ, and guest/IoT zones into distinct network ranges")
            recommendations.append("Apply WAN Firewall policies between segments to control inter-zone traffic")

        for name in segment_names:
            additional_findings.append("Segment found: " + name)

        additional_findings.append("Total distinct segments: " + str(segment_count))

        return create_response(
            result={
                criteriaKey: result_value,
                "totalNetworkSegments": segment_count,
                "segmentNames": segment_names
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalNetworkSegments": segment_count, "segmented": result_value},
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
