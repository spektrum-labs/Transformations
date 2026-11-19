"""
Transformation: endOfLifeSoftwareDetected
Vendor: Qualys  |  Category: Attack Surface Management
Evaluates: Whether end-of-life software is present in the environment.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "endOfLifeSoftwareDetected", "vendor": "Qualys", "category": "Attack Surface Management"}
        }
    }


# The read is ours, so a gap in it is ours to fix: the customer is told so, and errorCode routes it to engineering.
NOT_OURS_TO_ASK = "Nothing is needed from you; this is on Spektrum's side."


def not_measured(criteria_key, reason, error_code, validation=None, transformation_errors=None, findings=None,
                 recommendations=(NOT_OURS_TO_ASK,)):
    """criteria_key None plus a coded dataCollection error, so the evaluator records Not evaluated."""
    response = create_response(
        result={criteria_key: None}, validation=validation,
        api_errors=[reason], fail_reasons=[reason], transformation_errors=transformation_errors,
        additional_findings=findings, recommendations=list(recommendations))
    response["additionalInfo"]["dataCollection"]["errorCode"] = error_code
    return response


# Qualys CSAM lifecycle stages. Only a stage named here as current can answer "no end-of-life software".
END_OF_LIFE_TOKENS = ('eol', 'eos', 'obsolete', 'end of life', 'end-of-life', 'end of support', 'end-of-support')
CURRENT_STAGES = ('ga', 'general availability', 'pre-ga', 'beta')


def evaluate(data):
    """End-of-life software, when the reply carries the asset inventory (assetListData).

    getHostList returns the Qualys host list, which has no assetListData key, so this used to answer
    "no end-of-life software" for every estate. Without the key nothing was measured.
    """
    try:
        asset_list = data.get('assetListData') if isinstance(data, dict) else None
        assets = asset_list.get('asset') if isinstance(asset_list, dict) else None
        if isinstance(assets, dict):
            assets = [assets]
        if not isinstance(assets, list) or not assets:
            return {"endOfLifeSoftwareDetected": None,
                    "notMeasured": "Spektrum's Qualys read does not yet include installed software, so "
                                   "end-of-life software could not be checked."}
        stages = []
        assets_read = 0
        for asset in assets:
            software_list = asset.get('softwareListData') if isinstance(asset, dict) else None
            software = software_list.get('software') if isinstance(software_list, dict) else None
            if isinstance(software, dict):
                software = [software]
            read_before = len(stages)
            for sw in software if isinstance(software, list) else []:
                lifecycle = sw.get('lifecycle') if isinstance(sw, dict) else None
                stage = lifecycle.get('stage') if isinstance(lifecycle, dict) else lifecycle
                if isinstance(stage, str) and stage.strip() and stage.strip().lower() != 'unknown':
                    stages.append(stage.strip().lower())
            if len(stages) > read_before:
                assets_read += 1
        if not stages:
            # Assets with no readable software lifecycle prove nothing about end-of-life software.
            return {"endOfLifeSoftwareDetected": None,
                    "notMeasured": "Spektrum's Qualys read does not yet include installed software, so "
                                   "end-of-life software could not be checked."}
        if any(any(token in stage for token in END_OF_LIFE_TOKENS) for stage in stages):
            return {"endOfLifeSoftwareDetected": True, "assetsScanned": assets_read}
        if any(stage not in CURRENT_STAGES for stage in stages):
            # A stage we do not recognise is not proof the software is current.
            return {"endOfLifeSoftwareDetected": None,
                    "notMeasured": "Qualys reported a software lifecycle stage Spektrum does not yet read, so "
                                   "end-of-life software could not be checked."}
        return {"endOfLifeSoftwareDetected": False, "assetsScanned": assets_read}
    except Exception:
        return {"endOfLifeSoftwareDetected": None, "error": "unreadable value in the Qualys reply"}


def transform(input):
    criteriaKey = "endOfLifeSoftwareDetected"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return not_measured(criteriaKey, "The Qualys response failed validation, so end-of-life software "
                                "could not be checked.", "not_measured", validation=validation)
        eval_result = evaluate(data)
        if eval_result.get("notMeasured"):
            return not_measured(criteriaKey, eval_result["notMeasured"], "not_measured", validation=validation)
        result_value = eval_result.get(criteriaKey)
        if not isinstance(result_value, bool):
            return not_measured(criteriaKey, "The Qualys response could not be read, so end-of-life software "
                                "could not be checked.", "not_measured", validation=validation,
                                transformation_errors=[eval_result.get("error", "no value")])
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey}
        reason = ("End-of-life software is installed on assets Qualys inventories." if result_value
                  else "No end-of-life software on the " + str(eval_result["assetsScanned"]) + " assets whose software Qualys lists.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            additional_findings=[reason],
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception:
        return not_measured(criteriaKey, "The Qualys response could not be read, so end-of-life software "
                            "could not be checked.", "not_measured",
                            validation={"status": "error", "errors": [], "warnings": []},
                            transformation_errors=["unreadable value in the Qualys reply"])
