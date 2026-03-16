"""
Transformation: isDataSourcesConfigured
Vendor: Netwrix  |  Category: SIEM
Evaluates: Whether Netwrix Auditor is configured to monitor multiple distinct
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isDataSourcesConfigured", "vendor": "Netwrix", "category": "SIEM"}
        }
    }


def evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:
        records = data.get("ActivityRecordList", data.get("activityRecordList", []))

        if not isinstance(records, list) or len(records) == 0:
            return {
                "isDataSourcesConfigured": False,
                "dataSourceCount": 0,
                "dataSources": [],
                "reason": "No activity records found — no data sources appear to be configured"
            }

        # Collect all unique DataSource values from activity records
        distinct_sources = set()
        for record in records:
            ds = record.get("DataSource", record.get("dataSource", ""))
            if ds and str(ds).strip():
                distinct_sources.add(str(ds).strip())

        data_source_count = len(distinct_sources)
        result = data_source_count >= MIN_DATA_SOURCES

        # Categorize data sources for richer diagnostics
        categories_found = set()
        for source in distinct_sources:
            source_lower = source.lower()
            for category, keywords in KNOWN_DATA_SOURCES.items():
                if any(kw in source_lower for kw in keywords):
                    categories_found.add(category)
                    break

        return {
            "isDataSourcesConfigured": result,
            "dataSourceCount": data_source_count,
            "dataSources": sorted(list(distinct_sources)),
            "categoriesFound": sorted(list(categories_found)),
            "minimumRequired": MIN_DATA_SOURCES,
            "reason": (
                f"{data_source_count} distinct data source(s) found across {len(categories_found)} categories"
                if result
                else f"Only {data_source_count} data source(s) found — minimum {MIN_DATA_SOURCES} required for comprehensive coverage"
            )
        }
    except Exception as e:
        return {"isDataSourcesConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isDataSourcesConfigured"
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
        eval_result = evaluate(data)

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
            recommendations.append(f"Review Netwrix configuration for {criteriaKey}")

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
