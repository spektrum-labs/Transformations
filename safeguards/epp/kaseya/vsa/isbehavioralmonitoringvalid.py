"""
Transformation: isBehavioralMonitoringValid
Vendor: Kaseya
Category: Endpoint Protection

Evaluates isBehavioralMonitoringValid for Kaseya
"""

import json
from datetime import datetime


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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBehavioralMonitoringValid", "vendor": "Kaseya", "category": "Endpoint Protection"}
        }
    }


def transform(input):
    criteriaKey = "isBehavioralMonitoringValid"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # Initialize result
        result = {
            "isBehavioralMonitoringValid": False,
            "behavioralAnalysisEnabled": False,
            "anomalyDetectionEnabled": False,
            "automatedResponseEnabled": False,
            "alertingConfigured": False
        }

        # Get policy data
        policy_data = data.get("Data", data)

        # Check if policy is enabled first
        is_enabled = policy_data.get("enabled", False)
        if not is_enabled:
            return result

        # Get settings from policy
        settings = policy_data.get("settings", {})
        if not settings:
            return result

        # Check for behavioral analysis settings
        behavioral = settings.get("behavioralAnalysis", settings.get("BehavioralAnalysis", {}))
        if isinstance(behavioral, dict):
            result["behavioralAnalysisEnabled"] = behavioral.get("enabled", False)

            # Check for anomaly detection
            anomaly = behavioral.get("anomalyDetection", behavioral.get("AnomalyDetection", False))
            if isinstance(anomaly, dict):
                result["anomalyDetectionEnabled"] = anomaly.get("enabled", False)
            elif isinstance(anomaly, bool):
                result["anomalyDetectionEnabled"] = anomaly
        elif isinstance(behavioral, bool):
            result["behavioralAnalysisEnabled"] = behavioral

        # Check alternative paths for behavioral monitoring
        if not result["behavioralAnalysisEnabled"]:
            # Check for behavior monitoring
            behavior_monitor = settings.get("behaviorMonitoring", settings.get("BehaviorMonitoring", {}))
            if isinstance(behavior_monitor, dict):
                result["behavioralAnalysisEnabled"] = behavior_monitor.get("enabled", False)
            elif isinstance(behavior_monitor, bool):
                result["behavioralAnalysisEnabled"] = behavior_monitor

            # Check for heuristic analysis
            heuristics = settings.get("heuristicAnalysis", settings.get("heuristics", {}))
            if isinstance(heuristics, dict):
                result["behavioralAnalysisEnabled"] = result["behavioralAnalysisEnabled"] or heuristics.get("enabled", False)
            elif isinstance(heuristics, bool):
                result["behavioralAnalysisEnabled"] = result["behavioralAnalysisEnabled"] or heuristics

        # Check for automated response settings
        auto_response = settings.get("automatedResponse", settings.get("AutomatedResponse", {}))
        if isinstance(auto_response, dict):
            result["automatedResponseEnabled"] = auto_response.get("enabled", False)

            # Check for specific response actions
            actions = auto_response.get("actions", [])
            if actions and len(actions) > 0:
                result["automatedResponseEnabled"] = True
        elif isinstance(auto_response, bool):
            result["automatedResponseEnabled"] = auto_response

        # Check alternative response paths
        if not result["automatedResponseEnabled"]:
            # Check for threat response
            threat_response = settings.get("threatResponse", settings.get("ThreatResponse", {}))
            if isinstance(threat_response, dict):
                result["automatedResponseEnabled"] = threat_response.get("autoRemediate", threat_response.get("enabled", False))
            elif isinstance(threat_response, bool):
                result["automatedResponseEnabled"] = threat_response

            # Check for quarantine settings
            quarantine = settings.get("quarantine", settings.get("autoQuarantine", False))
            if isinstance(quarantine, dict):
                result["automatedResponseEnabled"] = result["automatedResponseEnabled"] or quarantine.get("enabled", False)
            elif isinstance(quarantine, bool):
                result["automatedResponseEnabled"] = result["automatedResponseEnabled"] or quarantine

        # Check for alerting configuration
        alerting = settings.get("alerting", settings.get("Alerting", settings.get("notifications", {})))
        if isinstance(alerting, dict):
            result["alertingConfigured"] = alerting.get("enabled", False)

            # Check for specific alert types
            behavioral_alerts = alerting.get("behavioralAlerts", alerting.get("anomalyAlerts", False))
            if behavioral_alerts:
                result["alertingConfigured"] = True
        elif isinstance(alerting, bool):
            result["alertingConfigured"] = alerting

        # Check alternative alerting paths
        if not result["alertingConfigured"]:
            email_alerts = settings.get("emailAlerts", settings.get("notifications", False))
            if email_alerts:
                result["alertingConfigured"] = True

        # Determine overall validity
        # Behavioral monitoring is valid if analysis is enabled and either alerts or automated response is configured
        result["isBehavioralMonitoringValid"] = (
            result["behavioralAnalysisEnabled"] and
            (result["alertingConfigured"] or result["automatedResponseEnabled"])
        )

        return result

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
