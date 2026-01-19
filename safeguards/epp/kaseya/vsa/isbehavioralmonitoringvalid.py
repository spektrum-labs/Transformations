import json
import ast


def transform(input):
    """
    Evaluates whether behavioral monitoring is properly configured in Kaseya VSA.
    Checks endpoint protection policies for behavioral analysis and anomaly detection.

    Parameters:
        input (dict): The JSON data from Kaseya getEndpointProtectionPolicies endpoint.

    Returns:
        dict: A dictionary indicating if behavioral monitoring is valid.
    """
    try:
        def _parse_input(input):
            if isinstance(input, str):
                try:
                    parsed = ast.literal_eval(input)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    input = input.replace("'", '"')
                    return json.loads(input)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)

        # Navigate through response wrappers
        data = data.get("response", data)
        data = data.get("result", data)
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

    except json.JSONDecodeError:
        return {"isBehavioralMonitoringValid": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBehavioralMonitoringValid": False, "error": str(e)}
