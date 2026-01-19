def transform(input):
    """
    Evaluates if cloud sandbox for file analysis is enabled in Zscaler ZIA.

    Checks for behavioral analysis and sandbox settings that indicate
    files are being analyzed in a sandbox environment.

    Parameters:
        input (dict): The JSON data from Zscaler ZIA sandbox settings endpoint.

    Returns:
        dict: A dictionary summarizing the sandbox status.
    """

    try:
        if 'response' in input:
            input = input['response']

        isSandboxEnabled = False
        behavioral_analysis_enabled = False

        # Get sandbox settings from response
        sandbox_settings = input.get('sandboxSettings', input.get('responseData', {}))

        if isinstance(sandbox_settings, dict):
            # Check for sandbox enabled flag
            if sandbox_settings.get('sandboxEnabled', False):
                isSandboxEnabled = True

            if sandbox_settings.get('cloudSandbox', False):
                isSandboxEnabled = True

            # Check for behavioral analysis
            if sandbox_settings.get('behavioralAnalysis', False):
                behavioral_analysis_enabled = True
                isSandboxEnabled = True

            if sandbox_settings.get('behavioralAnalysisEnabled', False):
                behavioral_analysis_enabled = True
                isSandboxEnabled = True

            # Check for file detonation
            if sandbox_settings.get('fileDetonation', False):
                isSandboxEnabled = True

            if sandbox_settings.get('fileDetonationEnabled', False):
                isSandboxEnabled = True

            # Check for advanced settings indicating sandbox is active
            if sandbox_settings.get('advancedSettings') or sandbox_settings.get('analysisSettings'):
                isSandboxEnabled = True

        # If sandbox settings exist and have content, assume sandbox is configured
        if isinstance(sandbox_settings, dict) and len(sandbox_settings) > 0:
            isSandboxEnabled = True

        sandbox_info = {
            "isSandboxEnabled": isSandboxEnabled,
            "behavioralAnalysisEnabled": behavioral_analysis_enabled
        }
        return sandbox_info
    except Exception as e:
        return {"isSandboxEnabled": False, "error": str(e)}
