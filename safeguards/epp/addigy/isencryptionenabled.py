def transform(input):
    """
    Evaluates if disk encryption (FileVault) is enabled across Addigy managed devices.
    FileVault is Apple's built-in disk encryption for macOS.

    Parameters:
        input (dict): The JSON data containing Addigy devices information.

    Returns:
        dict: A dictionary summarizing the encryption status across devices.
    """

    try:
        # Handle nested response structure
        if 'response' in input:
            input = input['response']

        # Get devices array
        devices = input.get("devices", input.get("data", input.get("items", [])))
        if isinstance(input, list):
            devices = input

        total_devices = len(devices) if isinstance(devices, list) else 0
        encrypted_devices = 0
        macos_devices = 0
        macos_encrypted = 0

        for device in devices if isinstance(devices, list) else []:
            # Get device facts/properties
            facts = device.get("facts", device)

            # Determine device type
            os_type = facts.get("os_type", facts.get("osType", facts.get("platform", ""))).lower()

            is_macos = "macos" in os_type or "mac" in os_type or "darwin" in os_type
            if is_macos:
                macos_devices += 1

            # Check FileVault status - Addigy reports this in various fact formats
            filevault_status = facts.get("filevault_status",
                              facts.get("filevault_enabled",
                              facts.get("FileVault_Status",
                              facts.get("disk_encryption",
                              facts.get("encryption_status",
                              facts.get("fde_status", ""))))))

            # Normalize the status check
            status_str = str(filevault_status).lower()
            is_encrypted = status_str in ["on", "enabled", "true", "encrypted", "1", "filevault on"]

            if is_encrypted:
                encrypted_devices += 1
                if is_macos:
                    macos_encrypted += 1

        # Calculate encryption percentage
        encryption_percentage = (
            (encrypted_devices / total_devices) * 100
            if total_devices > 0 else 0
        )

        macos_encryption_percentage = (
            (macos_encrypted / macos_devices) * 100
            if macos_devices > 0 else 0
        )

        # Encryption is considered enabled if any devices have it
        is_encryption_enabled = encrypted_devices > 0

        # Encryption is valid if a significant portion of devices are encrypted (>80%)
        is_encryption_valid = encryption_percentage >= 80

        encryption_info = {
            "isEncryptionEnabled": is_encryption_enabled,
            "isEncryptionValid": is_encryption_valid,
            "isFileVaultEnabled": is_encryption_enabled,
            "encryptionPercentage": round(encryption_percentage),
            "macosEncryptionPercentage": round(macos_encryption_percentage),
            "totalDevices": total_devices,
            "encryptedDevices": encrypted_devices,
            "macosDevices": macos_devices,
            "macosEncrypted": macos_encrypted
        }
        return encryption_info
    except Exception as e:
        return {
            "isEncryptionEnabled": False,
            "isEncryptionValid": False,
            "isFileVaultEnabled": False,
            "error": str(e)
        }
