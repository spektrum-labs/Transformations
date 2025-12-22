# Datto BCDR/Backup Transformation

**Safeguard Reference Number (SRN):** 1D9A8DCE-E059-4159-A709-569D7E2C2C89

## Overview

This transformation processes Datto BCDR (Business Continuity and Disaster Recovery) API responses into standardized backup safeguard coverage metrics for the Spektrum network.

Datto BCDR (formerly Kaseya BCDR) provides comprehensive business continuity and disaster recovery including:
- Local and cloud backup
- Instant virtualization
- Screenshot verification
- Ransomware protection
- Cloud Deletion Defense (immutable backups)

This transformation follows the same structure and patterns as the AWS Backup transformation.

## Transformation Files

| File | Purpose |
|------|---------|
| `backup_transform.py` | Main transformation - evaluates BCDR coverage across all devices |
| `confirmedlicensepurchased.py` | Validates Datto BCDR license/subscription status |
| `isbackupenabled.py` | Checks if backups are enabled |
| `is_backup_encrypted.py` | Validates backup encryption status |
| `is_backup_immutable.py` | Checks Cloud Deletion Defense / Ransomware Shield |
| `is_backup_tested.py` | Validates Screenshot Verification or restore tests |
| `is_backup_types_scheduled.py` | Checks backup schedule configuration |
| `is_backup_logging_enabled.py` | Validates logging and alerting |
| `is_backup_enabled_for_critical_systems.py` | Checks backup for servers/critical systems |
| `issamlenforced.py` | Validates SAML/SSO enforcement |

## Expected API Response Structure

The main `backup_transform.py` expects JSON from the Datto REST API:

```json
{
  "items": [
    {
      "id": "device-uuid",
      "name": "Server01",
      "type": "server",
      "deviceType": "windows_server",
      "backupEnabled": true,
      "isProtected": true,
      "lastBackup": "2025-12-19T10:00:00Z",
      "status": "protected",
      "encryption": {
        "enabled": true,
        "encrypted": true
      },
      "ransomwareShield": true,
      "cloudDeletionDefense": true,
      "screenshotVerification": {
        "enabled": true,
        "success": true,
        "verified": true
      },
      "schedule": {
        "enabled": true,
        "frequency": "hourly"
      },
      "cloudBackupEnabled": true,
      "localBackupEnabled": true,
      "instantVirtualization": true
    }
  ],
  "pagination": {
    "page": 1,
    "perPage": 100,
    "totalCount": 50
  },
  "isBackupConfigured": true
}
```

## Output Metrics

### Coverage Scores (0-100%)
- **Backup Enabled** - Overall backup enablement
- **Backup Encrypted** - Encryption coverage
- **Backup Immutable** - Cloud Deletion Defense / Ransomware Shield
- **Backup Tested** - Screenshot Verification coverage
- **Backup Scheduled** - Schedule configuration
- **Backup Logging** - Logging and alerts enabled
- **Critical Systems Protected** - Server/critical system protection
- **Cloud Backup** - Offsite/cloud backup coverage
- **Local Backup** - Local backup coverage
- **Screenshot Verification** - Automated backup verification
- **Instant Virtualization** - IVR readiness
- **Ransomware Protection** - Anti-ransomware features

### Boolean Flags
- `isBackupEnabled` - Backups are enabled
- `isBackupEncrypted` - Backups are encrypted
- `isBackupImmutable` - Immutable/ransomware-protected backups
- `isBackupTested` - Backups have been tested
- `isBackupTypesScheduled` - Backup schedules configured
- `isBackupLoggingEnabled` - Logging is enabled
- `isBackupEnabledForCriticalSystems` - Critical systems protected
- `isCloudBackupEnabled` - Cloud backup enabled
- `isLocalBackupEnabled` - Local backup enabled
- `isScreenshotVerificationEnabled` - Screenshot verification enabled
- `isInstantVirtualizationReady` - Instant virtualization ready
- `isRansomwareProtectionEnabled` - Ransomware protection enabled
- `isBackupConfigured` - BCDR is properly configured

## Usage

```python
from backup_transform import transform

# Sample API response
api_response = {
    "items": [...],
    "isBackupConfigured": True
}

# Run transformation
result = transform(api_response)
print(result)
```

## Testing

Use the `local_tester.py` from the Transformations root:

```bash
python local_tester.py safeguards/1D9A8DCE-E059-4159-A709-569D7E2C2C89/backup_transform.py sample_response.json
```

## API Documentation

To access Datto's REST API:
1. Log into the Datto Partner Portal
2. Navigate to Admin > Integrations
3. Generate API keys under the API Keys tab

**Important:** Leave the "Select Vendor" dropdown blank when creating API keys to avoid functionality restrictions.

## Datto BCDR Key Features

- **Screenshot Verification**: Automated backup testing via VM boot and screenshot
- **Instant Virtualization**: Boot VMs directly from backup images
- **Cloud Deletion Defense**: Immutable cloud backups protected from ransomware
- **Ransomware Shield**: Detection and protection against ransomware encryption
- **Inverse Chain Technology**: Efficient backup chain management

## References

- Datto Partner Portal API Documentation
- Datto BCDR Product Documentation
- [Datto PowerShell Wrapper](https://celerium.github.io/Datto-PowerShellWrapper/)

