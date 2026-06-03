# LABS-2842: [Resilience/Demo] AWS Cloud Security CIScompliancePercentage transform counts SUPPRESSED Security Hub findings (returns ~95.0% instead of 100%)

- **Type:** Bug
- **Status:** To Do
- **Priority:** High
- **Reporter:** josh.brown@spektrum.ai
- **Labels:** (none)
- **Components:** Fusion
- **Repo hints:** standards/cis-aws-foundations-benchmark, inflates/weights, spektrum-labs/transformations, subnet/detail, checks/industry

## Description

h2. Summary
In the new Resilience workflows (demo environment), the AWS Cloud Security safeguard reports an incorrect CIScompliancePercentage. The transform counts a SUPPRESSED Security Hub finding as a failure. AWS Security Hub's own security score excludes suppressed findings, so the value should be 100% but the platform shows ~95.0%.
h2. Environment
Resilience workflows — demo environment
Safeguard: AWS Cloud Security (Security Hub integration)
Config: {{configurations/cloudsecurity/awssecurityhub.json}}
AWS account in payload: 401656386916, region us-east-1
h2. Root cause (confirmed in config)
The {{CIScompliancePercentage}} criteriaKey maps to method {{getSecurityHubComplianceCIS}} ({{awssecurityhub.json}} lines 48-53 / 176-222). Its Security Hub filter is:
{{RecordState = ACTIVE}}
{{ComplianceStatus IN (PASSED, FAILED)}}
{{ComplianceAssociatedStandardsId = standards/cis-aws-foundations-benchmark/v/1.4.0}}
It does NOT filter on {{Workflow.Status}}. As a result, findings with {{Workflow.Status = SUPPRESSED}} are pulled into the dataset and counted by the shared {{compliancepercentage.py}} transform, even though AWS excludes suppressed findings from compliance scoring.
h2. Evidence from the sample payload (20 CIS findings)
19 PASSED, 1 FAILED.
The single FAILED finding is IAM.6 — "Hardware MFA should be enabled for the root user" (CRITICAL) — with {{"Workflow": { "Status": "SUPPRESSED" }}} and {{RecordState: ACTIVE}}.
Naive count: 19 / 20 = 95.0% (what the platform shows).
Suppressed-excluded: 19 / 19 = 100% (what AWS Security Hub shows, and what we should report).
h2. Steps to reproduce
Connect the demo AWS account (401656386916) Security Hub integration in Resilience workflows.
Run the AWS Cloud Security safeguard evaluation.
Observe {{CIScompliancePercentage}} renders ~95.0% while the AWS Security Hub console CIS v1.4.0 score reads 100% (the only failing control, IAM.6, is suppressed).
h2. Expected vs actual
Expected: CIScompliancePercentage = 100% (suppressed findings excluded, matching AWS scoring).
Actual: ~95.0% (suppressed CRITICAL IAM.6 failure counted against the score).
h2. Suggested fix
Primary — exclude suppressed findings. Either:
Add a {{WorkflowStatus}} filter to {{getSecurityHubComplianceCIS}} (and {{getSecurityHubComplianceAWS}}) for NEW / NOTIFIED / RESOLVED (i.e. exclude SUPPRESSED), or
Drop findings where {{Workflow.Status == SUPPRESSED}} inside {{compliancepercentage.py}}.
Secondary issues to check while in here:
{{compliancePercentage}} (FSBP) and {{CIScompliancePercentage}} (CIS) point to the 
same
 {{compliancepercentage.py}} transform (lines 45 & 51). Confirm the shared logic handles both standards correctly and isn't conflating them.
No per-control dedup.
 The payload has resource-level duplicates for the same control (S3.5 ×4, RDS.3 ×2). CIS scoring is per-control (a control passes only if all its resources pass); counting per-finding inflates/weights the denominator. Confirm the transform dedupes by {{Compliance.SecurityControlId}}.
Consider whether {{ComplianceStatus}} should also exclude {{WARNING}} / {{NOT_AVAILABLE}} (e.g. EC2.21 PASSED via {{CONFIG_EVALUATIONS_EMPTY}} — no resources in scope; verify these shouldn't skew results).
h2. Raw findings payload
Attached as a comment on this ticket.
h2. Transform reference
{{https://github.com/spektrum-labs/Transformations/blob/main/safeguards/9b380a34-6933-48e0-8b35-fe30f3bc3db3/compliancepercentage.py}}
Repo: spektrum-labs/Transformations

## Comments (recent)
### josh.brown@spektrum.ai — 2026-06-02T15:11:01.530+0000
Raw AWS Security Hub findings payload from the demo environment (account 401656386916, us-east-1). 20 findings total: 19 PASSED, 1 FAILED. The single FAILED finding (IAM.6, CRITICAL) has Workflow.Status = SUPPRESSED. Verbose non-diagnostic metadata (Remediation URLs, ProductFields, full RDS subnet/detail blocks) condensed to fit the Jira comment size limit; byte-exact full payload available on request.
{
  "apiResponse": {
    "Findings": [
      {
        "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "Types": [
          "Software and Configuration Checks/Industry and Regulatory Standards"
        ],
        "Description": "This AWS control checks whether your AWS account is enabled to use a hardware multi-factor authentication (MFA) device to sign in with root user credentials.",
        "Compliance": {
          "Status": "FAILED",
          "SecurityControlId": "IAM.6",
          "RelatedRequirements": [
            "CIS AWS Foundations Benchmark v1.4.0/1.6"
          ],
          "AssociatedStandards": [
            {
              "StandardsId": "standards/cis-aws-foundations-benchmark/v/1.4.0"
            }
          ]
        },
        "ProductName": "Security Hub",
        "FirstObservedAt": "2023-06-21T06:04:20.956Z",
        "CreatedAt": "2023-06-21T06:04:20.956Z",
        "LastObservedAt": "2026-06-01T18:48:51.456Z",
        "CompanyName": "AWS",
        "FindingProviderFields": {
          "Types": [
            "Software and Configuration Checks/Industry and Regulatory Standards"
          ],
          "Severity": {
            "Normalized": 90,
            "Label": "CRITICAL",
            "Original": "CRITICAL"
          }
        },
        "ProductFields": {
          "RelatedAWSResources:0/name": "securityhub-root-account-hardware-mfa-enabled-a5e95840",
          "RelatedAWSResources:0/type": "AWS::Config::ConfigRule",
          "aws/securityhub/ProductName": "Security Hub",
          "aws/securityhub/CompanyName": "AWS",
          "Resources:0/Id": "arn:aws:iam::401656386916:root",
          "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1::product/aws/securityhub/arn:aws:securityhub:us-east-1:401656386916:security-control/IAM.6/finding/8c32d4d0-588c-448f-84b1-2d47598a6053",
          "PreviousComplianceStatus": "FAILED"
        },
        "Remediation": {
          "Recommendation": {
            "Text": "For information on how to correct this issue, consult the AWS Security Hub controls documentation.",
            "Url": "https://docs.aws.amazon.com/console/securityhub/IAM.6/remediation"
          }
        },
        "SchemaVersion": "2018-10-08",
        "GeneratorId": "security-control/IAM.6",
        "RecordState": "ACTIVE",
        "Title": "Hardware MFA should be enabled for the root user",
        "Workflow": {
          "Status": "SUPPRESSED"
        },
        "Severity": {
          "Normalized": 90,
          "Label": "CRITICAL",
          "Original": "CRITICAL"
        },
        "UpdatedAt": "2026-06-01T18:50:06.012Z",
        "WorkflowState": "NEW",
        "AwsAccountId": "401656386916",
        "Region": "us-east-1",
        "Id": "arn:aws:securityhub:us-east-1:401656386916:security-control/IAM.6/finding/8c32d4d0-588c-448f-84b1-2d47598a6053",
        "Resources": [
          {
            "Partition": "aws",
            "Type": "AwsAccount",
            "Owner": {
              "Account": {
                "Id": "401656386916"
              }
            },
            "Region": "us-east-1",
            "Id": "AWS::::Account:401656386916",
            "Provider": "AWS"
          }
        ],
        "ProcessedAt": "2026-06-01T18:50:18.378Z"
      },
      {
        "Compliance": {
          "Status": "PASSED",
          "StatusReasons": [
            {
              "Description": "AWS Config evaluated your resources against the rule. The rule did not apply to the AWS resources in its scope, the specified resources were deleted, or the evaluation results were deleted.",
              "ReasonCode": "CONFIG_EVALUATIONS_EMPTY"
            }
          ],
          "SecurityControlId": "EC2.21",
          "RelatedRequirements": [
            "CIS AWS Foundations Benchmark v1.4.0/5.1"
          ],
          "AssociatedStandards": [
            {
              "StandardsId": "standards/aws-foundational-security-best-practices/v/1.0.0"
            },
            {
              "StandardsId": "standards/cis-aws-foundations-benchmark/v/1.4.0"
            }
          ]
        },
        "Title": "Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389",
        "RecordState": "ACTIVE",
        "Workflow": {
          "Status": "RESOLVED"
        },
        "Severity": {
          "Label": "INFORMATIONAL"
        },
        "AwsAccountId": "401656386916",
        "Region": "us-east-1",
        "Id": "arn:aws:securityhub:us-east-1:401656386916:security-control/EC2.21/finding/5b062199-3765-47cd-9175-c69a2f7bb2d7"
      },
      {
        "Compliance": {
          "Status": "PASSED",
          "SecurityControlId": "Config.1",
          "RelatedRequirements": [
            "CIS AWS Foundations Benchmark v1.4.0/3.5"
          ],
          "AssociatedStandards": [
            {
              "StandardsId": "standards/aws-foundational-security-best-practices/v/1.0.0"
            },
            {
              "StandardsId": "standards/cis-aws-foundations-benchmark/v/1.4.0"
            }
          ],
          "SecurityControlParameters": [
            {
              "Value": [
                "true"
              ],
              "Name": "includeConfigServiceLinkedRoleCheck"
            }
          ]
        },
        "Title": "AWS Config should be enabled and use the service-linked role for resource recording",
        "RecordState": "ACTIVE",
        "Workflow": {
          "Status": "RESOLVED"
        },
        "Severity": {
          "Label": "INFORMATIONAL"
        },
        "AwsAccountId": "401656386916",
        "Region": "us-east-1",
        "Id": "arn:aws:securityhub:us-east-1:401656386916:security-control/Config.1/finding/cd663ff8-c6c0-49f8-aff2-9c0ffacf6086"
      },
      {
        "Compliance": {
          "Status": "PASSED",
          "SecurityControlId": "CloudWatch.9",
          "RelatedRequirements": [
            "CIS AWS Foundations Benchmark v1.4.0/4.9"
          ],
          "AssociatedStandards": [
            {
              "StandardsId": "standards/cis-aws-foundations-benchmark/v/1.4.0"
            }
          ]
        },
        "Title": "Ensure a log metric filter and alarm exist for AWS Config configuration changes",
        "RecordState": "ACTIVE",
        "Workflow": {
          "Status": "RESOLVED"
        },
        "Severity": {
          "Label": "INFORMATIONAL"
        },
        "Id": "arn:aws:securityhub:us-east-1:401656386916:security-control/CloudWatch.9/finding/53ea1eff-71e6-4d07-8fc4-85424e143a5c"
      },
      {
        "Compliance": {
          "Status": "PASSED",
          "SecurityControlId": "CloudWatch.8",
          "RelatedRequirements": [
            "CIS AWS Foundations Benchmark v1.4.0/4.8"
          ],
          "AssociatedStandards": [
            {
              "StandardsId": "standards/cis-aws-foundations-benchmark/v/1.4.0"
            }
          ]
        },
        "Title": "Ensure a log metric filter and alarm exist for S3 bucket policy changes",
        "RecordState": "ACTIVE",
        "Workflow": {
          "Status": "RESOLVED"
        },
        "Severity": {
          "Label": "INFORMATIONAL"
        },
        "Id": "arn:aws:securityhub:us-east-1:401656386916:security-control/CloudWatch.8/finding/4210f544-cef9-4e21-8b15-4aa153f3f804"
      },
      {
        "Compliance": {
          "Status": "PASSED",
          "SecurityControlId": "CloudWatch.7",
          "RelatedRequirements": [
            "CIS AWS Foundations Benchmark v1.4.0/4.7"
          ],
          "AssociatedStandards": [
            {
              "StandardsId": "standards/cis-aws-foundations-benchmark/v/1.4.0"
            }
          ]
        },
        "Title": "Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs",
        "RecordState": "ACTIVE",
        "Workflow": {
          "Status": "RESOLVED"
        },
        "Severity": {
          "Label": "INFORMATIONAL"
        },
        "Id": "arn:aws:securityhub:us-east-1:401656386916:security-control/CloudWatch.7/finding/0859a9a2-53b9-472c-a08c-23e5b472f795"
      },
      {
        "Compliance": {
          "Status": "PASSED",
          "SecurityControlId": "CloudWatch.6",
          "RelatedRequirements": [
            "CIS AWS Foundations Benchmark v1.4.0/4.6"
          ],
          "AssociatedStandards": [
            {
              "StandardsId": "standards/cis-aws-foundations-benchmark/v/1.4.0"
            }
          ]
        },
        "Title": "Ensure a log metric filter and alarm exist for AWS Management Console authentication failures",
        "RecordState": "ACTIVE",
        "Workflow": {
          "Status": "RESOLVED"
        },
        "Severity": {
          "Label": "INFORMATIONAL"
        },
        "Id": "arn:aws:securityhub:us-east-1:401656386916:security-control/CloudWatch.6/finding/12edeaa0-649c-4c10-8672-e7b9c8ebcb3b"
      },
      {
        "Compliance": {
          "Status": "PASSED",
          "SecurityControlId": "CloudWatch.5",
          "RelatedRequirements": [
            "CIS AWS Foundations Benchmark v1.4.0/4.5"
          ],
          "AssociatedStandards": [
            {
              "StandardsId": "standards/cis-aws-foundations-benchmark/v/1.4.0"
            }
          ]
        },
        "Title": "Ensure a log metric filter and alarm exist for CloudTrail configuration changes",
        "RecordState": "ACTIVE",
        "Workflow": {
          "Status": "RESOLVED"
        },
        "Severity": {
          "Label": "INFORMATIONAL"
        },
        "Id": "arn:aws:securityhub:us-east-1:401656386916:security-control/CloudWatch.5/finding/e4a7b351-90d2-412e-8096-8a59da6b3ce5"
      },
      {
        "Compliance": {
          "Status": "PASSED",
          "SecurityControlId": "CloudWatch.4",
          "RelatedRequirements": [
            "CIS AWS Foundations Benchmark v1.4.0/4.4"
          ],
          "AssociatedStandards": [
            {
              "StandardsId": "standards/cis-aws-foundations-benchmark/v/1.4.0"
            }
          ]
        },
        "Title": "Ensure a log metric filter and alarm exist for IAM policy changes",
        "RecordState": "ACTIVE",
        "Workflow": {
          "Status": "RESOLVED"
        },
        "Severity": {
          "Label": "INFORMATIONAL"
        },
        "Id": "arn:aws:securityhub:us-east-1:401656386916:security-control/CloudWatch.4/finding/df2932e1-6152-4ba4-a78e-73c349f0ea84"
      },
      {
        "Compliance": {
          "Status": "PASSED",
          "SecurityControlId": "CloudWatch.14",
          "RelatedRequirements": [
            "CIS AWS Foundations Benchmark v1.4.0/4.14"
          ],
          "AssociatedStandards": [
            {
              "StandardsId": "standards/cis-aws-foundations-benchmark/v/1.4.0"
            }
          ]
        },
        "Title": "Ensure a log metric filter and alarm exist for VPC changes",
        "RecordState": "ACTIVE",
        "Workflow": {
          "Status": "RESOLVED"
        },
        "Severity": {
          "Label": "INFORMATIONAL"
        },
        "Id": "arn:aws:securityhub:us-east-1:401656386916:security-control/CloudWatch.14/finding/0ccda245-629b-43a4-b06a-f1cd51a79b31"
      },
      {
        "Compliance": {
          "Status": "PASSED",
          "SecurityControlId": "CloudWatch.13",
          "RelatedRequirements": [
            "CIS AWS Foundations Benchmark v1.4.0/4.13"
          ],
          "AssociatedStandards": [
            {
              "StandardsId": "standards/cis-aws-foundations-benchmark/v/1.4.0"
            }
          ]
        },
        "Title": "Ensure a log metric filter and alarm exist for route table changes",
        "RecordState": "ACTIVE",
        "Workflow": {
          "Status": "RESOLVED"
        },
        "Severity": {
          "Label": "INFORMATIONAL"
        },
        "Id": "arn:aws:securityhub:us-east-1:401656386916:security-control/CloudWatch.13/finding/e2131a2e-7c4e-44d8-aa5c-475f5541f705"
      },
      {
        "Compliance": {
          "Status": "PASSED",
          "SecurityControlId": "CloudWatch.12",
          "RelatedRequirements": [
            "CIS AWS Foundations Benchmark v1.4.0/4.12"
          ],
          "AssociatedStandards": [
            {
              "StandardsId": "standards/cis-aws-foundations-benchmark/v/1.4.0"
            }
          ]
        },
        "Title": "Ensure a log metric filter and alarm exist for changes to network gateways",
        "RecordState": "ACTIVE",
        "Workflow": {
          "Status": "RESOLVED"
        },
        "Severity": {
          "Label": "INFORMATIONAL"
        },
        "Id": "arn:aws:securityhub:us-east-1:401656386916:security-control/CloudWatch.12/finding/1e0e3252-1e7d-47b4-b15c-1054bad24413"
      },
      {
        "Compliance": {
          "Status": "PASSED",
          "SecurityControlId": "CloudWatch.11",
          "RelatedRequirements": [
            "CIS AWS Foundations Benchmark v1.4.0/4.11"
          ],
          "AssociatedStandards": [
            {
              "StandardsId": "standards/cis-aws-foundations-benchmark/v/1.4.0"
            }
          ]
        },
        "Title": "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)",
        "RecordState": "ACTIVE",
        "Workflow": {
          "Status": "RESOLVED"
        },
        "Severity": {
          "Label": "INFORMATIONAL"
        },
        "Id": "arn:aws:securityhub:us-east-1:401656386916:security-control/CloudWatch.11/finding/d078bf5d-ef3c-43cf-9e70-aa3f04d0005d"
      },
      {
        "Compliance": {
          "Status": "PASSED",
          "SecurityControlId": "CloudWatch.1",
          "RelatedRequirements": [
            "CIS AWS Foundations Benchmark v1.4.0/1.7",
            "CIS AWS Foundations Benchmark v1.4.0/4.3"
          ],
          "AssociatedStandards": [
            {
              "StandardsId": "standards/cis-aws-foundations-benchmark/v/1.4.0"
            }
          ]
        },
        "Title": "A log metric filter and alarm should exist for usage of the \"root\" user",
        "RecordState": "ACTIVE",
        "Workflow": {
          "Status": "RESOLVED"
        },
        "Severity": {
          "Label": "INFORMATIONAL"
        },
        "Id": "arn:aws:securityhub:us-east-1:401656386916:security-control/CloudWatch.1/finding/a99f3f0b-9dfd-40c9-98e3-b592f2bff206"
      },
      {
        "Compliance": {
          "Status": "PASSED",
          "SecurityControlId": "RDS.3",
          "RelatedRequirements": [
            "CIS AWS Foundations Benchmark v1.4.0/2.3.1"
          ],
          "AssociatedStandards": [
            {
              "StandardsId": "standards/aws-foundational-security-best-practices/v/1.0.0"
            },
            {
              "StandardsId": "standards/cis-aws-foundations-benchmark/v/1.4.0"
            }
          ]
        },
        "Title": "RDS DB instances should have encryption at-rest enabled",
        "RecordState": "ACTIVE",
        "Workflow": {
          "Status": "RESOLVED"
        },
        "Severity": {
          "Label": "INFORMATIONAL"
        },
        "AwsAccountId": "401656386916",
        "Region": "us-east-1",
        "Id": "arn:aws:securityhub:us-east-1:401656386916:security-control/RDS.3/finding/6f8be423-1e1a-4700-b891-4b983ef904de",
        "Resources": [
          {
            "Type": "AwsRdsDbInstance",
            "Id": "arn:aws:rds:us-east-1:401656386916:db:horizon-production",
            "Details": {
              "AwsRdsDbInstance": {
                "StorageEncrypted": true,
                "DBInstanceIdentifier": "horizon-production",
                "Engine": "sqlserver-se",
                "MultiAz": true
              }
            }
          }
        ]
      },
      {
        "Compliance": {
          "Status": "PASSED",
          "SecurityControlId": "RDS.3",
          "RelatedRequirements": [
            "CIS AWS Foundations Benchmark v1.4.0/2.3.1"
          ],
          "AssociatedStandards": [
            {
              "StandardsId": "standards/aws-foundational-security-best-practices/v/1.0.0"
            },
            {
              "StandardsId": "standards/cis-aws-foundations-benchmark/v/1.4.0"
            }
          ]
        },
        "Title": "RDS DB instances should have encryption at-rest enabled",
        "RecordState": "ACTIVE",
        "Workflow": {
          "Status": "RESOLVED"
        },
        "Severity": {
          "Label": "INFORMATIONAL"
        },
        "AwsAccountId": "401656386916",
        "Region": "us-east-1",
        "Id": "arn:aws:securityhub:us-east-1:401656386916:security-control/RDS.3/finding/748fbb09-000e-48cb-b417-96676d25840d",
        "Resources": [
          {
            "Type": "AwsRdsDbInstance",
            "Id": "arn:aws:rds:us-east-1:401656386916:db:horizon-db-restore",
            "Details": {
              "AwsRdsDbInstance": {
                "StorageEncrypted": true,
                "DBInstanceIdentifier": "horizon-db-restore",
                "Engine": "sqlserver-se",
                "MultiAz": false
              }
            }
          }
        ]
      },
      {
        "Compliance": {
          "Status": "PASSED",
          "SecurityControlId": "S3.5",
          "RelatedRequirements": [
            "CIS AWS Foundations Benchmark v1.4.0/2.1.2"
          ],
          "AssociatedStandards": [
            {
              "StandardsId": "standards/aws-foundational-security-best-practices/v/1.0.0"
            },
            {
              "StandardsId": "standards/cis-aws-foundations-benchmark/v/1.4.0"
            }
          ]
        },
        "Title": "S3 general purpose buckets should require requests to use SSL",
        "RecordState": "ACTIVE",
        "Workflow": {
          "Status": "RESOLVED"
        },
        "Severity": {
          "Label": "INFORMATIONAL"
        },
        "Id": "arn:aws:securityhub:us-east-1:401656386916:security-control/S3.5/finding/5f42be24-a3af-4e84-9425-63f54643dff1",
        "Resources": [
          {
            "Type": "AwsS3Bucket",
            "Id": "arn:aws:s3:::spektrum-underwriter-report"
          }
        ]
      },
      {
        "Compliance": {
          "Status": "PASSED",
          "SecurityControlId": "S3.5",
          "RelatedRequirements": [
            "CIS AWS Foundations Benchmark v1.4.0/2.1.2"
          ],
          "AssociatedStandards": [
            {
              "StandardsId": "standards/aws-foundational-security-best-practices/v/1.0.0"
            },
            {
              "StandardsId": "standards/cis-aws-foundations-benchmark/v/1.4.0"
            }
          ]
        },
        "Title": "S3 general purpose buckets should require requests to use SSL",
        "RecordState": "ACTIVE",
        "Workflow": {
          "Status": "RESOLVED"
        },
        "Severity": {
          "Label": "INFORMATIONAL"
        },
        "Id": "arn:aws:securityhub:us-east-1:401656386916:security-control/S3.5/finding/db281411-3de5-4071-b3b0-a0b3f10723a5",
        "Resources": [
          {
            "Type": "AwsS3Bucket",
            "Id": "arn:aws:s3:::testfors3horizon"
          }
        ]
      },
      {
        "Compliance": {
          "Status": "PASSED",
          "SecurityControlId": "S3.5",
          "RelatedRequirements": [
            "CIS AWS Foundations Benchmark v1.4.0/2.1.2"
          ],
          "AssociatedStandards": [
            {
              "StandardsId": "standards/aws-foundational-security-best-practices/v/1.0.0"
            },
            {
              "StandardsId": "standards/cis-aws-foundations-benchmark/v/1.4.0"
            }
          ]
        },
        "Title": "S3 general purpose buckets should require requests to use SSL",
        "RecordState": "ACTIVE",
        "Workflow": {
          "Status": "RESOLVED"
        },
        "Severity": {
          "Label": "INFORMATIONAL"
        },
        "Id": "arn:aws:securityhub:us-east-1:401656386916:security-control/S3.5/finding/9915f2a0-0e5b-4b6c-9dfb-0c306b3d4157",
        "Resources": [
          {
            "Type": "AwsS3Bucket",
            "Id": "arn:aws:s3:::spektrum-config"
          }
        ]
      },
      {
        "Compliance": {
          "Status": "PASSED",
          "SecurityControlId": "S3.5",
          "RelatedRequirements": [
            "CIS AWS Foundations Benchmark v1.4.0/2.1.2"
          ],
          "AssociatedStandards": [
            {
              "StandardsId": "standards/aws-foundational-security-best-practices/v/1.0.0"
            },
            {
              "StandardsId": "standards/cis-aws-foundations-benchmark/v/1.4.0"
            }
          ]
        },
        "Title": "S3 general purpose buckets should require requests to use SSL",
        "RecordState": "ACTIVE",
        "Workflow": {
          "Status": "RESOLVED"
        },
        "Severity": {
          "Label": "INFORMATIONAL"
        },
        "Id": "arn:aws:securityhub:us-east-1:401656386916:security-control/S3.5/finding/e72b3893-37a0-4490-a3d1-9e46b9f0263c",
        "Resources": [
          {
            "Type": "AwsS3Bucket",
            "Id": "arn:aws:s3:::spektrum-datadog-forwarder-product-forwarderbucket-vppm0322pjqr"
          }
        ]
      }
    ],
    "NextToken": "U2FsdGVkX1+XE2xsEP/ruNGEEeGOJjfz45pqBwUpvT+...(truncated)"
  }
}
