# Tenable Attack Surface Management — transformations

26 criteria, every one computed from data the Tenable ASM API actually returns. Each file is
standalone (repo convention), implements `transform(input)`, and returns the v1.0 response contract
(`transformedResponse` + `additionalInfo{dataCollection, validation, transformation, evaluation, metadata}`).

## Where the data comes from — four calls, no request body

| method | call | note |
|---|---|---|
| `getInventorySummary` | `POST /api/1.0/inventory?columns=id&limit=1` | envelope only: `total`, `stats` |
| `getInventory` | `POST /api/1.0/inventory?columns=…&limit=10000` | every asset, cursor-paged on `sortAfter` → `after` |
| `getSources` | `GET /api/1.0/sources` | discovery sources |
| `getSmartFolders` | `GET /api/1.0/smartfolders` | saved queries |
| `getAssetProperties` | `GET /api/1.0/columns` | available + custom asset properties |
| `getAzureKeys` | `GET /api/1.0/business/azure-keys` | cloud connectors |

`POST /inventory` is sent **with no body**: *"If no filters are provided, the API returns all assets"*
([asm-filtering](https://developer.tenable.com/docs/asm-filtering)). This matters — the engine's mapper
cannot produce a top-level JSON array, so a filter body is not expressible in a definition. Filtering
is therefore done in the transformation, over the full asset list, which also costs one API call
instead of seven.

## Criteria

**Discovery & coverage** — `confirmedLicensePurchased`, `isASMEnabled`, `isContinuousDiscoveryEnabled`
(newest `bd.last_metadata_change` ≤ 7d), `isUnmanagedAssetDiscoveryEnabled`, `activeIntegrationsCount`,
`isCloudConnectorConfigured` (Azure keys — configuration, not inferred from assets),
`isCloudAssetDiscoveryEnabled`.

**Risk & prioritisation** — `isRiskPrioritizationTrue`, `noCriticalFindings`, `noHighFindings`.

**Exposure** — `assetsWithKnownCvesCount` (`ports.cves`), `expiredCertificateCount`,
`certificateExpiringSoonCount` (≤30d, expired counted apart), `sslErrorCount`,
`exposedAdminPortsCount` (22/23/445/3389/3306/5432/6379/9200/27017/…), `exposedSecretKeysCount`
(`wtech.secretkeys` — keys leaked in page source), `assetsOnBlocklistCount` (`rbls.rbls`),
`exposedLoginPagesCount`, `mixedContentAssetsCount`, `vulnerableWordPressCount`,
`isWebApplicationFirewallDeployed`, `domainExpiringSoonCount` (hijack risk).

**Governance** — `isShadowITAssetTaggingEnabled`, `assetTriageBacklogCount` (added ≤30d, still
untagged), `isSavedQueryMonitoringEnabled`, `isCustomColumnsConfigured`.

## Honesty rules these files follow

* A count is **never** taken from a filtered `total` — it is counted from the assets in hand.
* When the pages held are fewer than the envelope's `total`, the result carries
  `partial: true` and a `note` saying the count is a lower bound. Tested.
* A criterion with no fact behind it in this API is **absent** — no transformation, no criteria key,
  no attestation standing in for one. Thirteen of the original bundle's keys are gone for this reason
  (KEV correlation, RBAC, subsidiary discovery, attack-path validation, audit logging, …).

## Tests

51 fixture runs, 0 raised. The primary fixture is Tenable's **own documented `POST /inventory`
response**, field for field. Every positive branch is proven to fire — admin ports, near-expiry
certificates, untriaged backlog and the partial-page lower bound each have a case that returns
non-zero, so none of these is a test that can only pass.
