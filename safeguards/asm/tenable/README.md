# Tenable Attack Surface Management — transformations

Twelve criteria the Tenable ASM API (`asm.cloud.tenable.com/api/1.0`) can actually answer. Each file is
standalone (repo convention), implements `transform(input)`, and returns the v1.0 response contract
(`transformedResponse` + `additionalInfo{dataCollection, validation, transformation, evaluation, metadata}`).

| criteriaKey | method | reads |
|---|---|---|
| confirmedLicensePurchased | verifyConnection `GET /sources` | a readable source list |
| isASMEnabled | getInventorySummary `POST /inventory limit=1` | `total` |
| isContinuousDiscoveryEnabled | getRecentlyChangedAssets | newest `bd.last_metadata_change` ≤ 7 days |
| isUnmanagedAssetDiscoveryEnabled | getInventorySummary | `stats.subdomaincount`, `total` vs `stats.domaincount` |
| isRiskPrioritizationTrue | getRecentlyChangedAssets | `bd.severity_ranking` populated on the sample |
| noCriticalFindings | getCriticalAssets (filter `bd.severity_ranking is critical`) | `total` == 0 |
| noHighFindings | getHighAssets (filter `… is high`) | `total` == 0 |
| activeIntegrationsCount | getSources | number of sources |
| isCloudAssetDiscoveryEnabled | getCloudHostedAssets (filter `ipgeo.cloudhosted is true`) | `total` > 0 |
| isShadowITAssetTaggingEnabled | getTaggedAssets | `bd.tags` / custom columns in use |
| certificateExpiringSoonCount | getCertificateInventory | `ssl.valid_to` within 30 days (expired counted apart) |
| isSavedQueryMonitoringEnabled | getSmartFolders `GET /smartfolders` | at least one folder |

Counts read the API's `total`, never `len(assets)`, and record when a single 10 000-row page is a lower
bound. Thirteen other criteria in the ASM requirement set have no fact behind them in this API and are
deliberately **not** here — see `Integration-Service/integration_configs/asm/tenable-attack-surface-management.json`
`notMeasurable`. A transformation for those would be reading fields the API does not return.

Fixtures: 25 (pass + fail per key, engine envelope and bare response), all green via `transform()`.
