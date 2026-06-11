# Data Schema

Schema version: `0.1.0`

The JSON and HTML reports are produced by `src/main.ps1` through the normalizer
and masking pipeline. Collector data is read-only and suitable for
`ConvertTo-Json`.

## Top-Level Object

| Field | Type | Description |
| --- | --- | --- |
| `SchemaVersion` | string | Report schema version. |
| `ToolName` | string | Tool display name. |
| `GeneratedAtUtc` | string | Report generation timestamp in ISO 8601 UTC format. |
| `ReadOnlyMode` | boolean | Always `true`; the tool does not alter licensing or system state. |
| `System` | object | Operating system and environment metadata. |
| `Hardware` | object | Hardware inventory metadata. |
| `WindowsLicense` | object | Windows license collector output. |
| `OfficeLicense` | object | Office license collector output. |
| `SuspiciousIndicators` | object | Suspicious indicator collector output. |
| `Rules` | object | Rule evaluation verdicts and overall risk. |

## System

| Field | Type | Description |
| --- | --- | --- |
| `CollectorName` | string | `System`. |
| `Status` | string | `Complete` or `Partial`. |
| `ExtractionTimeUtc` | string | Collector extraction timestamp in ISO 8601 UTC format. |
| `ComputerName` | string/null | Computer name. |
| `LoggedInUser` | string/null | Logged-in user; exported as `<REDACTED_USER>` when present. |
| `DomainOrWorkgroup` | string/null | Joined domain or workgroup name. |
| `OsCaption` | string/null | Operating system caption. |
| `OsVersion` | string/null | Operating system version. |
| `BuildNumber` | string/null | Operating system build number. |
| `Architecture` | string/null | Operating system architecture. |
| `InstallDate` | string/null | OS install date in ISO 8601 UTC format. |
| `Warnings` | array | Non-fatal collection warnings. |

## Hardware

| Field | Type | Description |
| --- | --- | --- |
| `CollectorName` | string | `Hardware`. |
| `Status` | string | `Complete` or `Partial`. |
| `Manufacturer` | string/null | Computer manufacturer. |
| `Model` | string/null | Computer model. |
| `CpuName` | string/null | Primary CPU name. |
| `TotalRamGb` | number/null | Total physical memory in GB. |
| `Motherboard` | object | Motherboard manufacturer, product, and serial number. |
| `BiosSerialNumber` | string/null | BIOS serial number. |
| `PhysicalDisks` | array | Physical disk model and serial number objects. |
| `ActiveMacAddresses` | array | MAC addresses for enabled adapters. |
| `Warnings` | array | Non-fatal collection warnings. |

Serial-like values are exported with only the first 3 and last 4 characters
visible. MAC addresses are exported with the middle bytes masked, for example
`AA:BB:XX:XX:XX:FF`.

## WindowsLicense

| Field | Type | Description |
| --- | --- | --- |
| `CollectorName` | string | `WindowsLicense`. |
| `Status` | string | `Complete` or `Partial`. |
| `WindowsCaption` | string/null | Windows operating system caption from `Win32_OperatingSystem`. |
| `Version` | string/null | Windows version. |
| `BuildNumber` | string/null | Windows build number. |
| `Architecture` | string/null | Windows architecture. |
| `ProductId` | string/null | Windows product ID, not a full product key. |
| `LicenseName` | string/null | Windows licensing product name. |
| `LicenseDescription` | string/null | Windows licensing product description. |
| `LicenseStatusCode` | number/null | Raw Software Protection Platform license status code. |
| `LicenseStatusText` | string/null | Friendly license status text. |
| `PartialProductKey` | string/null | Partial product key reported by Software Protection Platform. Full product keys are never collected. |
| `GracePeriodRemaining` | number/null | Grace period remaining, when reported by CIM. |
| `OemKeyPresent` | boolean | Whether `OA3xOriginalProductKey` exists. The full OEM key is not exported. |
| `KmsHost` | string/null | KMS host, when reported by CIM. |
| `KmsPort` | number/string/null | KMS port, when reported by CIM. |
| `Diagnostics` | object | Raw read-only `slmgr /xpr` and `slmgr /dlv` output for troubleshooting. Parsing is intentionally minimal because output can be localized. |
| `Warnings` | array | Non-fatal collection warnings. |

`WindowsLicense.Diagnostics` contains `SlmgrXpr` and `SlmgrDlv` strings. These
commands are read-only diagnostics; the tool does not call activation, key
installation, key removal, rearm, or licensing modification commands.

## OfficeLicense

| Field | Type | Description |
| --- | --- | --- |
| `CollectorName` | string | `OfficeLicense`. |
| `Status` | string | `Complete`, `Partial`, or `NotDetected`. |
| `OfficeDetected` | boolean | Whether a supported `OSPP.VBS` script was found. |
| `OsppVbsPaths` | array | Detected Office licensing script paths. |
| `PathsChecked` | array | Common Office 2013/2016 script paths checked by the collector. |
| `Products` | array | Parsed Office licensing products from `ospp.vbs /dstatusall`. |
| `Diagnostics` | array | Raw read-only `ospp.vbs /dstatusall` outputs, grouped by script path. |
| `Warnings` | array | Non-fatal command or parse warnings. |

Each `OfficeLicense.Products` item contains:

| Field | Type | Description |
| --- | --- | --- |
| `ProductName` | string/null | Best-effort product name. When not reported directly, this is derived from the license name. |
| `LicenseName` | string/null | Office license name. |
| `LicenseDescriptionOrChannel` | string/null | License description or channel text. |
| `LicenseStatus` | string/null | License status text reported by OSPP. |
| `InstalledProductKeyLast5` | string/null | Last five characters of the installed product key. Full Office product keys are never collected. |
| `KmsMachineName` | string/null | KMS machine name, when reported by OSPP. |
| `RemainingGrace` | string/null | Remaining grace period, when reported by OSPP. |
| `OsppPath` | string | `OSPP.VBS` path that produced the product record. |

If no supported `OSPP.VBS` file is found, the collector returns `Status:
NotDetected`, `OfficeDetected: false`, empty product and diagnostic arrays, and
no error.

## SuspiciousIndicators

| Field | Type | Description |
| --- | --- | --- |
| `CollectorName` | string | `SuspiciousIndicators`. |
| `Status` | string | `Complete` or `Partial`. |
| `DeepScanRequested` | boolean | Whether `-IncludeSuspiciousScan` requested the optional limited file scan. |
| `FileScanPerformed` | boolean | Whether the optional limited file-name scan ran. |
| `FileScanRoots` | array | Limited scan roots. The collector never scans the whole `C:\` drive. |
| `FileScanMaxDepth` | number | Maximum file scan recursion depth. Default is `2` when enabled. |
| `KeywordsLoaded` | number | Number of suspicious keywords loaded from `config/suspicious-keywords.json`. |
| `Indicators` | array | Matched read-only indicators. |
| `Warnings` | array | Non-fatal collection or access warnings. |

Each `SuspiciousIndicators.Indicators` item contains:

| Field | Type | Description |
| --- | --- | --- |
| `Source` | string | Source category such as `InstalledApplication`, `RunningProcess`, `WindowsService`, `ScheduledTask`, `StartupEntry`, or `LimitedFileScan`. |
| `MatchedKeyword` | string | Keyword matched from `config/suspicious-keywords.json`. |
| `ItemName` | string/null | Matched item display name, process name, task name, service name, or file name. |
| `ItemPathMasked` | string/null | Related path or command with usernames masked as `<REDACTED_USER>`. |
| `RiskWeight` | number | Keyword risk weight from configuration. |
| `EvidenceType` | string | Evidence category, for example `RegistryUninstallEntry`, `Process`, `Service`, `ScheduledTask`, `RegistryRunEntry`, or `FileName`. |

The optional file scan checks file names and paths only. It does not open file
contents, scan the whole drive, delete files, quarantine files, stop services,
or modify tasks or registry values.

## Rules

| Field | Type | Description |
| --- | --- | --- |
| `windowsVerdict` | string | Windows license verdict. |
| `officeVerdict` | string | Office license verdict. |
| `suspiciousIndicatorVerdict` | string | Suspicious indicator verdict. |
| `overallRisk` | string | Overall risk verdict. |
| `riskScore` | number | Additive evidence-based risk score. |
| `reasons` | array | Evidence-based reasons for the verdicts. |
| `recommendations` | array | Recommended manual review or remediation steps. |

Verdict values are `CLEAN`, `GENUINE_LIKELY`,
`ACTIVATED_REVIEW_REQUIRED`, `NOT_ACTIVATED`, `SUSPICIOUS`, `HIGH_RISK`,
and `NEED_MANUAL_REVIEW`.

Risk scoring uses these additive signals:

| Signal | Points |
| --- | ---: |
| License not activated | 40 |
| Non-genuine grace | 80 |
| KMS host not trusted | 35 |
| Suspicious installed application | 25 |
| Suspicious process, service, or scheduled task | 40 |
| Suspicious file name only | 10 |
| Office notifications status | 40 |

Trusted KMS hosts are loaded from `config/trusted-kms-hosts.json`. The rule
engine uses evidence-based language and does not make absolute legal
conclusions.

## HTML Report

`src/report/HtmlReport.ps1` renders the masked normalized report object with
`src/report/templates/report.template.html`. The HTML report uses an A4 layout,
Times New Roman, 13pt text, administrative-style tables, and a section named
`Nhận xét tự động của công cụ`.

The renderer escapes all inserted values and intentionally omits raw diagnostic
command output. It consumes the already-masked report object so usernames,
serial-like values, MAC addresses, and key-like values remain protected.
