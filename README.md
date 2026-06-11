# Windows License Audit Tool

A read-only Windows and Office license audit tool.

The tool exports:

- A normalized JSON report.
- An administrative-style HTML report that opens in the default browser when using the runner script.

The tool is designed for audit and review. It does not activate, deactivate, install keys, remove keys, delete files, stop services, modify scheduled tasks, or change licensing state.

## Quick Start

Open PowerShell in the project folder and run:

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\run-audit.ps1
```

This exports JSON and HTML reports to `exports\` and opens the HTML report in your default browser.

Run without opening the browser:

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\run-audit.ps1 -NoOpen
```

Run with the optional suspicious indicator file-name scan:

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\run-audit.ps1 -IncludeSuspiciousScan
```

Use a custom output directory:

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\run-audit.ps1 -OutputDir C:\Temp\AuditReports
```

For a short Vietnamese end-user guide, see [huong_dan.md](huong_dan.md).

## Execution Policy

If PowerShell blocks scripts, use a temporary process-level bypass:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\run-audit.ps1
```

Or run the script directly with:

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\run-audit.ps1
```

The `-Scope Process` option only applies to the current PowerShell window.

## What It Collects

The collectors gather read-only audit data:

- System information: extraction time, computer name, logged-in user, domain/workgroup, OS caption, version, build number, architecture, install date.
- Hardware information: manufacturer, model, CPU, RAM, motherboard, BIOS serial, physical disks, active MAC addresses.
- Windows licensing information from CIM and read-only `slmgr` diagnostics.
- Office licensing information from read-only `ospp.vbs /dstatusall`, when Office licensing scripts are present.
- Suspicious activation-related indicators from installed apps, processes, services, scheduled tasks, startup entries, and optional limited file-name scanning.

## Data Protection

Sensitive values are masked before report export:

- Usernames become `<REDACTED_USER>`.
- MAC addresses have middle bytes masked.
- Serial-like values show only the first 3 and last 4 characters.
- Full product-key-like values are masked.
- Full Windows, Office, and OEM product keys are never collected or printed.

See [docs/privacy.md](docs/privacy.md) for details.

## Reports

Reports are written to `exports\` by default:

- `windows-license-audit-*.json`: normalized machine-readable data.
- `windows-license-audit-*.html`: administrative-style report for review.

The HTML report includes:

- Title and extraction metadata.
- PC name and logged-in account.
- Hardware fingerprint table.
- Windows/license table.
- Office/license table.
- Automatic comments/verdict section.
- Signature section.

## Rule Engine

Collectors only collect data. The rule engine produces verdicts and risk scoring.

Verdicts include:

- `CLEAN`
- `GENUINE_LIKELY`
- `ACTIVATED_REVIEW_REQUIRED`
- `NOT_ACTIVATED`
- `SUSPICIOUS`
- `HIGH_RISK`
- `NEED_MANUAL_REVIEW`

Trusted KMS hosts are configured in [config/trusted-kms-hosts.json](config/trusted-kms-hosts.json). KMS results require organization context and should be reviewed by an administrator.

See [docs/limitations.md](docs/limitations.md) for interpretation limits.

## Suspicious Indicator Scan

Suspicious keyword matching uses [config/suspicious-keywords.json](config/suspicious-keywords.json).

The default run checks:

- Installed application uninstall registry keys.
- Running processes.
- Windows services.
- Scheduled tasks.
- Startup `Run` and `RunOnce` registry keys.

`-IncludeSuspiciousScan` also enables a limited file-name scan in:

- `C:\ProgramData`
- Current user's Desktop
- Current user's Downloads
- Current user's AppData Local
- Current user's AppData Roaming

The file scan does not scan the whole `C:\` drive and does not open file contents.

## Tests

Rule-engine tests use Pester and fixture JSON files under `tests\fixtures`. They do not query the local machine.

Run Pester tests:

```powershell
Invoke-Pester .\tests\RuleEngine.Tests.ps1
```

Run the lightweight fallback test script:

```powershell
.\tests\Invoke-RuleEngineTests.ps1
```

## Packaging

To move the tool to another machine, copy the whole project folder and keep this structure:

```text
windows-license-audit-tool/
├── run-audit.ps1
├── src/
├── config/
├── docs/
├── tests/
└── README.md
```

Then run:

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\run-audit.ps1
```

## Project Layout

```text
windows-license-audit-tool/
├── run-audit.ps1
├── src/
│   ├── main.ps1
│   ├── collectors/
│   ├── rules/
│   ├── report/
│   └── utils/
├── config/
├── docs/
├── tests/
├── exports/
├── huong_dan.md
└── README.md
```

## Safety Boundary

This tool must remain read-only. Any command or code path that activates software, changes keys, deletes files, removes software, stops services, modifies scheduled tasks, or changes licensing policy is out of scope.
