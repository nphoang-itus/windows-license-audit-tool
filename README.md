# Windows License Audit Tool

Initial skeleton for a read-only Windows and Office license audit tool.

The first supported output is a normalized JSON report. HTML, DOCX, and PDF reports are planned for later.

## Scope

The tool is designed to collect:

- System information
- Hardware information
- Windows license information
- Office license information
- Suspicious indicator information
- Rule-engine findings

Current collectors and rules are placeholders. Deep scanning is not implemented yet.

## Safety Rules

This tool must remain read-only. It must not:

- Activate or deactivate Windows or Office
- Install, remove, or modify product keys
- Delete files
- Remove software
- Stop services
- Modify scheduled tasks
- Change registry policy or licensing state

Sensitive values such as serial numbers, MAC addresses, usernames, SIDs, and product keys are masked before JSON export.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Run from a PowerShell session with permission to write to the selected output directory

No external PowerShell modules are required for the current skeleton.

## Usage

From the project root:

```powershell
.\src\main.ps1
```

Specify a report directory:

```powershell
.\src\main.ps1 -OutputDir .\exports
```

Request suspicious indicator placeholders:

```powershell
.\src\main.ps1 -IncludeSuspiciousScan
```

Enable verbose logging:

```powershell
.\src\main.ps1 -VerboseMode
```

Combine options:

```powershell
.\src\main.ps1 -OutputDir .\exports -IncludeSuspiciousScan -VerboseMode
```

## Project Layout

```text
windows-license-audit-tool/
├── src/
│   ├── main.ps1
│   ├── collectors/
│   ├── rules/
│   ├── report/
│   └── utils/
├── config/
├── exports/
├── tests/
├── docs/
└── README.md
```

## Development Notes

Add future collector implementations behind the existing placeholder functions. Prefer read-only APIs such as CIM/WMI queries and registry reads where appropriate. Any future command that can modify licensing state is out of scope for this tool.

Report generation should continue to use the normalized schema emitted before JSON export, so later HTML, DOCX, and PDF renderers share one data contract.
