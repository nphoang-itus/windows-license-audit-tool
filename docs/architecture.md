# Architecture

This project starts as a read-only JSON audit tool. The initial code is intentionally shallow and uses placeholders for collectors and rules.

## Pipeline

1. `src/main.ps1` loads all local modules.
2. Collector modules return read-only placeholder objects.
3. `src/report/Normalizer.ps1` converts collector output into a stable schema.
4. Rule modules return advisory findings.
5. `src/utils/Masking.ps1` masks sensitive values before export.
6. `src/report/JsonReport.ps1` writes the normalized JSON report.

## Read-Only Boundary

The tool must not activate Windows or Office, deactivate products, install or remove product keys, delete files, remove software, stop services, or alter scheduled tasks and policies.

The only expected write operation is creating an output directory and writing report files to it.
