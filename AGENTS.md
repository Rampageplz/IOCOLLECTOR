# AGENTS Instructions

This repository contains collectors for multiple Threat Intelligence feeds.

## Guidelines for Codex
- Run `python -m ioc_collector.main` before every commit to ensure collectors work.
- Keep documentation in `README.md` updated whenever behavior changes.
- Use environment variables or `config.json` to configure collectors.
- Log output is stored in `logs/`.

## Feature status
The initial sprint added a reporting module with several options.

### Completed
- Rich tables for summary, duplicates and top IOCs.
- Exports to JSON, CSV, TXT, PDF and XLSX.
- CLI filters `--type`, `--source`, `--top-count` and `--all`.
- Friendly message when no data is found.
- `Report` dataclass for consistent output.
- README examples for generating reports.

### Pending
 - Dashboard/API integrations and alert notifications.

### Completed in Sprint 1
 - Flags `--only-duplicates` and `--only-top`.
 - Coverage analysis with feed percentages.
 - Missing feeds detection and insights section.

### Next steps
- Add asynchronous collectors for performance.
- Provide dashboard visualization for reports.
- Improve documentation about the new `--value` and `--sort` options.

To update these instructions send a pull request editing this file.
