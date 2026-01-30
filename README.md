# Analysis Tool

This project converts multiple evidence sources into OCSF NDJSON using plugins (detect/parse/map/pipeline).

## Sysmon Direct Endpoint Connector

This repository includes a Windows Sysmon connector that continuously exports raw Sysmon events (no OCSF normalization) to NDJSON and maintains a checkpoint to avoid duplicates.

### Prerequisites

- Sysmon installed and logging to `Microsoft-Windows-Sysmon/Operational`.
- Administrative PowerShell access to read the Sysmon channel.
- Python 3.11+.

### Install

```bash
pip install pywin32
```

If `pywin32` is unavailable, the connector falls back to PowerShell `Get-WinEvent`.

### Run

```bash
python -m app.connectors.sysmon --poll-seconds 5 --max-events 500
```

Enable the optional local verification server (binds to 127.0.0.1 only):

```bash
python -m app.connectors.sysmon --poll-seconds 5 --max-events 500 --http-port 8787
```

### Output

Events are appended to daily NDJSON files:

```
out/raw/endpoint/windows_sysmon/<hostname>/<YYYY>/<MM>/<DD>/events.ndjson
```

Checkpoint state is stored at:

```
state/sysmon_checkpoint.json
```

### Reset checkpoint

Stop the connector, then delete the checkpoint file:

```bash
rm state/sysmon_checkpoint.json
```

The next run will re-export from the current log start (no duplicates beyond the reset).

### Webapp verification polling

```bash
GET http://127.0.0.1:<port>/status
GET http://127.0.0.1:<port>/tail?limit=20
```

## Windows Security Direct Endpoint Connector

This repository includes a Windows Security connector that continuously exports raw Security events (no OCSF normalization) to NDJSON and maintains a checkpoint to avoid duplicates.

### Prerequisites

- Administrative PowerShell access to read the `Security` channel.
- Python 3.11+.

### Install

```bash
pip install pywin32
```

If `pywin32` is unavailable, the connector falls back to PowerShell `Get-WinEvent`.

### Run

```bash
python -m app.connectors.security --poll-seconds 5 --max-events 500
```

Enable the optional local verification server (binds to 127.0.0.1 only):

```bash
python -m app.connectors.security --poll-seconds 5 --max-events 500 --http-port 8788
```

### Output

Events are appended to daily NDJSON files:

```
out/raw/endpoint/windows_security/<hostname>/<YYYY>/<MM>/<DD>/events.ndjson
```

Checkpoint state is stored at:

```
state/security_checkpoint.json
```

### Reset checkpoint

Stop the connector, then delete the checkpoint file:

```bash
rm state/security_checkpoint.json
```

The next run will re-export from the current log start (no duplicates beyond the reset).

### Webapp verification polling

```bash
GET http://127.0.0.1:<port>/status
GET http://127.0.0.1:<port>/tail?limit=20
```

## Documentation
- [Digital Evidence Coverage Framework](docs/evidence_coverage_framework.md)
