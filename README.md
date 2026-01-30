# Analysis Tool

This project converts multiple evidence sources into OCSF NDJSON using plugins (detect/parse/map/pipeline).

## Webapp connector startup

When you start the FastAPI webapp, it automatically launches the Sysmon and Windows Security
connectors (and reuses any already-running instances on their default ports). The Elastic
connector is also launched when the webapp starts (and reuses any existing instance on port 8789),
as long as you provide Elasticsearch credentials via environment variables. No manual
`python -m app.connectors.*` invocation is required. On Windows, Sysmon and Security event
collection may require running the webapp as Administrator, especially for the Windows
Security connector. If the Security connector fails to start, check
`/api/connectors/logs?name=security` for a clear error message.

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

Each line is a RawEvent envelope (v1.0). Example:

```json
{"envelope_version":"1.0","source":{"type":"sysmon","vendor":"microsoft","product":"sysmon","channel":"Microsoft-Windows-Sysmon/Operational","collector":{"name":"sysmon-connector","instance_id":"HOSTNAME:sysmon","host":"HOSTNAME"}},"event":{"time":{"observed_utc":"2024-01-02T03:04:06.000Z","created_utc":"2024-01-02T03:04:05.678Z"},"ids":{"record_id":123,"event_id":1,"activity_id":null,"correlation_id":null,"dedupe_hash":"sha256:ee29a3127270e1471e2bae6a6d7a4d321cbffc4af988544c64aac088ce1b0acf"},"host":{"hostname":"HOSTNAME","os":"windows","timezone":"UTC+0000"},"severity":"information","tags":["live","sysmon"]},"raw":{"format":"xml","data":"<Event>...</Event>","rendered_message":null}}
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

## Elastic SIEM Connector (Local Elasticsearch)

This repository includes a read-only Elastic connector that continuously exports raw Elasticsearch
documents (no OCSF normalization) to NDJSON and maintains a checkpoint to avoid duplicates.

### Prerequisites

- Local Elasticsearch reachable at `http://127.0.0.1:9200`.
- Credentials (Basic auth) via `ELASTIC_PASSWORD` (username defaults to `elastic`).
- Python 3.11+.

### Run

```bash
export ELASTIC_PASSWORD="your_password"
python -m app.connectors.elastic --poll-seconds 10 --max-events 500 --http-port 8789
```

Override indices and starting window if needed:

```bash
python -m app.connectors.elastic --indices "logs-*-default*" --start-ago-seconds 3600 --http-port 8789
```

You can also override the default index pattern with the `ELASTIC_INDEX` environment variable.

### Output

Events are appended to daily NDJSON files:

```
out/raw/siem/elastic/local/<index>/<YYYY>/<MM>/<DD>/events.ndjson
```

Checkpoint state is stored at:

```
state/elastic_checkpoint.json
```

### Reset checkpoint

Stop the connector, then delete the checkpoint file:

```bash
rm state/elastic_checkpoint.json
```

The next run will re-export from the configured `--start-ago-seconds` window.

### Webapp verification polling

```bash
GET http://127.0.0.1:8789/status
GET http://127.0.0.1:8789/tail?limit=20
```

### How to generate test SIEM logs (Kibana Dev Tools)

Use Kibana Dev Tools (Console) to insert documents into a data stream such as
`logs-test-default`. Replace `<id>` with a unique id and adjust fields as needed:

```json
POST logs-test-default/_create/<id>
{
  "@timestamp": "2024-06-07T12:34:56Z",
  "event": {
    "dataset": "test",
    "kind": "event",
    "action": "sample"
  },
  "message": "Test SIEM log entry from Kibana Dev Tools."
}
```

## Documentation
- [Digital Evidence Coverage Framework](docs/evidence_coverage_framework.md)
