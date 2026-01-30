from __future__ import annotations

import subprocess
import sys
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Iterable

from app.utils.timeutil import utc_now_iso


@dataclass(frozen=True)
class ConnectorSpec:
    name: str
    module: str
    port: int


CONNECTOR_REGISTRY: list[ConnectorSpec] = [
    ConnectorSpec(name="sysmon", module="app.connectors.sysmon", port=8787),
    ConnectorSpec(name="security", module="app.connectors.security", port=8788),
]

CONNECTOR_DEFAULT_ARGS: list[str] = ["--poll-seconds", "5", "--max-events", "500"]


class ConnectorManager:
    def __init__(
        self,
        registry: Iterable[ConnectorSpec] | None = None,
        default_args: Iterable[str] | None = None,
    ) -> None:
        self._registry = list(registry or CONNECTOR_REGISTRY)
        self._default_args = list(default_args or CONNECTOR_DEFAULT_ARGS)
        self._started: dict[str, subprocess.Popen[str]] = {}
        self._last_health_check: dict[str, str] = {}
        self._lock = threading.Lock()

    def startup(self) -> None:
        for spec in self._registry:
            if self._check_health(spec):
                continue
            self._start_connector(spec)

    def shutdown(self) -> None:
        for name, proc in list(self._started.items()):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        self._started.clear()

    def status(self) -> list[dict[str, object]]:
        statuses: list[dict[str, object]] = []
        for spec in self._registry:
            is_running = self._check_health(spec)
            proc = self._started.get(spec.name)
            pid = proc.pid if proc and proc.poll() is None else None
            statuses.append(
                {
                    "name": spec.name,
                    "port": spec.port,
                    "running": is_running,
                    "pid": pid,
                    "last_health_check_utc": self._last_health_check.get(spec.name),
                }
            )
        return statuses

    def _check_health(self, spec: ConnectorSpec) -> bool:
        url = f"http://127.0.0.1:{spec.port}/health"
        self._last_health_check[spec.name] = utc_now_iso()
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                return 200 <= response.status < 300
        except (urllib.error.URLError, TimeoutError):
            return False

    def _start_connector(self, spec: ConnectorSpec) -> None:
        with self._lock:
            if spec.name in self._started:
                return
            command = [
                sys.executable,
                "-m",
                spec.module,
                *self._default_args,
                "--http-port",
                str(spec.port),
            ]
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self._started[spec.name] = process
            self._attach_logger(spec.name, process)

    def _attach_logger(self, name: str, process: subprocess.Popen[str]) -> None:
        def _log_stream(stream: Iterable[str] | None) -> None:
            if stream is None:
                return
            for line in stream:
                print(f"[connector:{name}] {line.rstrip()}")

        if process.stdout:
            threading.Thread(
                target=_log_stream, args=(process.stdout,), daemon=True
            ).start()
        if process.stderr:
            threading.Thread(
                target=_log_stream, args=(process.stderr,), daemon=True
            ).start()
