"""Multi-Machine, Multi-City (Runtime), and Generic CLI Wrapper Engine."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import shlex
import subprocess
import tomllib
from typing import Any


@dataclass
class MachineTarget:
    id: str
    transport: str = "local"  # "local" | "ssh" | "http"
    ssh_target: str = ""
    supervisor_url: str = "http://127.0.0.1:8372"
    gc_bin: str = "/home/bhd/.local/bin/gc"
    default_city: str = "gascity"
    default_cwd: str = "/home/bhd"
    labels: dict[str, str] = field(default_factory=dict)


@dataclass
class CityRuntime:
    name: str
    machine: str
    city_dir: str
    supervisor_url: str = "http://127.0.0.1:8372"
    description: str = ""


@dataclass
class CLISpec:
    name: str
    binary: str
    allowed_subcommands: list[str] = field(default_factory=list)
    default_machine: str = "bhd-main2"
    description: str = ""


class FleetRouter:
    """Routes CLI commands and Supervisor HTTP calls across 1..N machines and 1..N cities."""

    def __init__(
        self,
        machines: dict[str, MachineTarget] | None = None,
        cities: dict[str, CityRuntime] | None = None,
        clis: dict[str, CLISpec] | None = None,
        default_machine: str = "bhd-main2",
        default_city: str = "gascity",
    ) -> None:
        self.machines = machines or {}
        self.cities = cities or {}
        self.clis = clis or {}
        self.default_machine = default_machine
        self.default_city = default_city

    @classmethod
    def from_config(cls, path: str | Path | None = None) -> "FleetRouter":
        raw_path = path or os.environ.get("GC_MCP_CONFIG", "")
        cfg_path = Path(raw_path) if raw_path else None
        data: dict[str, Any] = {}
        if cfg_path and cfg_path.is_file():
            raw = cfg_path.read_bytes()
            if cfg_path.suffix in (".toml", ".tml"):
                data = tomllib.loads(raw.decode("utf-8"))
            else:
                data = json.loads(raw.decode("utf-8"))

        default_sup = os.environ.get("GC_SUPERVISOR_URL", "http://127.0.0.1:8372").rstrip("/")
        default_dir = os.environ.get("GC_CITY_DIR", "/home/bhd/gascity-local")
        default_name = os.environ.get("GC_CITY_NAME", "gascity")
        default_bin = os.environ.get("GC_BIN", "/home/bhd/.local/bin/gc")
        default_machine = data.get("default_machine", os.environ.get("GC_DEFAULT_MACHINE", "bhd-main2"))
        default_city = data.get("default_city", default_name)

        machines: dict[str, MachineTarget] = {}
        for m in data.get("machines", []):
            mt = MachineTarget(
                id=m["id"],
                transport=m.get("transport", "local"),
                ssh_target=m.get("ssh_target", m["id"]),
                supervisor_url=m.get("supervisor_url", default_sup).rstrip("/"),
                gc_bin=m.get("gc_bin", default_bin),
                default_city=m.get("default_city", default_city),
                default_cwd=m.get("default_cwd", "/home/bhd"),
                labels=dict(m.get("labels", {})),
            )
            machines[mt.id] = mt

        if not machines:
            machines[default_machine] = MachineTarget(
                id=default_machine,
                transport="local",
                supervisor_url=default_sup,
                gc_bin=default_bin,
                default_city=default_city,
                default_cwd=default_dir,
            )

        cities: dict[str, CityRuntime] = {}
        for c in data.get("cities", []):
            m_id = c.get("machine", default_machine)
            m_ref = machines.get(m_id) or next(iter(machines.values()))
            cr = CityRuntime(
                name=c["name"],
                machine=m_id,
                city_dir=c.get("city_dir", default_dir),
                supervisor_url=c.get("supervisor_url", m_ref.supervisor_url).rstrip("/"),
                description=c.get("description", ""),
            )
            cities[cr.name] = cr

        if not cities:
            cities[default_city] = CityRuntime(
                name=default_city,
                machine=default_machine,
                city_dir=default_dir,
                supervisor_url=default_sup,
                description="Primary Gas City runtime",
            )

        clis: dict[str, CLISpec] = {}
        for cli in data.get("clis", []):
            cs = CLISpec(
                name=cli["name"],
                binary=cli.get("binary", cli["name"]),
                allowed_subcommands=list(cli.get("allowed_subcommands", [])),
                default_machine=cli.get("default_machine", default_machine),
                description=cli.get("description", ""),
            )
            clis[cs.name] = cs

        if "gc" not in clis:
            clis["gc"] = CLISpec(
                name="gc",
                binary=default_bin,
                allowed_subcommands=[],
                default_machine=default_machine,
                description="Gas City CLI",
            )

        return cls(
            machines=machines,
            cities=cities,
            clis=clis,
            default_machine=default_machine,
            default_city=default_city,
        )

    def resolve_target(self, machine: str | None = None, city: str | None = None) -> tuple[MachineTarget, CityRuntime]:
        city_obj = self.cities.get(city or "")
        if city_obj is not None and not machine:
            machine_obj = self.machines.get(city_obj.machine) or next(iter(self.machines.values()))
            return machine_obj, city_obj

        machine_obj = self.machines.get(machine or self.default_machine) or next(iter(self.machines.values()))
        if city_obj is None:
            city_obj = (
                self.cities.get(machine_obj.default_city)
                or self.cities.get(self.default_city)
                or next(iter(self.cities.values()))
            )
        return machine_obj, city_obj

    def exec_on_machine(
        self,
        argv: list[str],
        machine: str | None = None,
        cwd: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        target_machine, _ = self.resolve_target(machine=machine)
        bound_timeout = min(max(float(timeout), 1.0), 300.0)
        work_dir = cwd or target_machine.default_cwd

        if target_machine.transport == "ssh" and target_machine.ssh_target:
            quoted_cmd = " ".join(shlex.quote(str(x)) for x in argv)
            if work_dir:
                remote_cmd = f"cd {shlex.quote(work_dir)} 2>/dev/null || true; {quoted_cmd}"
            else:
                remote_cmd = quoted_cmd
            full_argv = [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                target_machine.ssh_target,
                remote_cmd,
            ]
            run_cwd = None
        else:
            full_argv = [str(x) for x in argv]
            run_cwd = work_dir if work_dir and Path(work_dir).is_dir() else None

        try:
            proc = subprocess.run(
                full_argv,
                cwd=run_cwd,
                capture_output=True,
                text=True,
                timeout=bound_timeout,
                check=False,
            )
            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()
            parsed = None
            if stdout:
                try:
                    parsed = json.loads(stdout)
                except Exception:
                    parsed = None
            return {
                "ok": proc.returncode == 0,
                "machine": target_machine.id,
                "transport": target_machine.transport,
                "argv": argv,
                "exit_code": proc.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "json": parsed,
            }
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "machine": target_machine.id,
                "transport": target_machine.transport,
                "argv": argv,
                "exit_code": 124,
                "error": f"Timed out after {bound_timeout}s",
            }
        except Exception as exc:
            return {
                "ok": False,
                "machine": target_machine.id,
                "transport": target_machine.transport,
                "argv": argv,
                "exit_code": 1,
                "error": str(exc),
            }

    def run_wrapped_cli(
        self,
        cli_name: str,
        subcommand: str,
        args: list[str] | None = None,
        machine: str | None = None,
        cwd: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        spec = self.clis.get(cli_name)
        if spec is None:
            return {
                "ok": False,
                "error": f"Unknown wrapped CLI {cli_name!r}. Configured CLIs: {sorted(self.clis.keys())}",
            }
        if spec.allowed_subcommands and subcommand not in spec.allowed_subcommands:
            return {
                "ok": False,
                "error": f"Subcommand {subcommand!r} not in allowed list for {cli_name}: {spec.allowed_subcommands}",
            }
        target_machine = machine or spec.default_machine
        argv = [spec.binary, *([subcommand] if subcommand else []), *[str(a) for a in (args or [])]]
        res = self.exec_on_machine(argv=argv, machine=target_machine, cwd=cwd, timeout=timeout)
        res["cli"] = cli_name
        res["subcommand"] = subcommand
        return res

    def fanout_cli(
        self,
        cli_name: str,
        subcommand: str,
        args: list[str] | None = None,
        machines: list[str] | None = None,
        timeout: float = 20.0,
    ) -> dict[str, Any]:
        target_ids = machines or list(self.machines.keys())
        results: dict[str, Any] = {}
        with ThreadPoolExecutor(max_workers=max(1, min(len(target_ids), 8))) as pool:
            futs = {
                m_id: pool.submit(
                    self.run_wrapped_cli,
                    cli_name=cli_name,
                    subcommand=subcommand,
                    args=args,
                    machine=m_id,
                    timeout=timeout,
                )
                for m_id in target_ids
            }
            for m_id, fut in futs.items():
                results[m_id] = fut.result()
        return {
            "ok": all(r.get("ok", False) for r in results.values()),
            "cli": cli_name,
            "subcommand": subcommand,
            "machines": target_ids,
            "results": results,
        }

    def inventory(self) -> dict[str, Any]:
        return {
            "default_machine": self.default_machine,
            "default_city": self.default_city,
            "machines": [
                {
                    "id": m.id,
                    "transport": m.transport,
                    "ssh_target": m.ssh_target,
                    "supervisor_url": m.supervisor_url,
                    "gc_bin": m.gc_bin,
                    "default_city": m.default_city,
                    "labels": m.labels,
                }
                for m in self.machines.values()
            ],
            "cities": [
                {
                    "name": c.name,
                    "machine": c.machine,
                    "city_dir": c.city_dir,
                    "supervisor_url": c.supervisor_url,
                    "description": c.description,
                }
                for c in self.cities.values()
            ],
            "clis": [
                {
                    "name": s.name,
                    "binary": s.binary,
                    "allowed_subcommands": s.allowed_subcommands,
                    "default_machine": s.default_machine,
                    "description": s.description,
                }
                for s in self.clis.values()
            ],
        }
