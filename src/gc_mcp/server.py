#!/usr/bin/env python3
"""Gas City (gc) Unified MCP & REST Gateway (`gc-mcp-rest`).

Exposes 100% of Gas City functionalities over Tailscale HTTP and HTTPS:
1. Model Context Protocol (MCP) JSON-RPC 2.0 server:
   - `POST /mcp` (Streamable HTTP JSON-RPC 2.0)
   - `GET /mcp` (Server metadata / SSE stream)
   - `GET /sse` & `POST /messages` (SSE + message endpoint)
   - 19 domain & generic MCP tools covering all 46 `gc` CLI commands and all 127 `/v0/*` Supervisor routes
   - MCP resources (`gc://status`, `gc://cities`, `gc://agents`, `gc://beads`, `gc://formulas`,
     `gc://convoys`, `gc://orders`, `gc://rigs`, `gc://openapi`) and prompts
2. REST API:
   - `GET /health` & `GET /api/health`
   - `GET /openapi.json` (combined OpenAPI 3.1 schema of `/v0/*` + `/api/v1/*` + `/mcp`)
   - `GET /api/v1/capabilities`
   - `GET /api/v1/<resource>` (`status`, `cities`, `agents`, `sessions`, `beads`, `beads/ready`,
     `formulas`, `convoys`, `orders`, `rigs`, `packs`, `services`, `runs`, `mail`, `events`,
     `waits`, `usage`, `config`, `readiness`, `provider-readiness`, `doctor`, `costs`, `skills`,
     `metrics`, `version`)
   - `POST /api/v1/cli` (safe structured execution of any of the 46 `gc` CLI subcommands)
   - `POST /api/v1/rest` (structured proxy call to any `/v0/*` Supervisor Control Plane endpoint)
   - `POST /api/v1/sling`, `POST /api/v1/formula/cook`, `POST /api/v1/bd`, `POST /api/v1/nudge`,
     `POST /api/v1/handoff`, `POST /api/v1/reload`, `POST /api/v1/converge`
   - Transparent `/v0/*` reverse proxy (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`) to `gc supervisor`
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

try:
    from .fleet import FleetRouter
    from .oauth import OAuthManager
except ImportError:
    import sys as _sys
    _sys.path.insert(0, str(Path('/data/dev/projects/gc-mcp/src')))
    from gc_mcp.fleet import FleetRouter
    from gc_mcp.oauth import OAuthManager


CLI_COMMANDS: tuple[str, ...] = (
    "agent",
    "agent-script",
    "analyze",
    "bd",
    "beads",
    "build-image",
    "cities",
    "completion",
    "config",
    "context",
    "converge",
    "convoy",
    "costs",
    "dashboard",
    "doctor",
    "dolt-cleanup",
    "event",
    "events",
    "extmsg",
    "formula",
    "github",
    "graph",
    "handoff",
    "help",
    "hook",
    "import",
    "init",
    "lint",
    "login",
    "logout",
    "mail",
    "maintenance",
    "mcp",
    "metrics",
    "nudge",
    "order",
    "pack",
    "prime",
    "prompt",
    "ready",
    "register",
    "reload",
    "restart",
    "resume",
    "rig",
    "runtime",
    "service",
    "session",
    "shell",
    "skill",
    "sling",
    "start",
    "status",
    "stop",
    "storage",
    "supervisor",
    "suspend",
    "trace",
    "unregister",
    "version",
    "wait",
    "whoami",
    "worktree",
)


def _try_parse_json(raw: str) -> Any:
    text = raw.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


class GCBackend:
    def __init__(
        self,
        supervisor_url: str | None = None,
        city_dir: str | None = None,
        city_name: str | None = None,
        gc_bin: str | None = None,
        fleet: FleetRouter | None = None,
        oauth: OAuthManager | None = None,
    ) -> None:
        self.supervisor_url = (
            supervisor_url or os.environ.get("GC_SUPERVISOR_URL", "http://127.0.0.1:8372")
        ).rstrip("/")
        self.city_dir = city_dir or os.environ.get("GC_CITY_DIR", "/home/bhd/gascity-local")
        self.city_name = city_name or os.environ.get("GC_CITY_NAME", "gascity")
        self.gc_bin = gc_bin or os.environ.get("GC_BIN", "/home/bhd/.local/bin/gc")
        self.fleet = fleet or FleetRouter.from_config()
        self.oauth = oauth or OAuthManager()

    def _supervisor_host_header(self) -> str:
        parsed = urllib.parse.urlparse(self.supervisor_url)
        return parsed.netloc or "127.0.0.1:8372"

    def supervisor_request(
        self,
        method: str,
        path: str,
        query: dict[str, Any] | None = None,
        body: Any = None,
        raw_body: bytes | None = None,
        content_type: str = "application/json",
        timeout: float = 30.0,
    ) -> tuple[int, dict[str, str], bytes]:
        if not path.startswith("/"):
            path = "/" + path
        url = f"{self.supervisor_url}{path}"
        if query:
            qs = urllib.parse.urlencode(
                {k: v for k, v in query.items() if v is not None}, doseq=True
            )
            if qs:
                sep = "&" if "?" in url else "?"
                url = f"{url}{sep}{qs}"

        payload: bytes | None = raw_body
        if payload is None and body is not None:
            if isinstance(body, (bytes, bytearray)):
                payload = bytes(body)
            elif isinstance(body, str):
                payload = body.encode("utf-8")
            else:
                payload = json.dumps(body).encode("utf-8")

        host_hdr = self._supervisor_host_header()
        headers = {
            "Host": host_hdr,
            "Origin": f"http://{host_hdr}",
            "Referer": f"http://{host_hdr}/",
            "Accept": "application/json, text/plain, */*",
        }
        if payload is not None:
            headers["Content-Type"] = content_type

        req = urllib.request.Request(url, data=payload, headers=headers, method=method.upper())
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp_headers = {k: v for k, v in resp.headers.items()}
                return resp.status, resp_headers, resp.read()
        except urllib.error.HTTPError as exc:
            resp_headers = {k: v for k, v in exc.headers.items()} if exc.headers else {}
            return exc.code, resp_headers, exc.read()
        except Exception as exc:
            err = json.dumps({"ok": False, "error": str(exc), "url": url}).encode("utf-8")
            return 502, {"Content-Type": "application/json"}, err

    def supervisor_json(
        self,
        method: str,
        path: str,
        query: dict[str, Any] | None = None,
        body: Any = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        status, _, raw = self.supervisor_request(
            method=method, path=path, query=query, body=body, timeout=timeout
        )
        text = raw.decode("utf-8", errors="replace")
        parsed = _try_parse_json(text)
        return {
            "ok": 200 <= status < 300,
            "status": status,
            "path": path,
            "data": parsed if parsed is not None else text,
        }

    def run_cli(
        self,
        command: str,
        args: list[str] | None = None,
        timeout: float = 60.0,
    ) -> dict[str, Any]:
        cmd = command.strip()
        if cmd not in CLI_COMMANDS:
            return {
                "ok": False,
                "command": cmd,
                "exit_code": 2,
                "error": f"Unsupported gc subcommand {cmd!r}. Allowed: {', '.join(CLI_COMMANDS)}",
            }
        safe_args = [str(a) for a in (args or [])]
        argv = [self.gc_bin, cmd, *safe_args]
        cwd = self.city_dir if Path(self.city_dir).is_dir() else None
        try:
            proc = subprocess.run(
                argv,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=min(max(float(timeout), 1.0), 300.0),
                check=False,
            )
            parsed = _try_parse_json(proc.stdout)
            return {
                "ok": proc.returncode == 0,
                "command": cmd,
                "args": safe_args,
                "exit_code": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "data": parsed if parsed is not None else proc.stdout.strip(),
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "ok": False,
                "command": cmd,
                "args": safe_args,
                "exit_code": 124,
                "error": f"Command timed out after {timeout}s",
                "stdout": exc.stdout or "",
                "stderr": exc.stderr or "",
            }
        except Exception as exc:
            return {
                "ok": False,
                "command": cmd,
                "args": safe_args,
                "exit_code": 1,
                "error": str(exc),
            }


MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "gc_status",
        "description": "Get Gas City status overview (controller state, agents, rigs, sessions).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string", "description": "City name (default: gascity)"},
                "source": {
                    "type": "string",
                    "enum": ["rest", "cli"],
                    "description": "Use supervisor REST API ('rest', default) or local CLI ('cli')",
                },
            },
        },
    },
    {
        "name": "gc_cities",
        "description": "List registered cities or inspect a specific city.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string", "description": "Optional city name to inspect"},
            },
        },
    },
    {
        "name": "gc_agents",
        "description": "List agents, inspect an agent, fetch agent output, or trigger an agent action.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string", "description": "City name (default: gascity)"},
                "action": {
                    "type": "string",
                    "enum": ["list", "get", "output", "act"],
                    "description": "Operation to perform (default: list)",
                },
                "agent": {"type": "string", "description": "Agent name or dir/base"},
                "agent_action": {"type": "string", "description": "Action name when action=act"},
                "body": {"type": "object", "description": "Optional request body for action=act"},
            },
        },
    },
    {
        "name": "gc_sessions",
        "description": "List or manage interactive/agent sessions (get, transcript, messages, pending, submit, respond, stop, suspend, wake, close, kill, rename).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string"},
                "action": {
                    "type": "string",
                    "enum": [
                        "list",
                        "get",
                        "transcript",
                        "messages",
                        "pending",
                        "submit",
                        "respond",
                        "stop",
                        "suspend",
                        "wake",
                        "close",
                        "kill",
                        "rename",
                    ],
                },
                "session_id": {"type": "string"},
                "body": {"type": "object"},
                "query": {"type": "object"},
            },
        },
    },
    {
        "name": "gc_beads",
        "description": "List, query ready beads, inspect bead, dependency graph, create, update, assign, close, reopen, or run `gc bd`.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string"},
                "action": {
                    "type": "string",
                    "enum": [
                        "list",
                        "ready",
                        "get",
                        "graph",
                        "create",
                        "update",
                        "assign",
                        "close",
                        "reopen",
                        "deps",
                        "bd_cli",
                    ],
                },
                "bead_id": {"type": "string"},
                "query": {"type": "object"},
                "body": {"type": "object"},
                "bd_args": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
    {
        "name": "gc_formulas",
        "description": "List, inspect, preview, source, validate, list runs, or cook Gas City formulas.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string"},
                "action": {
                    "type": "string",
                    "enum": ["list", "feed", "get", "preview", "runs", "source", "validate", "cook"],
                },
                "name": {"type": "string", "description": "Formula name"},
                "query": {"type": "object"},
                "body": {"type": "object"},
                "cook_args": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
    {
        "name": "gc_convoys",
        "description": "List, inspect, create, add, check, close, or remove convoys.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string"},
                "action": {
                    "type": "string",
                    "enum": ["list", "get", "create", "add", "check", "close", "remove"],
                },
                "convoy_id": {"type": "string"},
                "body": {"type": "object"},
            },
        },
    },
    {
        "name": "gc_orders",
        "description": "List, check, feed, history, inspect, enable, disable, or run scheduled/event orders.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string"},
                "action": {
                    "type": "string",
                    "enum": ["list", "check", "feed", "history", "get", "enable", "disable", "run"],
                },
                "name": {"type": "string"},
                "body": {"type": "object"},
            },
        },
    },
    {
        "name": "gc_mail",
        "description": "List, count, read, send, reply, archive, or view threads of agent/human mail.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string"},
                "action": {
                    "type": "string",
                    "enum": ["list", "count", "get", "thread", "send", "reply", "read", "mark-unread", "archive"],
                },
                "mail_id": {"type": "string"},
                "query": {"type": "object"},
                "body": {"type": "object"},
            },
        },
    },
    {
        "name": "gc_rigs",
        "description": "List rigs, inspect a rig, or trigger a rig action.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string"},
                "action": {"type": "string", "enum": ["list", "get", "act"]},
                "rig": {"type": "string"},
                "rig_action": {"type": "string"},
                "body": {"type": "object"},
            },
        },
    },
    {
        "name": "gc_packs",
        "description": "List or inspect remote/local pack sources.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string"},
                "name": {"type": "string"},
            },
        },
    },
    {
        "name": "gc_runs",
        "description": "List workflow/formula runs, census, inspect a run or its steps, or cancel a run.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string"},
                "action": {"type": "string", "enum": ["list", "census", "get", "steps", "cancel"]},
                "run_id": {"type": "string"},
                "query": {"type": "object"},
            },
        },
    },
    {
        "name": "gc_services",
        "description": "List workspace services, inspect a service, or restart it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string"},
                "action": {"type": "string", "enum": ["list", "get", "restart"]},
                "name": {"type": "string"},
            },
        },
    },
    {
        "name": "gc_sling",
        "description": "Route work (a bead or prompt) to an agent or session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string"},
                "target": {"type": "string", "description": "Target agent or session"},
                "bead": {"type": "string", "description": "Bead ID or work item"},
                "body": {"type": "object", "description": "Raw sling payload for /v0/city/{city}/sling"},
                "cli_args": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
    {
        "name": "gc_events",
        "description": "List or emit Gas City events.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string"},
                "action": {"type": "string", "enum": ["list", "emit"]},
                "query": {"type": "object"},
                "body": {"type": "object"},
            },
        },
    },
    {
        "name": "gc_config",
        "description": "Inspect, explain, validate, or view defaults/patches of city configuration.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string"},
                "action": {"type": "string", "enum": ["get", "defaults", "explain", "validate", "patches"]},
            },
        },
    },
    {
        "name": "gc_doctor_and_ops",
        "description": "Run operational inspections and actions: health, readiness, doctor, costs, usage, analyze, metrics, waits, trace, converge, nudge, handoff, worktree, skill, prime, reload, maintenance.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string"},
                "op": {
                    "type": "string",
                    "enum": [
                        "health",
                        "readiness",
                        "provider-readiness",
                        "usage",
                        "waits",
                        "maintenance",
                        "doctor",
                        "costs",
                        "analyze",
                        "metrics",
                        "trace",
                        "converge",
                        "nudge",
                        "handoff",
                        "worktree",
                        "skill",
                        "prime",
                        "reload",
                    ],
                },
                "args": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["op"],
        },
    },
    {
        "name": "gc_rest_request",
        "description": "Call any of the 127 native Gas City Supervisor `/v0/*` Control Plane REST API endpoints.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                    "default": "GET",
                },
                "path": {"type": "string", "description": "API path starting with /v0/ or /health"},
                "query": {"type": "object"},
                "body": {"type": "object"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "gc_cli",
        "description": "Execute any of the 46 `gc` CLI subcommands safely with structured arguments.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "enum": list(CLI_COMMANDS)},
                "args": {"type": "array", "items": {"type": "string"}},
                "timeout": {"type": "number", "default": 60},
            },
            "required": ["command"],
        },
    },
    {
        "name": "gc_machines",
        "description": "List all configured machines, Gas City runtimes (cities), and wrapped CLIs across the multi-machine fleet.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "machine": {"type": "string", "description": "Optional machine filter"},
            },
        },
    },
    {
        "name": "gc_multi_exec",
        "description": "Execute any wrapped CLI (`gc`, `gt`, `bd`, `herdr`, `hostname`) on one or multiple machines in parallel (`bhd-main2`, `bhd-pad1`, `gcp-23dec`, `cfly-out`).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cli": {"type": "string", "description": "Wrapped CLI name (default: gc; options: gc, gt, bd, herdr, hostname)"},
                "subcommand": {"type": "string", "description": "CLI subcommand to run (optional for single-binary CLIs like hostname)"},
                "args": {"type": "array", "items": {"type": "string"}},
                "machine": {"type": "string", "description": "Single target machine ID"},
                "machines": {"type": "array", "items": {"type": "string"}, "description": "Multiple machine IDs for parallel fan-out"},
                "timeout": {"type": "number"},
            },
        },
    },
]


def execute_mcp_tool(backend: GCBackend, name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
    args = arguments or {}
    city = args.get("city") or backend.city_name

    if name == "gc_machines":
        inv = backend.fleet.inventory()
        m_filter = args.get("machine")
        if m_filter:
            inv["machines"] = [m for m in inv["machines"] if m["id"] == m_filter]
            inv["cities"] = [c for c in inv["cities"] if c["machine"] == m_filter]
        return {"ok": True, "data": inv}

    if name == "gc_multi_exec":
        cli_name = str(args.get("cli") or "gc")
        raw_sub = args.get("subcommand")
        subcmd = str(raw_sub) if raw_sub is not None else ("version" if cli_name == "gc" else "")
        raw_sub_args = args.get("args") or []
        sub_args = [x.strip() for x in raw_sub_args.split(",") if x.strip()] if isinstance(raw_sub_args, str) else [str(x) for x in raw_sub_args]
        t_sec = float(args.get("timeout") or args.get("timeout_sec") or 20.0)
        raw_machines = args.get("machines")
        if raw_machines:
            m_list = [m.strip() for m in raw_machines.split(",") if m.strip()] if isinstance(raw_machines, str) else [str(m) for m in raw_machines]
            return backend.fleet.fanout_cli(
                cli_name=cli_name,
                subcommand=subcmd,
                args=sub_args,
                machines=m_list,
                timeout=t_sec,
            )
        return backend.fleet.run_wrapped_cli(
            cli_name=cli_name,
            subcommand=subcmd,
            args=sub_args,
            machine=args.get("machine"),
            timeout=t_sec,
        )

    if name == "gc_status":
        if args.get("source") == "cli":
            return backend.run_cli("status", ["--json"])
        return backend.supervisor_json("GET", f"/v0/city/{city}/status")

    if name == "gc_cities":
        if args.get("city"):
            return backend.supervisor_json("GET", f"/v0/city/{args['city']}")
        return backend.supervisor_json("GET", "/v0/cities")

    if name == "gc_agents":
        act = args.get("action", "list")
        agent = args.get("agent", "")
        if act == "list":
            res = backend.supervisor_json("GET", f"/v0/city/{city}/agents", timeout=3.0)
            if not res["ok"]:
                st = backend.supervisor_json("GET", f"/v0/city/{city}/status", timeout=5.0)
                if st["ok"] and isinstance(st["data"], dict):
                    return {
                        "ok": True,
                        "status": 200,
                        "path": f"/v0/city/{city}/status#agents",
                        "data": {
                            "items": st["data"].get("agent_details") or st["data"].get("agents") or [],
                            "total": st["data"].get("agent_count", 0),
                        },
                    }
            return res
        if act == "get":
            return backend.supervisor_json("GET", f"/v0/city/{city}/agent/{agent}")
        if act == "output":
            return backend.supervisor_json("GET", f"/v0/city/{city}/agent/{agent}/output")
        if act == "act":
            sub = args.get("agent_action", "restart")
            return backend.supervisor_json(
                "POST", f"/v0/city/{city}/agent/{agent}/{sub}", body=args.get("body") or {}
            )

    if name == "gc_sessions":
        act = args.get("action", "list")
        sid = args.get("session_id", "")
        if act == "list":
            return backend.supervisor_json("GET", f"/v0/city/{city}/sessions", query=args.get("query"))
        if act == "get":
            return backend.supervisor_json("GET", f"/v0/city/{city}/session/{sid}")
        if act in ("transcript", "messages", "pending"):
            return backend.supervisor_json("GET", f"/v0/city/{city}/session/{sid}/{act}", query=args.get("query"))
        return backend.supervisor_json(
            "POST", f"/v0/city/{city}/session/{sid}/{act}", body=args.get("body") or {}
        )

    if name == "gc_beads":
        act = args.get("action", "list")
        bid = args.get("bead_id", "")
        if act == "list":
            res = backend.supervisor_json("GET", f"/v0/city/{city}/beads", query=args.get("query"), timeout=3.0)
            if not res["ok"]:
                st = backend.supervisor_json("GET", f"/v0/city/{city}/status", timeout=5.0)
                if st["ok"] and isinstance(st["data"], dict):
                    return {"ok": True, "status": 200, "path": f"/v0/city/{city}/status#beads", "data": st["data"].get("beads") or {}}
            return res
        if act == "ready":
            res = backend.supervisor_json("GET", f"/v0/city/{city}/beads/ready", query=args.get("query"), timeout=3.0)
            if not res["ok"]:
                st = backend.supervisor_json("GET", f"/v0/city/{city}/status", timeout=5.0)
                if st["ok"] and isinstance(st["data"], dict):
                    return {"ok": True, "status": 200, "path": f"/v0/city/{city}/status#work", "data": st["data"].get("work") or {}}
            return res
        if act == "get":
            return backend.supervisor_json("GET", f"/v0/city/{city}/bead/{bid}")
        if act == "graph":
            return backend.supervisor_json("GET", f"/v0/city/{city}/beads/graph/{bid}")
        if act == "deps":
            return backend.supervisor_json("GET", f"/v0/city/{city}/bead/{bid}/deps")
        if act == "create":
            return backend.supervisor_json("POST", f"/v0/city/{city}/beads", body=args.get("body") or {})
        if act in ("update", "assign", "close", "reopen"):
            return backend.supervisor_json(
                "POST", f"/v0/city/{city}/bead/{bid}/{act}", body=args.get("body") or {}
            )
        if act == "bd_cli":
            return backend.run_cli("bd", list(args.get("bd_args") or []))

    if name == "gc_formulas":
        act = args.get("action", "list")
        fname = args.get("name", "")
        q = dict(args.get("query") or {})
        q.setdefault("scope_kind", "city")
        q.setdefault("scope_ref", city)
        if act == "list":
            return backend.supervisor_json("GET", f"/v0/city/{city}/formulas", query=q)
        if act == "feed":
            return backend.supervisor_json("GET", f"/v0/city/{city}/formulas/feed", query=q)
        if act == "get":
            return backend.supervisor_json("GET", f"/v0/city/{city}/formulas/{fname}", query=q)
        if act in ("preview", "runs", "source"):
            return backend.supervisor_json("GET", f"/v0/city/{city}/formulas/{fname}/{act}", query=q)
        if act == "validate":
            return backend.supervisor_json(
                "POST", f"/v0/city/{city}/formulas/{fname}/validate", body=args.get("body") or {}
            )
        if act == "cook":
            cook_args = ["cook", *([fname] if fname else []), *[str(x) for x in (args.get("cook_args") or [])]]
            return backend.run_cli("formula", cook_args)

    if name == "gc_convoys":
        act = args.get("action", "list")
        cid = args.get("convoy_id", "")
        if act == "list":
            return backend.supervisor_json("GET", f"/v0/city/{city}/convoys")
        if act == "get":
            return backend.supervisor_json("GET", f"/v0/city/{city}/convoy/{cid}")
        if act == "create":
            return backend.supervisor_json("POST", f"/v0/city/{city}/convoys", body=args.get("body") or {})
        if act in ("add", "check", "close", "remove"):
            return backend.supervisor_json(
                "POST", f"/v0/city/{city}/convoy/{cid}/{act}", body=args.get("body") or {}
            )

    if name == "gc_orders":
        act = args.get("action", "list")
        oname = args.get("name", "")
        if act == "list":
            return backend.supervisor_json("GET", f"/v0/city/{city}/orders")
        if act in ("check", "feed", "history"):
            return backend.supervisor_json("GET", f"/v0/city/{city}/orders/{act}")
        if act == "get":
            return backend.supervisor_json("GET", f"/v0/city/{city}/order/{oname}")
        if act in ("enable", "disable", "run"):
            return backend.supervisor_json(
                "POST", f"/v0/city/{city}/order/{oname}/{act}", body=args.get("body") or {}
            )

    if name == "gc_mail":
        act = args.get("action", "list")
        mid = args.get("mail_id", "")
        if act == "list":
            return backend.supervisor_json("GET", f"/v0/city/{city}/mail", query=args.get("query"))
        if act == "count":
            return backend.supervisor_json("GET", f"/v0/city/{city}/mail/count", query=args.get("query"))
        if act == "get":
            return backend.supervisor_json("GET", f"/v0/city/{city}/mail/{mid}")
        if act == "thread":
            return backend.supervisor_json("GET", f"/v0/city/{city}/mail/thread/{mid}")
        if act == "send":
            return backend.supervisor_json("POST", f"/v0/city/{city}/mail", body=args.get("body") or {})
        if act in ("reply", "read", "mark-unread", "archive"):
            return backend.supervisor_json(
                "POST", f"/v0/city/{city}/mail/{mid}/{act}", body=args.get("body") or {}
            )

    if name == "gc_rigs":
        act = args.get("action", "list")
        rig = args.get("rig", "")
        if act == "list":
            res = backend.supervisor_json("GET", f"/v0/city/{city}/rigs", timeout=3.0)
            if not res["ok"]:
                st = backend.supervisor_json("GET", f"/v0/city/{city}/status", timeout=5.0)
                if st["ok"] and isinstance(st["data"], dict):
                    return {
                        "ok": True,
                        "status": 200,
                        "path": f"/v0/city/{city}/status#rigs",
                        "data": {
                            "items": st["data"].get("rig_details") or st["data"].get("rigs") or [],
                            "total": st["data"].get("rig_count", 0),
                        },
                    }
            return res
        if act == "get":
            return backend.supervisor_json("GET", f"/v0/city/{city}/rig/{rig}")
        if act == "act":
            ra = args.get("rig_action", "status")
            return backend.supervisor_json(
                "POST", f"/v0/city/{city}/rig/{rig}/{ra}", body=args.get("body") or {}
            )

    if name == "gc_packs":
        if args.get("name"):
            return backend.supervisor_json("GET", f"/v0/city/{city}/packs/{args['name']}")
        return backend.supervisor_json("GET", f"/v0/city/{city}/packs")

    if name == "gc_runs":
        act = args.get("action", "list")
        rid = args.get("run_id", "")
        if act == "list":
            return backend.supervisor_json("GET", f"/v0/city/{city}/runs", query=args.get("query"))
        if act == "census":
            return backend.supervisor_json("GET", f"/v0/city/{city}/runs/census")
        if act == "get":
            return backend.supervisor_json("GET", f"/v0/city/{city}/runs/{rid}")
        if act == "steps":
            return backend.supervisor_json("GET", f"/v0/city/{city}/runs/{rid}/steps")
        if act == "cancel":
            return backend.supervisor_json("POST", f"/v0/city/{city}/runs/{rid}/cancel", body={})

    if name == "gc_services":
        act = args.get("action", "list")
        sname = args.get("name", "")
        if act == "list":
            return backend.supervisor_json("GET", f"/v0/city/{city}/services")
        if act == "get":
            return backend.supervisor_json("GET", f"/v0/city/{city}/service/{sname}")
        if act == "restart":
            return backend.supervisor_json("POST", f"/v0/city/{city}/service/{sname}/restart", body={})

    if name == "gc_sling":
        if args.get("cli_args"):
            return backend.run_cli("sling", list(args["cli_args"]))
        payload = dict(args.get("body") or {})
        if args.get("target"):
            payload.setdefault("target", args["target"])
        if args.get("bead"):
            payload.setdefault("bead", args["bead"])
        return backend.supervisor_json("POST", f"/v0/city/{city}/sling", body=payload)

    if name == "gc_events":
        act = args.get("action", "list")
        if act == "emit":
            return backend.supervisor_json("POST", f"/v0/city/{city}/events", body=args.get("body") or {})
        return backend.supervisor_json("GET", f"/v0/city/{city}/events", query=args.get("query"))

    if name == "gc_config":
        act = args.get("action", "get")
        if act == "get":
            return backend.supervisor_json("GET", f"/v0/city/{city}/config")
        if act in ("defaults", "explain", "validate"):
            return backend.supervisor_json("GET", f"/v0/city/{city}/config/{act}")
        if act == "patches":
            return backend.supervisor_json("GET", f"/v0/city/{city}/patches/agents")

    if name == "gc_doctor_and_ops":
        op = args.get("op", "health")
        cli_args = [str(x) for x in (args.get("args") or [])]
        if op == "health":
            return backend.supervisor_json("GET", f"/v0/city/{city}/health")
        if op == "readiness":
            return backend.supervisor_json("GET", f"/v0/city/{city}/readiness")
        if op == "provider-readiness":
            return backend.supervisor_json("GET", f"/v0/city/{city}/provider-readiness")
        if op == "usage":
            return backend.supervisor_json("GET", f"/v0/city/{city}/usage")
        if op == "waits":
            return backend.supervisor_json("GET", f"/v0/city/{city}/waits")
        if op == "maintenance":
            return backend.supervisor_json("GET", f"/v0/city/{city}/maintenance/status")
        return backend.run_cli(op, cli_args)

    if name == "gc_rest_request":
        return backend.supervisor_json(
            method=args.get("method", "GET"),
            path=args["path"],
            query=args.get("query"),
            body=args.get("body"),
        )

    if name == "gc_cli":
        return backend.run_cli(
            command=args["command"],
            args=list(args.get("args") or []),
            timeout=float(args.get("timeout", 60)),
        )

    return {"ok": False, "error": f"Unknown tool {name!r}"}


MCP_RESOURCES: list[dict[str, str]] = [
    {"uri": "gc://status", "name": "Gas City Status", "mimeType": "application/json"},
    {"uri": "gc://cities", "name": "Registered Cities", "mimeType": "application/json"},
    {"uri": "gc://agents", "name": "City Agents", "mimeType": "application/json"},
    {"uri": "gc://beads", "name": "City Beads", "mimeType": "application/json"},
    {"uri": "gc://formulas", "name": "City Formulas", "mimeType": "application/json"},
    {"uri": "gc://convoys", "name": "City Convoys", "mimeType": "application/json"},
    {"uri": "gc://orders", "name": "City Orders", "mimeType": "application/json"},
    {"uri": "gc://rigs", "name": "City Rigs", "mimeType": "application/json"},
    {"uri": "gc://openapi", "name": "Supervisor OpenAPI 3.1 Spec", "mimeType": "application/json"},
]


def read_mcp_resource(backend: GCBackend, uri: str) -> dict[str, Any]:
    city = backend.city_name
    mapping = {
        "gc://status": f"/v0/city/{city}/status",
        "gc://cities": "/v0/cities",
        "gc://agents": f"/v0/city/{city}/agents",
        "gc://beads": f"/v0/city/{city}/beads",
        "gc://formulas": f"/v0/city/{city}/formulas",
        "gc://convoys": f"/v0/city/{city}/convoys",
        "gc://orders": f"/v0/city/{city}/orders",
        "gc://rigs": f"/v0/city/{city}/rigs",
        "gc://openapi": "/openapi.json",
    }
    path = mapping.get(uri)
    if not path:
        return {"ok": False, "error": f"Unknown resource URI {uri!r}"}
    return backend.supervisor_json("GET", path)


REST_V1_GET_ROUTES: dict[str, str] = {
    "/api/v1/cities": "/v0/cities",
    "/api/v1/agents": "/v0/city/{city}/agents",
    "/api/v1/sessions": "/v0/city/{city}/sessions",
    "/api/v1/beads": "/v0/city/{city}/beads",
    "/api/v1/beads/ready": "/v0/city/{city}/beads/ready",
    "/api/v1/formulas": "/v0/city/{city}/formulas",
    "/api/v1/convoys": "/v0/city/{city}/convoys",
    "/api/v1/orders": "/v0/city/{city}/orders",
    "/api/v1/rigs": "/v0/city/{city}/rigs",
    "/api/v1/packs": "/v0/city/{city}/packs",
    "/api/v1/services": "/v0/city/{city}/services",
    "/api/v1/runs": "/v0/city/{city}/runs",
    "/api/v1/mail": "/v0/city/{city}/mail",
    "/api/v1/events": "/v0/city/{city}/events",
    "/api/v1/waits": "/v0/city/{city}/waits",
    "/api/v1/usage": "/v0/city/{city}/usage",
    "/api/v1/config": "/v0/city/{city}/config",
    "/api/v1/readiness": "/v0/city/{city}/readiness",
    "/api/v1/provider-readiness": "/v0/city/{city}/provider-readiness",
}


REST_V1_CLI_GET_ROUTES: dict[str, tuple[str, list[str]]] = {
    "/api/v1/doctor": ("doctor", []),
    "/api/v1/costs": ("costs", []),
    "/api/v1/skills": ("skill", []),
    "/api/v1/metrics": ("metrics", []),
    "/api/v1/version": ("version", []),
}


def make_handler(backend: GCBackend):
    class GCMcpRestHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _send_cors(self) -> None:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "*")
            self.send_header("Access-Control-Expose-Headers", "Mcp-Session-Id, WWW-Authenticate")

        def _request_base_url(self) -> str:
            fwd_host = (self.headers.get("X-Forwarded-Host") or "").split(",")[0].strip()
            host = fwd_host or (self.headers.get("Host") or "").strip()
            fwd_proto = (self.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip()
            if not host or host in ("127.0.0.1:8375", "localhost:8375"):
                return backend.oauth.base_url
            is_https_host = (
                host.endswith(".ts.net")
                or ":18375" in host
                or ":10000" in host
                or ".sslip.io" in host
                or ".nip.io" in host
                or ".run.app" in host
            )
            proto = "https" if is_https_host else (fwd_proto or "http")
            return f"{proto}://{host}".rstrip("/")

        def _is_external_request(self) -> bool:
            if (self.headers.get("X-Require-OAuth") or "").lower() in ("1", "true", "yes"):
                return True
            burl = self._request_base_url().lower()
            return any(tok in burl for tok in (".sslip.io", ".nip.io", ":10000", ".run.app"))

        def _send_unauthorized(self) -> None:
            req_base = self._request_base_url()
            self.send_response(401)
            self._send_cors()
            self.send_header(
                "WWW-Authenticate",
                f'Bearer resource_metadata="{req_base}/.well-known/oauth-protected-resource"',
            )
            self.send_header("Content-Type", "application/json")
            err = json.dumps({"error": "unauthorized", "error_description": "Bearer token required"}).encode("utf-8")
            self.send_header("Content-Length", str(len(err)))
            self.end_headers()
            self.wfile.write(err)

        def _send_redirect(self, location: str, status: int = 302) -> None:
            self.send_response(status)
            self._send_cors()
            self.send_header("Location", location)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _send_json(self, status: int, payload: Any, extra_headers: dict[str, str] | None = None) -> None:
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self._send_cors()
            if extra_headers:
                for hk, hv in extra_headers.items():
                    self.send_header(hk, hv)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _read_body(self) -> bytes:
            length = int(self.headers.get("Content-Length", "0") or "0")
            return self.rfile.read(length) if length > 0 else b""

        def do_OPTIONS(self) -> None:
            self.send_response(204)
            self._send_cors()
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            query = urllib.parse.parse_qs(parsed.query)
            req_base = self._request_base_url()

            if path.startswith("/.well-known/oauth-authorization-server") or path.startswith(
                "/.well-known/openid-configuration"
            ):
                self._send_json(200, backend.oauth.metadata(req_base))
                return

            if path.startswith("/.well-known/oauth-protected-resource"):
                self._send_json(200, backend.oauth.protected_resource_metadata(req_base))
                return

            if path == "/oauth/userinfo":
                ok, claims = backend.oauth.check_request_auth(
                    self.headers.get("Authorization"), require_auth=True
                )
                if not ok or not claims:
                    self._send_unauthorized()
                    return
                self._send_json(
                    200,
                    {
                        "sub": claims.get("sub", "google:buihongduc132@gmail.com"),
                        "email": claims.get("email", "buihongduc132@gmail.com"),
                        "email_verified": True,
                        "name": "Duc Bui",
                    },
                )
                return

            if path == "/oauth/google/callback":
                google_code = (query.get("code") or [""])[0]
                gstate = (query.get("state") or [""])[0]
                if not google_code or not gstate:
                    self._send_json(
                        400,
                        {"error": "invalid_request", "error_description": "Missing code or state from Google"},
                    )
                    return
                st, res = backend.oauth.complete_google_callback(google_code=google_code, gstate=gstate)
                if st == 302 and isinstance(res, str):
                    self._send_redirect(res, 302)
                    return
                self._send_json(st, res)
                return

            if path == "/oauth/authorize":
                client_id = (query.get("client_id") or ["default"])[0]
                redirect_uri = (query.get("redirect_uri") or ["http://localhost:8000/callback"])[0]
                code_challenge = (query.get("code_challenge") or [""])[0]
                code_challenge_method = (query.get("code_challenge_method") or ["S256"])[0]
                state = (query.get("state") or [""])[0]
                scope = (query.get("scope") or ["openid email mcp:tools"])[0]
                email = (query.get("email") or ["buihongduc132@gmail.com"])[0]
                accept = (self.headers.get("Accept") or "").lower()
                fmt = (query.get("format") or [""])[0].lower()
                flow = (query.get("flow") or [""])[0].lower()

                use_google_redirect = (
                    fmt != "json"
                    and bool(backend.oauth.google_client_id)
                    and (
                        flow == "google"
                        or "text/html" in accept
                        or "chatgpt.com" in redirect_uri
                        or "openai.com" in redirect_uri
                    )
                )
                if use_google_redirect:
                    google_url = backend.oauth.start_google_authorization(
                        client_id=client_id,
                        redirect_uri=redirect_uri,
                        code_challenge=code_challenge,
                        code_challenge_method=code_challenge_method,
                        state=state,
                        scope=scope,
                        req_base_url=req_base,
                    )
                    self._send_redirect(google_url, 302)
                    return

                code = backend.oauth.create_authorization_code(
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                    code_challenge=code_challenge,
                    code_challenge_method=code_challenge_method,
                    state=state,
                    email=email,
                    scope=scope,
                )
                sep = "&" if "?" in redirect_uri else "?"
                location = f"{redirect_uri}{sep}code={urllib.parse.quote(code)}"
                if state:
                    location += f"&state={urllib.parse.quote(state)}"
                if fmt != "json" and ("text/html" in accept or "chatgpt.com" in redirect_uri):
                    self._send_redirect(location, 302)
                    return
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "code": code,
                        "state": state,
                        "redirect_to": location,
                        "google_oauth_upstream": (
                            f"https://accounts.google.com/o/oauth2/v2/auth?client_id={backend.oauth.google_client_id}"
                            if backend.oauth.google_client_id
                            else None
                        ),
                    },
                )
                return

            if path == "/device/verify":
                user_code = (query.get("user_code") or [""])[0]
                email = (query.get("email") or ["buihongduc132@gmail.com"])[0]
                if user_code:
                    st, payload = backend.oauth.approve_device_flow(user_code=user_code, email=email)
                    self._send_json(st, payload)
                    return
                self._send_json(200, {"ok": True, "message": "Pass ?user_code=XXXX-XXXX to approve device"})
                return

            if path == "/api/v1/machines":
                self._send_json(200, {"ok": True, "data": backend.fleet.inventory()})
                return

            if path in ("/health", "/api/health"):
                sup = backend.supervisor_json("GET", "/health", timeout=5.0)
                self._send_json(
                    200,
                    {
                        "status": "ok",
                        "service": "gc-mcp-rest",
                        "city": backend.city_name,
                        "supervisor_url": backend.supervisor_url,
                        "supervisor_ok": sup["ok"],
                        "supervisor_health": sup["data"],
                        "mcp_endpoint": "/mcp",
                        "sse_endpoint": "/sse",
                        "rest_prefix": "/api/v1",
                        "supervisor_proxy_prefix": "/v0",
                        "tools_count": len(MCP_TOOLS),
                        "cli_commands_count": len(CLI_COMMANDS),
                        "cli_commands": list(CLI_COMMANDS),
                        "machines_count": len(backend.fleet.machines),
                        "cities_count": len(backend.fleet.cities),
                        "wrapped_clis": sorted(backend.fleet.clis.keys()),
                        "oauth_enabled": True,
                        "oauth_mode": backend.oauth.auth_mode,
                        "google_oauth_configured": bool(backend.oauth.google_client_id),
                    },
                )
                return

            if path == "/openapi.json":
                sup = backend.supervisor_json("GET", "/openapi.json", timeout=10.0)
                spec = sup["data"] if isinstance(sup["data"], dict) else {"openapi": "3.1.0", "paths": {}}
                paths = spec.setdefault("paths", {})
                for p, desc in (
                    ("/health", "Unified GC MCP & REST Gateway health"),
                    ("/api/health", "Unified GC MCP & REST Gateway health"),
                    ("/api/v1/capabilities", "List all GC CLI commands, MCP tools, and REST routes"),
                    ("/api/v1/status", "City-wide status overview"),
                    ("/api/v1/cli", "Execute any GC CLI subcommand"),
                    ("/api/v1/rest", "Execute any /v0/* Supervisor REST endpoint"),
                    ("/mcp", "Model Context Protocol (MCP) JSON-RPC 2.0 endpoint"),
                ):
                    paths.setdefault(p, {"get": {"summary": desc}})
                self._send_json(200, spec)
                return

            if path == "/api/v1/capabilities":
                sup = backend.supervisor_json("GET", "/openapi.json", timeout=10.0)
                sup_paths = (
                    sorted(sup["data"].get("paths", {}).keys())
                    if isinstance(sup["data"], dict)
                    else []
                )
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "service": "gc-mcp-rest",
                        "city": backend.city_name,
                        "mcp_tools": MCP_TOOLS,
                        "mcp_resources": MCP_RESOURCES,
                        "cli_commands": list(CLI_COMMANDS),
                        "rest_v1_get_routes": sorted(
                            ["/api/v1/status", *REST_V1_GET_ROUTES.keys(), *REST_V1_CLI_GET_ROUTES.keys()]
                        ),
                        "rest_v1_post_routes": [
                            "/api/v1/cli",
                            "/api/v1/rest",
                            "/api/v1/sling",
                            "/api/v1/formula/cook",
                            "/api/v1/bd",
                            "/api/v1/nudge",
                            "/api/v1/handoff",
                            "/api/v1/reload",
                            "/api/v1/converge",
                        ],
                        "supervisor_v0_routes_count": len(sup_paths),
                        "supervisor_v0_routes": sup_paths,
                    },
                )
                return

            if path == "/api/v1/status":
                source = (query.get("source") or ["rest"])[0]
                if source == "cli":
                    res = backend.run_cli("status", ["--json"])
                    self._send_json(200 if res["ok"] else 500, res)
                    return
                res = backend.supervisor_json("GET", f"/v0/city/{backend.city_name}/status", query=query)
                self._send_json(res["status"], res["data"])
                return

            if path in REST_V1_GET_ROUTES:
                if path == "/api/v1/agents":
                    res = execute_mcp_tool(backend, "gc_agents", {"action": "list"})
                    self._send_json(200 if res["ok"] else res["status"], res["data"])
                    return
                if path == "/api/v1/rigs":
                    res = execute_mcp_tool(backend, "gc_rigs", {"action": "list"})
                    self._send_json(200 if res["ok"] else res["status"], res["data"])
                    return
                if path == "/api/v1/beads":
                    res = execute_mcp_tool(backend, "gc_beads", {"action": "list", "query": query})
                    self._send_json(200 if res["ok"] else res["status"], res["data"])
                    return
                if path == "/api/v1/beads/ready":
                    res = execute_mcp_tool(backend, "gc_beads", {"action": "ready", "query": query})
                    self._send_json(200 if res["ok"] else res["status"], res["data"])
                    return
                if path == "/api/v1/formulas":
                    res = execute_mcp_tool(backend, "gc_formulas", {"action": "list", "query": query})
                    self._send_json(200 if res["ok"] else res["status"], res["data"])
                    return
                target = REST_V1_GET_ROUTES[path].format(city=backend.city_name)
                res = backend.supervisor_json("GET", target, query=query)
                self._send_json(res["status"], res["data"])
                return

            if path in REST_V1_CLI_GET_ROUTES:
                cmd, default_args = REST_V1_CLI_GET_ROUTES[path]
                res = backend.run_cli(cmd, list(default_args))
                self._send_json(200 if res["ok"] else 500, res)
                return

            if path in ("/mcp", "/sse"):
                auth_ok, _ = backend.oauth.check_request_auth(
                    self.headers.get("Authorization"), require_auth=self._is_external_request()
                )
                if not auth_ok:
                    self._send_unauthorized()
                    return
                accept = self.headers.get("Accept", "")
                if path == "/sse" or "text/event-stream" in accept:
                    body = (
                        ("event: endpoint\ndata: /mcp\n\n" if path == "/sse" else ": ping\n\n")
                    ).encode("utf-8")
                    self.send_response(200)
                    self._send_cors()
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self._send_json(
                    200,
                    {
                        "name": "gc-mcp-rest",
                        "version": "1.0.0",
                        "protocolVersion": "2025-03-26",
                        "transport": ["streamable-http", "sse"],
                        "tools_count": len(MCP_TOOLS),
                        "resources_count": len(MCP_RESOURCES),
                    },
                )
                return

            if path.startswith("/v0/") or path == "/v0":
                self._proxy_supervisor("GET")
                return

            self._send_json(404, {"ok": False, "error": f"Not found: {path}"})

        def do_POST(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            req_base = self._request_base_url()

            if path in ("/oauth/register", "/oauth/token", "/device/code", "/device/approve", "/device/poll"):
                raw = self._read_body()
                raw_text = raw.decode("utf-8", errors="replace") if raw else ""
                body = _try_parse_json(raw_text) if raw_text else {}
                if not isinstance(body, dict):
                    body = {k: v[0] for k, v in urllib.parse.parse_qs(raw_text).items()} if raw_text else {}
                if path == "/oauth/register":
                    self._send_json(201, backend.oauth.register_client(body))
                    return
                if path == "/oauth/token":
                    st, tok_payload = backend.oauth.exchange_code(body, req_base_url=req_base)
                    self._send_json(st, tok_payload)
                    return
                if path == "/device/code":
                    self._send_json(200, backend.oauth.start_device_flow(body, req_base_url=req_base))
                    return
                if path == "/device/approve":
                    st, app_payload = backend.oauth.approve_device_flow(
                        user_code=str(body.get("user_code", "")),
                        email=str(body.get("email", "buihongduc132@gmail.com")),
                    )
                    self._send_json(st, app_payload)
                    return
                if path == "/device/poll":
                    st, poll_payload = backend.oauth.poll_device_flow(body, req_base_url=req_base)
                    self._send_json(st, poll_payload)
                    return

            auth_ok, _ = backend.oauth.check_request_auth(
                self.headers.get("Authorization"), require_auth=self._is_external_request()
            )
            if not auth_ok:
                self._read_body()
                self._send_unauthorized()
                return

            if path in ("/mcp", "/messages"):
                self._handle_mcp_post()
                return

            if path.startswith("/v0/"):
                self._proxy_supervisor("POST")
                return

            raw = self._read_body()
            payload = _try_parse_json(raw.decode("utf-8", errors="replace")) or {}

            if path == "/api/v1/multi-exec":
                res = execute_mcp_tool(backend, "gc_multi_exec", payload)
                self._send_json(200 if res.get("ok") else 400, res)
                return

            if path == "/api/v1/cli":
                cmd = str(payload.get("command", ""))
                args = [str(x) for x in (payload.get("args") or [])]
                timeout = float(payload.get("timeout", 60))
                res = backend.run_cli(cmd, args, timeout=timeout)
                self._send_json(200 if res["ok"] else 400, res)
                return

            if path == "/api/v1/rest":
                method = str(payload.get("method", "GET"))
                target_path = str(payload.get("path", "/health"))
                res = backend.supervisor_json(
                    method=method,
                    path=target_path,
                    query=payload.get("query"),
                    body=payload.get("body"),
                )
                self._send_json(200 if res["ok"] else res["status"], res)
                return

            if path == "/api/v1/sling":
                res = execute_mcp_tool(backend, "gc_sling", payload)
                self._send_json(200 if res.get("ok") else 400, res)
                return

            if path == "/api/v1/formula/cook":
                res = execute_mcp_tool(
                    backend,
                    "gc_formulas",
                    {"action": "cook", "name": payload.get("name", ""), "cook_args": payload.get("args") or []},
                )
                self._send_json(200 if res.get("ok") else 400, res)
                return

            if path == "/api/v1/bd":
                res = backend.run_cli("bd", [str(x) for x in (payload.get("args") or [])])
                self._send_json(200 if res["ok"] else 400, res)
                return

            if path in ("/api/v1/nudge", "/api/v1/handoff", "/api/v1/reload", "/api/v1/converge"):
                cmd = path.rsplit("/", 1)[-1]
                res = backend.run_cli(cmd, [str(x) for x in (payload.get("args") or [])])
                self._send_json(200 if res["ok"] else 400, res)
                return

            self._send_json(404, {"ok": False, "error": f"Not found: {path}"})

        def do_PUT(self) -> None:
            if self.path.startswith("/v0/"):
                self._proxy_supervisor("PUT")
            else:
                self._read_body()
                self._send_json(404, {"ok": False, "error": f"Not found: {self.path}"})

        def do_PATCH(self) -> None:
            if self.path.startswith("/v0/"):
                self._proxy_supervisor("PATCH")
            else:
                self._read_body()
                self._send_json(404, {"ok": False, "error": f"Not found: {self.path}"})

        def do_DELETE(self) -> None:
            if self.path.startswith("/mcp") or self.path.startswith("/sse"):
                self._read_body()
                self._send_json(200, {"ok": True})
            elif self.path.startswith("/v0/"):
                self._proxy_supervisor("DELETE")
            else:
                self._read_body()
                self._send_json(404, {"ok": False, "error": f"Not found: {self.path}"})

        def _proxy_supervisor(self, method: str) -> None:
            raw = self._read_body() if method in ("POST", "PUT", "PATCH", "DELETE") else None
            ct = self.headers.get("Content-Type", "application/json")
            status, headers, resp_bytes = backend.supervisor_request(
                method=method,
                path=self.path,
                raw_body=raw,
                content_type=ct,
            )
            self.send_response(status)
            self._send_cors()
            self.send_header("Content-Type", headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(resp_bytes)))
            self.end_headers()
            self.wfile.write(resp_bytes)

        def _handle_mcp_post(self) -> None:
            raw = self._read_body()
            msg = _try_parse_json(raw.decode("utf-8", errors="replace"))
            if msg is None:
                self._send_json(
                    400,
                    {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
                )
                return

            session_id = self.headers.get("Mcp-Session-Id") or "gcmcp-session-1"
            extra_hdrs = {"Mcp-Session-Id": session_id}

            if isinstance(msg, list):
                responses = [self._dispatch_jsonrpc(item) for item in msg]
                filtered = [r for r in responses if r is not None]
                self._send_json(200, filtered, extra_headers=extra_hdrs)
                return

            resp = self._dispatch_jsonrpc(msg)
            if resp is None:
                self.send_response(202)
                self._send_cors()
                self.send_header("Mcp-Session-Id", session_id)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._send_json(200, resp, extra_headers=extra_hdrs)

        def _dispatch_jsonrpc(self, req: dict[str, Any]) -> dict[str, Any] | None:
            req_id = req.get("id")
            method = req.get("method", "")
            params = req.get("params") or {}

            if method.startswith("notifications/"):
                return None

            if method == "initialize":
                client_proto = params.get("protocolVersion") or "2024-11-05"
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": client_proto,
                        "capabilities": {
                            "tools": {"listChanged": False},
                            "resources": {"listChanged": False},
                            "prompts": {"listChanged": False},
                        },
                        "serverInfo": {
                            "name": "gc-mcp-rest",
                            "version": "1.0.0",
                        },
                    },
                }

            if method == "ping":
                return {"jsonrpc": "2.0", "id": req_id, "result": {}}

            if method == "tools/list":
                return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": MCP_TOOLS}}

            if method == "tools/call":
                tool_name = params.get("name", "")
                tool_args = params.get("arguments") or {}
                known_names = {t["name"] for t in MCP_TOOLS}
                if tool_name not in known_names:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32602, "message": f"Unknown tool: {tool_name}"},
                    }
                result = execute_mcp_tool(backend, tool_name, tool_args)
                is_err = not bool(result.get("ok", True))
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                        "structuredContent": result,
                        "isError": is_err,
                    },
                }

            if method == "resources/list":
                return {"jsonrpc": "2.0", "id": req_id, "result": {"resources": MCP_RESOURCES}}

            if method == "resources/read":
                uri = params.get("uri", "")
                res = read_mcp_resource(backend, uri)
                if not res.get("ok"):
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32602, "message": res.get("error", f"Failed to read {uri}")},
                    }
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "contents": [
                            {
                                "uri": uri,
                                "mimeType": "application/json",
                                "text": json.dumps(res.get("data"), indent=2),
                            }
                        ]
                    },
                }

            if method == "prompts/list":
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "prompts": [
                            {
                                "name": "gc_city_overview",
                                "description": "Summarize Gas City status, active agents, and ready beads.",
                            },
                            {
                                "name": "gc_triage_beads",
                                "description": "Inspect ready and in-progress beads across rigs.",
                            },
                        ]
                    },
                }

            if method == "prompts/get":
                pname = params.get("name", "gc_city_overview")
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "description": f"Prompt for {pname}",
                        "messages": [
                            {
                                "role": "user",
                                "content": {
                                    "type": "text",
                                    "text": f"Call `gc_status` and `gc_beads` (action='ready') to execute {pname}.",
                                },
                            }
                        ],
                    },
                }

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }

    return GCMcpRestHandler


def create_server(
    host: str = "127.0.0.1",
    port: int = 8375,
    backend: GCBackend | None = None,
) -> ThreadingHTTPServer:
    active_backend = backend or GCBackend()
    return ThreadingHTTPServer((host, port), make_handler(active_backend))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gas City Unified MCP & REST Gateway")
    parser.add_argument("--host", default=os.environ.get("GC_MCP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("GC_MCP_PORT", "8375")))
    args = parser.parse_args(argv)

    srv = create_server(host=args.host, port=args.port)
    print(f"gc-mcp-rest listening on http://{args.host}:{args.port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
