"""Unit and integration tests for gc-mcp (Multi-Machine Fleet, Generic CLI Wrapper, OAuth 2.1 + PKCE Device Flow)."""
from __future__ import annotations

import json
from pathlib import Path
import threading
import urllib.error
import urllib.request

from gc_mcp.fastmcp_bridge import build_fastmcp_gateway
from gc_mcp.fleet import CityRuntime, CLISpec, FleetRouter, MachineTarget
from gc_mcp.oauth import OAuthManager, _pkce_s256
from gc_mcp.server import GCBackend, create_server, execute_mcp_tool


def _http_json(method: str, url: str, body: dict | None = None, headers: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req_headers = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_fleet_router_multi_machine_and_cli_wrap(tmp_path: Path) -> None:
    cfg = tmp_path / "fleet.toml"
    cfg.write_text(
        """
default_machine = "m1"
default_city = "city-a"

[[machines]]
id = "m1"
transport = "local"
supervisor_url = "http://127.0.0.1:8372"
gc_bin = "/bin/echo"
default_city = "city-a"
default_cwd = "/tmp"

[[machines]]
id = "m2"
transport = "local"
supervisor_url = "http://127.0.0.1:8372"
gc_bin = "/bin/echo"
default_city = "city-b"
default_cwd = "/tmp"

[[cities]]
name = "city-a"
machine = "m1"
city_dir = "/tmp"

[[cities]]
name = "city-b"
machine = "m2"
city_dir = "/tmp"

[[clis]]
name = "echo_cli"
binary = "/bin/echo"
allowed_subcommands = ["hello", "status"]
default_machine = "m1"
"""
    )
    router = FleetRouter.from_config(cfg)
    inv = router.inventory()
    assert len(inv["machines"]) == 2
    assert len(inv["cities"]) == 2

    res = router.run_wrapped_cli("echo_cli", "hello", ["world"], machine="m1")
    assert res["ok"] is True
    assert res["stdout"] == "hello world"

    denied = router.run_wrapped_cli("echo_cli", "forbidden", [])
    assert denied["ok"] is False

    fanout = router.fanout_cli("echo_cli", "status", ["--ok"], machines=["m1", "m2"])
    assert fanout["ok"] is True
    assert set(fanout["results"].keys()) == {"m1", "m2"}


def test_oauth_pkce_and_desktop_commander_device_flow() -> None:
    oauth = OAuthManager(
        base_url="https://mcp.example.com",
        auth_mode="required",
        google_client_id="12345.apps.googleusercontent.com",
        allowed_emails=["buihongduc132@gmail.com"],
    )
    meta = oauth.metadata()
    assert meta["google_oauth_configured"] is True
    assert "urn:ietf:params:oauth:grant-type:device_code" in meta["grant_types_supported"]

    # 1. DCR + Auth Code + PKCE S256
    client = oauth.register_client({"client_name": "TestClient"})
    verifier = "test-pkce-code-verifier-1234567890"
    challenge = _pkce_s256(verifier)
    code = oauth.create_authorization_code(
        client_id=client["client_id"],
        redirect_uri="http://localhost:8000/cb",
        code_challenge=challenge,
        email="buihongduc132@gmail.com",
    )
    st_bad, _ = oauth.exchange_code({"code": code, "code_verifier": "wrong"})
    assert st_bad == 400

    code2 = oauth.create_authorization_code(
        client_id=client["client_id"],
        redirect_uri="http://localhost:8000/cb",
        code_challenge=challenge,
        email="buihongduc132@gmail.com",
    )
    st_ok, tok = oauth.exchange_code({"code": code2, "code_verifier": verifier})
    assert st_ok == 200
    assert "access_token" in tok
    ok, claims = oauth.check_request_auth(f"Bearer {tok['access_token']}")
    assert ok is True
    assert claims["email"] == "buihongduc132@gmail.com"

    # 2. Desktop Commander style Device Code + PKCE S256 flow
    dev = oauth.start_device_flow({"device_id": "bhd-main2", "code_challenge": challenge})
    st_pending, pending_body = oauth.poll_device_flow(
        {"device_code": dev["device_code"], "code_verifier": verifier}
    )
    assert st_pending == 400
    assert pending_body["error"] == "authorization_pending"

    st_app, _ = oauth.approve_device_flow(dev["user_code"], email="buihongduc132@gmail.com")
    assert st_app == 200

    st_poll, dev_tok = oauth.poll_device_flow(
        {"device_code": dev["device_code"], "code_verifier": verifier}
    )
    assert st_poll == 200
    assert dev_tok["device_id"] == "bhd-main2"
    assert oauth.verify_token(dev_tok["access_token"]) is not None


def test_http_server_oauth_and_multi_machine_endpoints() -> None:
    fleet = FleetRouter(
        machines={"bhd-main2": MachineTarget(id="bhd-main2", transport="local", gc_bin="/bin/echo")},
        cities={"gascity": CityRuntime(name="gascity", machine="bhd-main2", city_dir="/tmp")},
        clis={"gc": CLISpec(name="gc", binary="/bin/echo", default_machine="bhd-main2")},
    )
    oauth = OAuthManager(base_url="http://127.0.0.1:0", auth_mode="required", allowed_emails=["buihongduc132@gmail.com"])
    backend = GCBackend(city_dir="/tmp", gc_bin="/bin/echo", fleet=fleet, oauth=oauth)
    srv = create_server(host="127.0.0.1", port=0, backend=backend)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"
    try:
        st, meta = _http_json("GET", f"{base}/.well-known/oauth-authorization-server")
        assert st == 200
        assert meta["auth_mode"] == "required"

        # Unauthenticated POST /mcp must return 401 when auth_mode == required
        st_unauth, _ = _http_json("POST", f"{base}/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert st_unauth == 401

        # Complete Device Code flow over HTTP
        verifier = "http-device-verifier-987654321"
        challenge = _pkce_s256(verifier)
        st_dc, dc_data = _http_json("POST", f"{base}/device/code", {"device_id": "pad1", "code_challenge": challenge})
        assert st_dc == 200
        st_ap, _ = _http_json(
            "POST",
            f"{base}/device/approve",
            {"user_code": dc_data["user_code"], "email": "buihongduc132@gmail.com"},
        )
        assert st_ap == 200
        st_pl, tok_data = _http_json(
            "POST",
            f"{base}/device/poll",
            {"device_code": dc_data["device_code"], "code_verifier": verifier},
        )
        assert st_pl == 200
        headers = {"Authorization": f"Bearer {tok_data['access_token']}"}

        # Authenticated MCP call to gc_machines & gc_multi_exec
        st_mcp, mcp_res = _http_json(
            "POST",
            f"{base}/mcp",
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "gc_machines", "arguments": {}},
            },
            headers=headers,
        )
        assert st_mcp == 200
        assert mcp_res["result"]["structuredContent"]["ok"] is True

        st_exec, exec_res = _http_json(
            "POST",
            f"{base}/api/v1/multi-exec",
            {"cli": "gc", "subcommand": "version", "machines": ["bhd-main2"]},
            headers=headers,
        )
        assert st_exec == 200
        assert exec_res["ok"] is True
    finally:
        srv.shutdown()
        srv.server_close()


def test_fastmcp_gateway_builder() -> None:
    import subprocess
    venv_py = "/data/dev/projects/mcp-hub-standalone/.venv/bin/python"
    if Path(venv_py).is_file():
        proc = subprocess.run(
            [
                venv_py,
                "-c",
                "import sys; sys.path.insert(0, '/data/dev/projects/gc-mcp/src'); "
                "from gc_mcp.fastmcp_bridge import build_fastmcp_gateway; "
                "gw = build_fastmcp_gateway(name='test-fastmcp-gw'); "
                "assert gw.name == 'test-fastmcp-gw'",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
    else:
        gw = build_fastmcp_gateway(name="test-fastmcp-gw")
        assert gw is not None
