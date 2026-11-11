"""Reusable FastMCP 3.x Bridge for wrapping any CLI / MCP across 1..N machines with Google OAuth."""
from __future__ import annotations

import os
from typing import Any

from .fleet import FleetRouter


def build_fastmcp_gateway(
    name: str = "gc-multi-machine-mcp",
    fleet: FleetRouter | None = None,
    proxy_mcp_servers: dict[str, dict[str, Any]] | None = None,
    enable_google_oauth: bool = False,
) -> Any:
    """
    Builds a FastMCP 3.x server that:
      1. Wraps every configured CLI in FleetRouter (`gc`, `gt`, `bd`, `herdr`, etc.) as MCP tools
         capable of executing on 1 or multiple machines (`machine` / `machines` params).
      2. Optionally mounts any downstream stdio/HTTP MCP servers via `FastMCP.as_proxy`.
      3. Optionally secures the HTTP/SSE transport with `GoogleProvider` (OAuth 2.1 + DCR proxy).
    """
    from fastmcp import FastMCP

    router = fleet or FleetRouter.from_config()
    auth_provider = None
    if enable_google_oauth and os.environ.get("GOOGLE_CLIENT_ID"):
        from fastmcp.server.auth.providers.google import GoogleProvider

        auth_provider = GoogleProvider(
            client_id=os.environ["GOOGLE_CLIENT_ID"],
            client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
            base_url=os.environ.get("GC_MCP_BASE_URL", "http://localhost:8375"),
            required_scopes=["openid", "https://www.googleapis.com/auth/userinfo.email"],
            allowed_client_redirect_uris=["http://localhost:*", "http://127.0.0.1:*", "https://*"],
        )

    mcp = FastMCP(name=name, auth=auth_provider)

    @mcp.tool()
    def fleet_inventory() -> dict[str, Any]:
        """List all configured machines, Gas City runtimes (cities), and wrapped CLIs."""
        return router.inventory()

    @mcp.tool()
    def cli_exec(
        cli: str,
        subcommand: str,
        args: list[str] | None = None,
        machine: str | None = None,
        cwd: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Execute any configured CLI (`gc`, `gt`, `bd`, `herdr`, etc.) on a target machine."""
        return router.run_wrapped_cli(
            cli_name=cli,
            subcommand=subcommand,
            args=args,
            machine=machine,
            cwd=cwd,
            timeout=timeout,
        )

    @mcp.tool()
    def cli_fanout(
        cli: str,
        subcommand: str,
        args: list[str] | None = None,
        machines: list[str] | None = None,
        timeout: float = 20.0,
    ) -> dict[str, Any]:
        """Execute a wrapped CLI command across multiple machines in parallel."""
        return router.fanout_cli(
            cli_name=cli,
            subcommand=subcommand,
            args=args,
            machines=machines,
            timeout=timeout,
        )

    if proxy_mcp_servers:
        proxy = FastMCP.as_proxy({"mcpServers": proxy_mcp_servers}, name=f"{name}-proxy")
        mcp.mount(proxy, namespace="proxy")

    return mcp
