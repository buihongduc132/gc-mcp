# `gc-mcp` — Multi-Machine Gas City & CLI-to-MCP / REST Gateway (with Google OAuth 2.1 + PKCE Device Flow)

`gc-mcp` is a standalone, zero-lock-in MCP (Model Context Protocol) and REST gateway that:
1. **Exposes 100% of Gas City (`gc`)** over Streamable HTTP (`/mcp`), SSE (`/sse`), high-level REST (`/api/v1/*`), and native Supervisor proxy (`/v0/*`).
2. **Wires Multiple Runtimes (Cities) Across Multiple Machines (`1..N` hosts)**:
   - Configure any number of `[[machines]]` (`local`, `ssh`, or remote `http`) and `[[cities]]` in a single TOML/JSON file (`GC_MCP_CONFIG`).
   - Fan out commands across multiple machines in parallel via `gc_multi_exec` or `POST /api/v1/multi-exec`.
3. **Wraps Any Local or Remote CLI into MCP (`[[clis]]` + FastMCP 3.x Bridge)**:
   - Declaratively wrap `gc`, `gt`, `bd`, `herdr`, or any custom CLI binary across `1..N` machines (`src/gc_mcp/fleet.py` & `src/gc_mcp/fastmcp_bridge.py`).
   - Mount downstream stdio/HTTP MCP servers via `FastMCP.as_proxy`.
4. **Supports Full OAuth 2.1 (Google OAuth Proxy + Desktop-Commander PKCE Device Flow)**:
   - **MCP OAuth 2.1 + DCR**: `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `POST /oauth/register`, `GET /oauth/authorize`, `POST /oauth/token`.
   - **Google OAuth (`GoogleProvider` / OIDC)**: Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GC_OAUTH_ALLOWED_EMAILS`.
   - **Desktop-Commander-Style RFC 8628 Device Code + PKCE S256 Flow**: `POST /device/code`, `GET /device/verify`, `POST /device/approve`, `POST /device/poll`.

## Quick Start

```bash
cp config/cities.example.toml config/cities.toml
GC_MCP_CONFIG=config/cities.toml python3 -m gc_mcp.server --host 127.0.0.1 --port 8375
```
