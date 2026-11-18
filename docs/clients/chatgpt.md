# Connect Kule to ChatGPT

Use a deployed Kule instance with OAuth enabled and a valid HTTPS endpoint, such as `https://mcp.example.com/mcp`. Replace example domains with your own. See the [README](../../README.md) for server setup. Start with read-only privileges and keep host execution disabled for initial testing.

## Add the plugin

1. Open ChatGPT's **Plugins** area and choose **+ → Add custom MCP server**.
2. Set the name to **Kule**, supply the HTTPS MCP endpoint, and select OAuth authentication. If your account supports Secure MCP Tunnel, consult its documentation before using it; a private URL alone is not reachable from the cloud.
3. Review the risk notice, create the plugin, and inspect the discovered operations. Sign in through your configured identity provider and authorize the requested access.
4. Open a new chat, select Kule (or mention it), and ask it to call `whoami`. Confirm the returned identity and expected privileges before enabling additional integrations.

Account and workspace restrictions may affect custom plugin availability. Older interfaces may instead use Settings → Apps → Create and require Developer mode.

## Troubleshooting

- **OAuth failure:** check the advertised issuer, HTTPS public URL, exact authorized callback allowlist and identity-provider group mapping. Never loosen callbacks to arbitrary domains.
- **Repeated sign-in:** verify that the identity provider grants refresh tokens (including `offline_access` when required), persistent OAuth state and refresh-token behavior.
- **Tools missing:** compare the authorized MCP `tools/list` response with the client-visible schema; refresh/review the plugin in the client where supported. Workspace approval and cached tool definitions can affect visibility.
- **Access denied:** check the principal's Kule and backend permissions. Do not broaden permissions just to pass a smoke test.
- Disconnect the plugin in ChatGPT when no longer needed; server-side revocation must also be enforced by your authorization infrastructure.

Reference: [OpenAI — Connecting custom MCP servers in ChatGPT](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt). UI checked against public documentation on 2026-11-18; this guide is not a fresh end-to-end deployment test.
