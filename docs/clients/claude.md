# Connect Kule to Claude

Use a deployed Kule instance with OAuth enabled and a publicly reachable HTTPS endpoint on the standard HTTPS port, such as `https://mcp.example.com/mcp`. Claude's remote connector runs from Anthropic's infrastructure, not from your device. See the [README](../../README.md) for server setup. Use a least-privilege identity for initial testing.

## Add the connector

1. In Claude, open **Customize → Connectors → + Add → Add custom connector**.
2. Name the connector **Kule**, enter your full MCP endpoint, and continue.
3. Review the detected OAuth settings and choose to sign in now or when needed.
4. Select the OAuth client registration option supported by your Kule deployment. Claude's published client identity is the recommended option when supported; otherwise use automatic registration (DCR). Use your own OAuth client only when explicitly configured on the server.
5. Complete setup and sign in through your identity provider.
6. Enable Kule for a conversation and ask Claude to call `whoami`. Verify identity and permissions before using write operations.

Workspace administrators may need to approve custom connectors.

## Troubleshooting

- **Client Not Registered:** a server may not support Claude's published client metadata identity. Try automatic registration if enabled and compatible. A manually registered client must explicitly allow the exact callback `https://claude.ai/api/mcp/auth_callback`; provide its issued client ID and secret only if required. Do not disable OAuth or accept arbitrary redirects.
- **Connection failed:** verify a cloud-reachable HTTPS endpoint, correct MCP path, TLS certificate and reverse-proxy configuration.
- **Access denied or missing tools:** verify identity claims, enabled integrations, tool discovery and backend authorization.
- **Repeated authentication:** verify persistent OAuth state and supported refresh-token flows.
- Disconnect Kule in Claude when no longer needed; enforce grant revocation at the authorization server as well.

Reference: [Anthropic — Get started with custom connectors using remote MCP](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp). UI checked against public documentation on 2026-11-18; this guide is not a fresh end-to-end deployment test.
