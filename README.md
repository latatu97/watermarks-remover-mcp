# watermarks-remover MCP for ChatGPT

Private, authenticated Model Context Protocol adapter for [guillaumemeyer/watermarks-remover](https://github.com/guillaumemeyer/watermarks-remover).

## Deployed services
- Original engine: https://watermarks-remover-private-api.onrender.com
- MCP adapter: https://watermarks-remover-mcp-2wee.onrender.com/mcp
- Render dashboard: https://dashboard.render.com/web/srv-dc05g90jo6nc73f2juc0

## Required Render environment
- WATERMARKS_SERVICE_URL: the HTTPS engine URL above
- WATERMARKS_SERVER_API_KEY: secret used to access the engine, managed in Render
- MCP_BEARER_TOKEN: independent secret required for each MCP call, managed in Render
- MCP_PUBLIC_HOST: watermarks-remover-mcp-2wee.onrender.com

**Never commit secrets to GitHub or paste them into chat.** Connect the plugin using ChatGPT's secure credential dialog. If the MCP secret is not available to you, rotate it in the Render Environment settings, then enter the new value in the ChatGPT connection dialog.

## Scope
The available tools are check_engine, engine_capabilities, inspect_document and clean_document. They use the original engine's API. They require file bytes encoded as base64; the bridge does not automatically read uploaded ChatGPT attachments. Maximum supported file size is 512 KiB per call. File processing requires the user's explicit approval for transfer to the Render service.

No guarantee is made regarding SynthID, invisible pixel-level marks, or other robust provenance features. Only features reported by engine_capabilities should be described as available.

For healthcare or personally identifying documents, do not transmit the files without appropriate data-protection assessment and authorization.
