# ChatGPT sign-in for meeting summaries

## Goal

Let a local Meetily installation use an eligible user's ChatGPT plan for text meeting summaries after browser sign-in. Keep Claude's existing API-key integration.

## Scope

- Add a separate `chatgpt` summary provider. Keep the existing `openai` API-key provider and all transcription providers.
- Run OAuth authorization-code with PKCE in the Tauri Rust process via the system browser and a loopback callback. Use OpenAI's dynamic OSS client registration and a stable, opaque host ID.
- Verify callback state, the issued client ID, ID-token signature, issuer, audience, expiry and nonce, then require the `chatgpt.tokens.use.direct` grant before enabling summaries.
- Keep OAuth credentials in an app-data file with owner-only permissions on Unix. Never send access or refresh tokens to the web UI, logs, SQLite or Git.
- Refresh a near-expiry access token with the saved issued client ID. Serialize refreshes and replace rotating credentials atomically.
- Fetch the signed-in account's model catalog; send summaries to `POST /v1/responses` with `store:false` and `stream:true`, and accept output only after `response.completed`.
- Show connection status, sign-in, sign-out, model selection and a link to ChatGPT usage in summary settings. Sign-out revokes the refresh token when reachable and clears local credentials.

## Failure behavior and tests

An invalid callback, token or scope does not activate the connection. Interrupted, failed or incomplete response streams do not save a partial summary. Errors are shown without token values. Tests cover OAuth callback validation, model filtering, Responses stream completion and refresh behavior; frontend typecheck and Rust checks cover wiring.

## Constraints

ChatGPT login covers text summarization only. Meetily's local transcription remains unchanged. Claude subscription login is excluded because Anthropic does not permit unapproved third-party products to offer it; the existing Claude API-key path remains available.
