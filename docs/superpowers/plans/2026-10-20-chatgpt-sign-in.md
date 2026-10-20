# ChatGPT Sign-in Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add ChatGPT plan login and text meeting summaries to the Meetily desktop app.

**Architecture:** A Rust module owns the OAuth session and Responses API calls. Tauri commands expose only connection state and model names. The existing summary processor invokes a new `chatgpt` provider while the UI chooses that provider and account model.

**Tech Stack:** Rust/Tauri, reqwest, Tokio, Next.js/TypeScript.

**Spec:** `docs/superpowers/specs/2026-10-20-chatgpt-sign-in-design.md`

## Global Constraints

- Keep existing OpenAI and Claude API-key providers working.
- Never pass OAuth tokens into the web UI, SQLite, logs or Git.
- Responses requests use `store:false`, `stream:true`; only `response.completed` succeeds.
- Local transcription is unchanged.

## Review Focus

- Callback with a mismatched state or client ID must not save credentials.
- An ID token with wrong nonce, audience or signature must be rejected.
- An expired access token refreshes once and rotating tokens replace the old set atomically.
- A stream that fails or ends before `response.completed` must not return a summary.
- Changing back to an API-key provider must continue to work.

---

### Task 1: Native sign-in and credential lifecycle

**Files:** Create `frontend/src-tauri/src/chatgpt.rs`; modify `frontend/src-tauri/Cargo.toml`, `frontend/src-tauri/src/lib.rs`.

**Interfaces:** `chatgpt_sign_in`, `chatgpt_get_session`, `chatgpt_sign_out`, `chatgpt_list_models` Tauri commands; internal `access_token(app_data_dir: &Path) -> Result<String, String>`.

- [ ] Write tests for callback and identity validation, invalid grants, and token refresh replacement.
- [ ] Run tests and confirm failure.
- [ ] Implement loopback PKCE, token validation and protected storage with the smallest isolated module.
- [ ] Run focused Rust tests and confirm pass.

### Task 2: Summary inference

**Files:** Modify `frontend/src-tauri/src/summary/llm_client.rs`, `frontend/src-tauri/src/summary/service.rs`, `frontend/src-tauri/src/database/repositories/setting.rs`.

**Interfaces:** `LLMProvider::ChatGPT`; `generate_summary` reads the token through `chatgpt::access_token` and calls Responses.

- [ ] Write parser tests for completed, failed and truncated SSE streams.
- [ ] Run tests and confirm failure.
- [ ] Implement the `chatgpt` Responses path and provider configuration.
- [ ] Run focused Rust tests and confirm pass.

### Task 3: Settings UI

**Files:** Modify `frontend/src/components/ModelSettingsModal.tsx`, `frontend/src/services/configService.ts`, `frontend/src/components/SummaryModelSettings.tsx`, `frontend/src/hooks/meeting-details/useModelConfiguration.ts`, and any exhaustive provider maps reported by typecheck.

**Interfaces:** UI calls only session/model Tauri commands; saved provider value is `chatgpt` with no API key.

- [ ] Add connection controls, model loading and correct save validation.
- [ ] Run TypeScript typecheck and lint; fix failures caused by the provider addition.
- [ ] Verify Rust check, focused tests and Git diff before pushing the branch to the personal fork.
