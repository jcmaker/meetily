use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::LazyLock,
    time::Duration,
};
use tauri::{AppHandle, Manager, Runtime};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Mutex,
};
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

const RESOURCE: &str = "https://api.openai.com/v1";
const AUTH_BASE: &str = "https://auth.openai.com";
const AUTH_FILE: &str = "chatgpt-auth.json";
const REQUIRED_SCOPE: &str = "chatgpt.tokens.use.direct";
static AUTH_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[derive(Serialize, Deserialize)]
struct AuthStore {
    host_id: String,
    client_id: Option<String>,
    profile: Option<Profile>,
}

#[derive(Serialize, Deserialize)]
struct Profile {
    subject: String,
    email: Option<String>,
    id_token: String,
    access_token: Option<String>,
    refresh_token: Option<String>,
    scopes: Vec<String>,
    expires_at: i64,
}

#[derive(Debug, Serialize)]
pub struct Session {
    pub email: Option<String>,
    pub connected: bool,
    pub plan_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct Model {
    pub slug: String,
    pub display_name: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    scope: Option<String>,
    expires_in: i64,
    token_type: String,
}

#[derive(Deserialize)]
struct Discovery {
    jwks_uri: String,
    revocation_endpoint: String,
}

#[derive(Deserialize)]
struct IdClaims {
    sub: String,
    email: Option<String>,
    nonce: String,
}

struct Callback {
    code: String,
    client_id: String,
}

fn parse_callback(
    raw: &str,
    expected_state: &str,
    saved_client_id: Option<&str>,
) -> Result<Callback, String> {
    let url = Url::parse(raw).map_err(|_| "Invalid ChatGPT callback URL")?;
    if url.host_str() != Some("127.0.0.1") || url.path() != "/auth/callback" {
        return Err("Invalid ChatGPT callback destination".into());
    }
    let mut params = std::collections::HashMap::new();
    for (key, value) in url.query_pairs().into_owned() {
        if params.insert(key, value).is_some() {
            return Err("ChatGPT callback contains duplicate parameters".into());
        }
    }
    if params.get("state").map(String::as_str) != Some(expected_state) {
        return Err("ChatGPT sign-in state mismatch".into());
    }
    if let Some(error) = params.get("error") {
        return Err(format!("ChatGPT sign-in was declined: {error}"));
    }
    let code = params
        .get("code")
        .filter(|value| !value.is_empty())
        .ok_or("ChatGPT sign-in did not return a code")?
        .clone();
    let returned_client_id = params.get("client_id").map(String::as_str);
    let client_id = match saved_client_id {
        Some(saved) if returned_client_id.is_none() || returned_client_id == Some(saved) => saved,
        Some(_) => return Err("ChatGPT client registration changed unexpectedly".into()),
        None => returned_client_id
            .filter(|id| id.starts_with("oaiapp_"))
            .ok_or("ChatGPT sign-in did not return an issued client ID")?,
    };
    Ok(Callback {
        code,
        client_id: client_id.to_string(),
    })
}

fn auth_path(dir: &Path) -> PathBuf {
    dir.join(AUTH_FILE)
}

fn load_store(dir: &Path) -> Result<AuthStore, String> {
    match fs::read(auth_path(dir)) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).map_err(|e| format!("Invalid ChatGPT credentials: {e}"))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(AuthStore {
            host_id: format!("urn:uuid:{}", Uuid::new_v4()),
            client_id: None,
            profile: None,
        }),
        Err(error) => Err(format!("Could not read ChatGPT credentials: {error}")),
    }
}

fn save_store(dir: &Path, store: &AuthStore) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("Could not create app data directory: {e}"))?;
    let temporary = dir.join(format!(".{AUTH_FILE}.{}", Uuid::new_v4()));
    let result = (|| -> Result<(), String> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(|e| e.to_string())?;
        serde_json::to_writer(&mut file, store).map_err(|e| e.to_string())?;
        file.flush().map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        fs::rename(&temporary, auth_path(dir)).map_err(|e| e.to_string())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|e| format!("Could not save ChatGPT credentials: {e}"))
}

fn session(store: &AuthStore) -> Session {
    let profile = store.profile.as_ref();
    let connected = profile.and_then(|p| p.refresh_token.as_ref()).is_some();
    Session {
        email: profile.and_then(|p| p.email.clone()),
        connected,
        plan_enabled: connected
            && profile.is_some_and(|p| p.scopes.iter().any(|s| s == REQUIRED_SCOPE)),
    }
}

fn random_secret() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn auth_client() -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())
}

async fn discovery(client: &Client) -> Result<Discovery, String> {
    client
        .get(format!("{AUTH_BASE}/.well-known/openid-configuration"))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())
}

async fn verify_id_token(
    client: &Client,
    token: &str,
    client_id: &str,
    nonce: &str,
) -> Result<IdClaims, String> {
    let header = decode_header(token).map_err(|_| "Invalid ChatGPT ID token header")?;
    if header.alg != Algorithm::RS256 {
        return Err("Unsupported ChatGPT ID token algorithm".into());
    }
    let kid = header.kid.ok_or("ChatGPT ID token has no key ID")?;
    let jwks: JwkSet = client
        .get(discovery(client).await?.jwks_uri)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    let jwk = jwks
        .keys
        .iter()
        .find(|key| key.common.key_id.as_deref() == Some(kid.as_str()))
        .ok_or("ChatGPT ID token key is unknown")?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| "Invalid ChatGPT signing key")?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[AUTH_BASE]);
    validation.set_audience(&[client_id]);
    let claims = decode::<IdClaims>(token, &key, &validation)
        .map_err(|e| format!("ChatGPT ID token validation failed: {e}"))?
        .claims;
    if claims.nonce != nonce {
        return Err("ChatGPT ID token nonce mismatch".into());
    }
    if claims.sub.is_empty() {
        return Err("ChatGPT ID token has no subject".into());
    }
    Ok(claims)
}

#[tauri::command]
pub async fn chatgpt_get_session<R: Runtime>(app: AppHandle<R>) -> Result<Session, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let _guard = AUTH_LOCK.lock().await;
    Ok(session(&load_store(&dir)?))
}

#[tauri::command]
pub async fn chatgpt_sign_in<R: Runtime>(app: AppHandle<R>) -> Result<Session, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let _guard = AUTH_LOCK.lock().await;
    let mut store = load_store(&dir)?;
    save_store(&dir, &store)?;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let callback_uri = format!(
        "http://127.0.0.1:{}/auth/callback",
        listener.local_addr().map_err(|e| e.to_string())?.port()
    );
    let state = random_secret();
    let nonce = random_secret();
    let verifier = random_secret();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let mut authorization =
        Url::parse(&format!("{AUTH_BASE}/api/accounts/authorize")).map_err(|e| e.to_string())?;
    {
        let mut query = authorization.query_pairs_mut();
        query
            .append_pair(
                "client_id",
                store.client_id.as_deref().unwrap_or("dynamic_agent_client"),
            )
            .append_pair("ext_agent_host_id", &store.host_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", &callback_uri)
            .append_pair(
                "scope",
                "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct",
            )
            .append_pair("resource", RESOURCE)
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge_method", "S256")
            .append_pair("code_challenge", &challenge);
        if store.client_id.is_none() {
            query.append_pair("agent_name_hint", "Meetily");
        }
        if let Some(profile) = &store.profile {
            if !profile.id_token.is_empty() {
                query.append_pair("id_token_hint", &profile.id_token);
            }
            if let Some(email) = &profile.email {
                query.append_pair("login_hint", email);
            }
        }
    }
    webbrowser::open(authorization.as_str()).map_err(|e| format!("Could not open browser: {e}"))?;
    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(180), listener.accept())
        .await
        .map_err(|_| "ChatGPT sign-in timed out")?
        .map_err(|e| e.to_string())?;
    let mut buffer = [0u8; 8192];
    let mut read = 0;
    while !buffer[..read].contains(&b'\n') {
        if read == buffer.len() {
            return Err("ChatGPT callback request is too large".into());
        }
        let count = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut buffer[read..]))
            .await
            .map_err(|_| "ChatGPT callback request timed out")?
            .map_err(|e| e.to_string())?;
        if count == 0 {
            return Err("ChatGPT callback closed early".into());
        }
        read += count;
    }
    let request =
        std::str::from_utf8(&buffer[..read]).map_err(|_| "Invalid ChatGPT callback request")?;
    let target = request
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("GET "))
        .and_then(|line| line.split_whitespace().next())
        .ok_or("Invalid ChatGPT callback request")?;
    let raw_callback = format!(
        "http://127.0.0.1:{}{target}",
        listener.local_addr().map_err(|e| e.to_string())?.port()
    );
    let callback = parse_callback(&raw_callback, &state, store.client_id.as_deref());
    let body = if callback.is_ok() {
        "You can return to Meetily."
    } else {
        "ChatGPT sign-in failed. Return to Meetily."
    };
    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    let _ = socket.write_all(response.as_bytes()).await;
    let callback = callback?;
    if store.client_id.is_none() {
        store.client_id = Some(callback.client_id.clone());
        save_store(&dir, &store)?;
    }
    let client = auth_client()?;
    let token_response: TokenResponse = client
        .post(format!("{AUTH_BASE}/api/accounts/oauth/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", &callback.client_id),
            ("code", &callback.code),
            ("code_verifier", &verifier),
            ("redirect_uri", &callback_uri),
            ("resource", RESOURCE),
        ])
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| format!("ChatGPT token exchange failed: {e}"))?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    if !token_response.token_type.eq_ignore_ascii_case("bearer") {
        return Err("ChatGPT returned an unsupported token type".into());
    }
    let id_token = token_response
        .id_token
        .ok_or("ChatGPT sign-in returned no ID token")?;
    let claims = verify_id_token(&client, &id_token, &callback.client_id, &nonce).await?;
    if store
        .profile
        .as_ref()
        .is_some_and(|p| p.subject != claims.sub)
    {
        return Err("ChatGPT account changed during reconnection".into());
    }
    let scopes: Vec<String> = token_response
        .scope
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    if !scopes.iter().any(|scope| scope == REQUIRED_SCOPE) {
        return Err("ChatGPT plan use was not authorized for this app".into());
    }
    let refresh_token = token_response
        .refresh_token
        .ok_or("ChatGPT sign-in returned no renewable session")?;
    store.profile = Some(Profile {
        subject: claims.sub,
        email: claims.email,
        id_token,
        access_token: Some(token_response.access_token),
        refresh_token: Some(refresh_token),
        scopes,
        expires_at: Utc::now().timestamp() + token_response.expires_in,
    });
    save_store(&dir, &store)?;
    Ok(session(&store))
}

pub async fn access_token(dir: &Path) -> Result<String, String> {
    let _guard = AUTH_LOCK.lock().await;
    let mut store = load_store(dir)?;
    let client_id = store
        .client_id
        .clone()
        .ok_or("Connect ChatGPT in summary settings first")?;
    let profile = store
        .profile
        .as_mut()
        .ok_or("Connect ChatGPT in summary settings first")?;
    if !profile.scopes.iter().any(|scope| scope == REQUIRED_SCOPE) {
        return Err("ChatGPT plan use is not enabled".into());
    }
    if profile.expires_at > Utc::now().timestamp() + 60 {
        if let Some(token) = &profile.access_token {
            return Ok(token.clone());
        }
    }
    let refresh_token = profile
        .refresh_token
        .as_deref()
        .ok_or("Sign in with ChatGPT again")?;
    let response = auth_client()?
        .post(format!("{AUTH_BASE}/api/accounts/oauth/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", refresh_token),
            ("resource", RESOURCE),
        ])
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if refresh_is_unusable(&body) {
            profile.access_token = None;
            profile.refresh_token = None;
            save_store(dir, &store)?;
            return Err("ChatGPT session expired. Sign in again.".into());
        }
        return Err(format!("ChatGPT token refresh failed ({status})"));
    }
    let refreshed: TokenResponse = response.json().await.map_err(|e| e.to_string())?;
    if !refreshed.token_type.eq_ignore_ascii_case("bearer") {
        return Err("ChatGPT returned an unsupported token type".into());
    }
    if let Some(scope) = refreshed.scope {
        let scopes: Vec<String> = scope.split_whitespace().map(str::to_string).collect();
        if !scopes.iter().any(|s| s == REQUIRED_SCOPE) {
            profile.access_token = None;
            profile.refresh_token = None;
            save_store(dir, &store)?;
            return Err("ChatGPT plan use is no longer authorized".into());
        }
        profile.scopes = scopes;
    }
    profile.access_token = Some(refreshed.access_token.clone());
    if let Some(refresh_token) = refreshed.refresh_token {
        profile.refresh_token = Some(refresh_token);
    }
    profile.expires_at = Utc::now().timestamp() + refreshed.expires_in;
    save_store(dir, &store)?;
    Ok(refreshed.access_token)
}

fn refresh_is_unusable(body: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    let code = value.get("error").and_then(|error| {
        error
            .as_str()
            .or_else(|| error.get("code").and_then(|code| code.as_str()))
    });
    matches!(
        code,
        Some(
            "invalid_grant"
                | "invalid_refresh_token"
                | "token_expired"
                | "refresh_token_expired"
                | "refresh_token_invalidated"
                | "refresh_token_reused"
        )
    )
}

#[tauri::command]
pub async fn chatgpt_sign_out<R: Runtime>(app: AppHandle<R>) -> Result<String, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let _guard = AUTH_LOCK.lock().await;
    let mut store = load_store(&dir)?;
    let mut warning = String::new();
    if let (Some(client_id), Some(profile)) = (&store.client_id, &store.profile) {
        if let Some(refresh_token) = &profile.refresh_token {
            let client = auth_client()?;
            let result = async {
                let endpoint = discovery(&client).await?.revocation_endpoint;
                client
                    .post(endpoint)
                    .form(&[
                        ("token", refresh_token.as_str()),
                        ("token_type_hint", "refresh_token"),
                        ("client_id", client_id.as_str()),
                    ])
                    .send()
                    .await
                    .map_err(|e| e.to_string())?
                    .error_for_status()
                    .map_err(|e| e.to_string())?;
                Ok::<(), String>(())
            }
            .await;
            if result.is_err() {
                warning = "Signed out locally; remote revocation could not be confirmed. Disconnect Meetily in ChatGPT settings if needed.".into();
            }
        }
    }
    store.profile = None;
    save_store(&dir, &store)?;
    Ok(warning)
}

#[tauri::command]
pub async fn chatgpt_list_models<R: Runtime>(app: AppHandle<R>) -> Result<Vec<Model>, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let token = access_token(&dir).await?;
    let value: serde_json::Value = auth_client()?
        .get(format!("{RESOURCE}/models"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    Ok(value
        .get("models")
        .and_then(|models| models.as_array())
        .ok_or("Invalid ChatGPT model catalog")?
        .iter()
        .filter(|model| model.get("visibility").and_then(|v| v.as_str()) == Some("list"))
        .filter_map(|model| {
            Some(Model {
                slug: model.get("slug")?.as_str()?.to_string(),
                display_name: model.get("display_name")?.as_str()?.to_string(),
            })
        })
        .collect())
}

#[tauri::command]
pub fn chatgpt_open_usage() -> Result<(), String> {
    webbrowser::open("https://chatgpt.com/settings/usage").map_err(|e| e.to_string())
}

fn parse_response_stream(raw: &str) -> Result<String, String> {
    let mut output = String::new();
    let mut completed = false;
    for frame in raw.replace("\r\n", "\n").split("\n\n") {
        let data = frame
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .collect::<Vec<_>>()
            .join("\n");
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let event: serde_json::Value = serde_json::from_str(&data)
            .map_err(|e| format!("Invalid ChatGPT response event: {e}"))?;
        match event.get("type").and_then(|value| value.as_str()) {
            Some("response.output_text.delta") => output.push_str(
                event
                    .get("delta")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            ),
            Some("response.completed") => completed = true,
            Some("response.failed" | "response.incomplete") => {
                let code = event
                    .pointer("/response/error/code")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown_error");
                return Err(format!("ChatGPT response failed: {code}"));
            }
            _ => {}
        }
    }
    if !completed {
        return Err("ChatGPT response ended before completion".into());
    }
    if output.trim().is_empty() {
        return Err("ChatGPT returned an empty summary".into());
    }
    Ok(output)
}

pub async fn generate_response(
    client: &Client,
    dir: &Path,
    model: &str,
    instructions: &str,
    input: &str,
    cancellation: Option<&CancellationToken>,
) -> Result<String, String> {
    let token = access_token(dir).await?;
    let request = async {
        let response = client
            .post(format!("{RESOURCE}/responses"))
            .bearer_auth(token)
            .json(
                &serde_json::json!({"model": model, "instructions": instructions,
                "input": [{"role": "user", "content": input}], "store": false, "stream": true}),
            )
            .timeout(Duration::from_secs(300))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status();
        let body = response.text().await.map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(format!(
                "ChatGPT request failed ({status}): {}",
                body.chars().take(500).collect::<String>()
            ));
        }
        parse_response_stream(&body)
    };
    if let Some(token) = cancellation {
        tokio::select! { _ = token.cancelled() => Err("Summary generation was cancelled".into()), result = request => result }
    } else {
        request.await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_rejects_wrong_state() {
        let url = "http://127.0.0.1:1234/auth/callback?code=abc&state=wrong&client_id=oaiapp_123";
        assert!(parse_callback(url, "expected", None).is_err());
    }

    #[test]
    fn callback_requires_issued_client_id_for_registration() {
        let url = "http://127.0.0.1:1234/auth/callback?code=abc&state=expected";
        assert!(parse_callback(url, "expected", None).is_err());
    }

    #[test]
    fn callback_rejects_changed_client_id_on_reauthorization() {
        let url =
            "http://127.0.0.1:1234/auth/callback?code=abc&state=expected&client_id=oaiapp_other";
        assert!(parse_callback(url, "expected", Some("oaiapp_saved")).is_err());
    }

    #[test]
    fn callback_accepts_issued_client_id() {
        let url =
            "http://127.0.0.1:1234/auth/callback?code=abc&state=expected&client_id=oaiapp_123";
        let callback = parse_callback(url, "expected", None).unwrap();
        assert_eq!(callback.code, "abc");
        assert_eq!(callback.client_id, "oaiapp_123");
    }

    #[test]
    fn callback_rejects_duplicate_security_parameters() {
        let url = "http://127.0.0.1:1234/auth/callback?code=abc&state=wrong&state=expected&client_id=oaiapp_123";
        assert!(parse_callback(url, "expected", None).is_err());
    }

    #[test]
    fn response_stream_requires_completed_event() {
        let events = "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n";
        assert!(parse_response_stream(events).is_err());
    }

    #[test]
    fn response_stream_returns_only_completed_text() {
        let events = concat!(
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hello\"}\n\n",
            "data: {\"type\":\"response.completed\"}\n\n"
        );
        assert_eq!(parse_response_stream(events).unwrap(), "Hello");
    }

    #[test]
    fn response_stream_rejects_failed_event() {
        let events = "data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"subscription_sharing_usage_limit_exceeded\"}}}\n\n";
        assert!(parse_response_stream(events)
            .unwrap_err()
            .contains("subscription_sharing_usage_limit_exceeded"));
    }

    #[test]
    fn response_stream_rejects_incomplete_event() {
        let events = "data: {\"type\":\"response.incomplete\"}\n\n";
        assert!(parse_response_stream(events).is_err());
    }

    #[test]
    fn session_never_serializes_credentials() {
        let store = AuthStore {
            host_id: "urn:uuid:test".into(),
            client_id: Some("oaiapp_test".into()),
            profile: Some(Profile {
                subject: "test".into(),
                email: Some("test@example.com".into()),
                id_token: "private-id-token".into(),
                access_token: Some("private-access-token".into()),
                refresh_token: Some("private-refresh-token".into()),
                scopes: vec![REQUIRED_SCOPE.into()],
                expires_at: i64::MAX,
            }),
        };
        let json = serde_json::to_string(&session(&store)).unwrap();
        assert!(json.contains("test@example.com"));
        assert!(!json.contains("private-"));
    }

    #[cfg(unix)]
    #[test]
    fn credential_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("meetily-auth-test-{}", Uuid::new_v4()));
        let store = load_store(&dir).unwrap();
        save_store(&dir, &store).unwrap();
        let permissions = fs::metadata(auth_path(&dir)).unwrap().permissions().mode() & 0o777;
        assert_eq!(permissions, 0o600);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn terminal_refresh_errors_require_new_sign_in() {
        assert!(refresh_is_unusable(r#"{"error":"invalid_grant"}"#));
        assert!(refresh_is_unusable(
            r#"{"error":{"code":"refresh_token_reused"}}"#
        ));
        assert!(!refresh_is_unusable(
            r#"{"error":"temporarily_unavailable"}"#
        ));
    }
}
