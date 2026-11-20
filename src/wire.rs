// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 EON contributors

//! The transport rules of `docs/api.md`: JSON, base64url, the error shape.

use std::io::Read;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::Error;

const MAX_BODY: u64 = 16 * 1024 * 1024;

pub fn b64(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn unb64(text: &str) -> Result<Vec<u8>, Error> {
    B64.decode(text)
        .map_err(|_| Error::Protocol("a binary value is not base64url".into()))
}

/// A server address the client will talk to: HTTPS, or plain HTTP to this
/// machine only (for a server someone runs locally, and for tests).
pub fn check_server(raw: &str) -> Result<String, Error> {
    let url = raw.trim().trim_end_matches('/').to_owned();
    let loopback = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
        .iter()
        .any(|p| url == *p || url.starts_with(&format!("{p}:")));
    let rest = url.strip_prefix("https://").unwrap_or("");
    let https = !rest.is_empty() && !rest.contains(['/', '?', '#', '@', ' ']);
    if https || loopback {
        Ok(url)
    } else {
        Err(Error::Invalid("server address".into()))
    }
}

pub struct Wire {
    agent: ureq::Agent,
    pub base: String,
}

impl Wire {
    pub fn new(base: String) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirects(0)
            .user_agent(concat!("eon-account-client/", env!("CARGO_PKG_VERSION")))
            .build();
        Self { agent, base }
    }

    pub fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<T, Error> {
        let text = self.raw(method, path, token, body)?;
        let text = if text.trim().is_empty() {
            "null"
        } else {
            &text
        };
        serde_json::from_str(text).map_err(|e| Error::Network(format!("unexpected answer: {e}")))
    }

    pub fn raw(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<String, Error> {
        let mut req = self.agent.request(method, &format!("{}{path}", self.base));
        if let Some(t) = token {
            req = req.set("Authorization", &format!("Bearer {t}"));
        }
        let result = match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        };
        match result {
            Ok(resp) => read(resp),
            Err(ureq::Error::Status(status, resp)) => {
                let text = read(resp).unwrap_or_default();
                Err(error_from(status, &text))
            }
            Err(e) => Err(Error::Network(e.kind().to_string())),
        }
    }
}

fn read(resp: ureq::Response) -> Result<String, Error> {
    let mut text = String::new();
    resp.into_reader()
        .take(MAX_BODY)
        .read_to_string(&mut text)
        .map_err(|e| Error::Network(e.to_string()))?;
    Ok(text)
}

fn error_from(status: u16, text: &str) -> Error {
    let body: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    let message = body["message"].as_str().unwrap_or("").to_owned();
    match body["error"].as_str().unwrap_or("") {
        "invalid" => Error::Invalid(message),
        "taken" => Error::Taken,
        "unauthorised" => Error::Unauthorised,
        "forbidden" => Error::Forbidden,
        "not_found" => Error::NotFound,
        "conflict" => Error::Conflict(body["version"].as_u64().unwrap_or(0)),
        "too_large" => Error::TooLarge,
        "rate_limited" => Error::RateLimited,
        "closed" => Error::Closed,
        "unavailable" => Error::Unavailable,
        _ => Error::Network(format!("HTTP {status}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_or_this_machine() {
        assert_eq!(
            check_server("https://account.example.org/").as_deref(),
            Ok("https://account.example.org")
        );
        assert!(check_server("http://127.0.0.1:8080").is_ok());
        assert!(check_server("http://localhost").is_ok());
        for bad in [
            "http://account.example.org",
            "https://",
            "https://a.example/path",
            "https://user@a.example",
            "ftp://a.example",
            "http://127.0.0.1.evil.example",
            "http://localhost.evil.example",
        ] {
            assert!(check_server(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn errors_map_to_their_kind() {
        assert_eq!(
            error_from(409, r#"{"error":"taken","message":"x"}"#),
            Error::Taken
        );
        assert_eq!(
            error_from(409, r#"{"error":"conflict","message":"x","version":4}"#),
            Error::Conflict(4)
        );
        assert_eq!(error_from(502, "<html>"), Error::Network("HTTP 502".into()));
    }
}
