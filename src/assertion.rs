// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 EON contributors

//! Checking an assertion, for a service that trusts an EON Account server
//! (`eon-account-spec/docs/cryptography.md#assertions`). A service learns a
//! pseudonym that is its own and, if the person chose, their username —
//! never an account id, a contact or a session.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::Error;

/// How much clock difference between the account server and a service is forgiven.
pub const LEEWAY_SECS: u64 = 60;

/// The decoded payload (`schemas/assertion.v0.schema.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub v: u32,
    pub iss: String,
    pub aud: String,
    /// The pseudonym: stable for this person at this audience, and different at every other.
    pub sub: String,
    /// The username, present only when the person chose to share it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub iat: u64,
    pub exp: u64,
    pub kid: String,
}

/// One key from an issuer's `GET /v0/keys`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedKey {
    pub kid: String,
    pub alg: String,
    /// The Ed25519 public key, base64url.
    pub public: String,
}

/// An issuer's `GET /v0/keys` answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySet {
    pub issuer: String,
    pub keys: Vec<PublishedKey>,
}

/// Checks `assertion` for `audience` at time `now` (Unix seconds) against an
/// issuer's published keys. Every failure is [`Error::Unauthorised`]; the
/// reason is not the caller's business and not an attacker's either.
pub fn verify(assertion: &str, keys: &KeySet, audience: &str, now: u64) -> Result<Claims, Error> {
    let bad = || Error::Unauthorised;
    let (payload_b64, sig_b64) = assertion.split_once('.').ok_or_else(bad)?;
    let payload = B64.decode(payload_b64).map_err(|_| bad())?;
    let sig: [u8; 64] = B64
        .decode(sig_b64)
        .ok()
        .and_then(|s| s.try_into().ok())
        .ok_or_else(bad)?;
    let claims: Claims = serde_json::from_slice(&payload).map_err(|_| bad())?;
    let key = keys
        .keys
        .iter()
        .find(|k| k.kid == claims.kid && k.alg == "Ed25519")
        .ok_or_else(bad)?;
    let public: [u8; 32] = B64
        .decode(&key.public)
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or_else(bad)?;
    VerifyingKey::from_bytes(&public)
        .map_err(|_| bad())?
        .verify_strict(&payload, &Signature::from_bytes(&sig))
        .map_err(|_| bad())?;
    let fresh = now <= claims.exp.saturating_add(LEEWAY_SECS)
        && claims.iat <= now.saturating_add(LEEWAY_SECS);
    if claims.v != 0 || claims.iss != keys.issuer || claims.aud != audience || !fresh {
        return Err(bad());
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn issue(key: &SigningKey, claims: &Claims) -> String {
        // serde_json's map is ordered, and these values are ASCII strings and
        // integers: the compact form is the JCS form.
        let value = serde_json::to_value(claims).expect("value");
        let payload = serde_json::to_vec(&value).expect("json");
        let sig = key.sign(&payload);
        format!("{}.{}", B64.encode(&payload), B64.encode(sig.to_bytes()))
    }

    fn setup() -> (SigningKey, KeySet, Claims) {
        let key = SigningKey::from_bytes(&[7; 32]);
        let set = KeySet {
            issuer: "https://account.example.org".into(),
            keys: vec![PublishedKey {
                kid: "k1".into(),
                alg: "Ed25519".into(),
                public: B64.encode(key.verifying_key().to_bytes()),
            }],
        };
        let claims = Claims {
            v: 0,
            iss: "https://account.example.org".into(),
            aud: "https://community.example.org".into(),
            sub: "q83vEjRWeJq83vEjRWeJqw".into(),
            name: None,
            iat: 1_000,
            exp: 1_300,
            kid: "k1".into(),
        };
        (key, set, claims)
    }

    #[test]
    fn a_good_assertion_is_accepted_for_its_audience_only() {
        let (key, set, claims) = setup();
        let a = issue(&key, &claims);
        assert_eq!(
            verify(&a, &set, "https://community.example.org", 1_100).expect("ok"),
            claims
        );
        assert!(verify(&a, &set, "https://other.example.org", 1_100).is_err());
    }

    #[test]
    fn expiry_tampering_and_strangers_are_refused() {
        let (key, set, claims) = setup();
        let a = issue(&key, &claims);
        let aud = "https://community.example.org";
        assert!(verify(&a, &set, aud, 1_300 + LEEWAY_SECS).is_ok());
        assert!(verify(&a, &set, aud, 1_301 + LEEWAY_SECS).is_err());
        // A changed payload under the old signature.
        let named = Claims {
            name: Some("someone".into()),
            ..claims.clone()
        };
        let forged = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&named).expect("json")),
            a.split_once('.').expect("dot").1
        );
        assert!(verify(&forged, &set, aud, 1_100).is_err());
        // Signed by a key the issuer does not publish.
        let stranger = SigningKey::from_bytes(&[8; 32]);
        assert!(verify(&issue(&stranger, &claims), &set, aud, 1_100).is_err());
        // Claims to be from another issuer.
        let elsewhere = Claims {
            iss: "https://evil.example".into(),
            ..claims
        };
        assert!(verify(&issue(&key, &elsewhere), &set, aud, 1_100).is_err());
        assert!(verify("not-an-assertion", &set, aud, 1_100).is_err());
    }
}
