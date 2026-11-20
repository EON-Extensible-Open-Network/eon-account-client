// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 EON contributors

//! An account on one server, as one application on one device holds it.
//!
//! The folder holds `account.json`: the server address, and — while signed
//! in — the session token and the vault key sealed under a key derived from
//! that token. It is as sensitive as a signed-in browser profile; signing
//! out deletes both. The password and the recovery key are never written.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::crypto::{self, aad, Key, RecoveryKey, Suite};
use crate::wire::{b64, check_server, unb64, Wire};
use crate::{normalise_username, Error, MIN_PASSWORD};

const FILE: &str = "account.json";
/// The longest device name the server keeps.
pub const DEVICE_MAX: usize = 64;

/// `GET /v0/info`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Info {
    pub api: u32,
    pub name: String,
    pub version: String,
    pub registration: String,
    pub contacts: Contacts,
    pub suite: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contacts {
    pub email: bool,
    pub phone: bool,
}

/// An e-mail address or a phone number on the account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Contact {
    #[serde(alias = "address", alias = "number")]
    pub value: String,
    pub verified: bool,
}

/// `GET /v0/me`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Me {
    pub username: String,
    pub created_at: u64,
    pub email: Option<Contact>,
    pub phone: Option<Contact>,
    pub vault: VaultSize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSize {
    pub entries: u64,
    pub bytes: u64,
}

/// One of the account's sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub device: String,
    pub created_at: u64,
    pub last_used: u64,
    pub current: bool,
}

/// One vault entry, as the server sees it: a name, a size and a time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub app: String,
    pub name: String,
    pub version: u64,
    pub size: u64,
    pub updated_at: u64,
}

/// What a vault write did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    Saved(u64),
    /// Someone else wrote first; read, merge and try again.
    Conflict(u64),
}

/// Proof that a code sent to a verified contact was typed back.
#[derive(Debug, Clone)]
pub struct ResetTicket {
    pub token: String,
    pub username: String,
}

#[derive(Default, Clone, Serialize, Deserialize)]
struct Stored {
    server: Option<String>,
    session: Option<StoredSession>,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredSession {
    username: String,
    token: String,
    expires_at: u64,
    /// The vault key, sealed under a key derived from the token.
    device_box: String,
}

#[derive(Deserialize)]
struct SessionReply {
    token: String,
    expires_at: u64,
    username: String,
}

/// The account of one application on this device.
pub struct Account {
    dir: PathBuf,
    state: Mutex<Stored>,
}

fn device(name: &str) -> String {
    name.chars().take(DEVICE_MAX).collect()
}

fn check_password(password: &str) -> Result<(), Error> {
    if password.chars().count() < MIN_PASSWORD {
        return Err(Error::WeakPassword);
    }
    Ok(())
}

fn field<'a>(v: &'a Value, name: &str) -> Result<&'a str, Error> {
    v[name]
        .as_str()
        .ok_or_else(|| Error::Network(format!("the answer has no `{name}`")))
}

fn opaque(e: impl std::fmt::Display) -> Error {
    Error::Protocol(format!("OPAQUE: {e}"))
}

/// The client half of an OPAQUE registration, before the server answered.
struct Registering {
    state: ClientRegistration<Suite>,
    request: String,
}

fn registration_start(password: &str) -> Result<Registering, Error> {
    let start =
        ClientRegistration::<Suite>::start(&mut OsRng, password.as_bytes()).map_err(opaque)?;
    Ok(Registering {
        request: b64(&start.message.serialize()),
        state: start.state,
    })
}

/// Finishes a registration: the record for the server and the password key.
fn registration_finish(
    reg: Registering,
    password: &str,
    response: &str,
) -> Result<(String, Key), Error> {
    let response = RegistrationResponse::<Suite>::deserialize(&unb64(response)?).map_err(opaque)?;
    let ksf = crypto::ksf()?;
    let done = reg
        .state
        .finish(
            &mut OsRng,
            password.as_bytes(),
            response,
            ClientRegistrationFinishParameters::new(Identifiers::default(), Some(&ksf)),
        )
        .map_err(opaque)?;
    Ok((
        b64(&done.message.serialize()),
        crypto::password_key(&done.export_key),
    ))
}

/// A new vault: its key, wrapped twice, and the recovery key that opens one wrap.
fn new_vault(username: &str, password_key: &Key) -> Result<(Key, RecoveryKey, Value), Error> {
    let vault_key = crypto::new_vault_key();
    let recovery = RecoveryKey::generate();
    let vault = json!({
        "password_wrap": b64(&crypto::seal(password_key, &vault_key[..], &aad::wrap_password(username))?),
        "recovery_wrap": b64(&crypto::seal(&crypto::recovery_wrap_key(&recovery), &vault_key[..], &aad::wrap_recovery(username))?),
        "recovery_proof": b64(&crypto::recovery_proof(&recovery)[..]),
    });
    Ok((vault_key, recovery, vault))
}

impl Account {
    /// The account kept in `dir`. Nothing is sent anywhere.
    #[must_use]
    pub fn open(dir: &Path) -> Self {
        let stored = std::fs::read_to_string(dir.join(FILE))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Self {
            dir: dir.to_path_buf(),
            state: Mutex::new(stored),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Stored> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn save(&self, stored: &Stored) -> Result<(), Error> {
        std::fs::create_dir_all(&self.dir).map_err(|e| Error::Io(e.to_string()))?;
        let text = serde_json::to_string_pretty(stored).map_err(|e| Error::Io(e.to_string()))?;
        let tmp = self.dir.join(format!("{FILE}.tmp"));
        std::fs::write(&tmp, text).map_err(|e| Error::Io(e.to_string()))?;
        std::fs::rename(&tmp, self.dir.join(FILE)).map_err(|e| Error::Io(e.to_string()))
    }

    /// The server address, if one has been set.
    #[must_use]
    pub fn server(&self) -> Option<String> {
        self.lock().server.clone()
    }

    /// Sets the server address. A different server ends the current session here.
    pub fn set_server(&self, address: Option<&str>) -> Result<(), Error> {
        let server = address
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .map(check_server)
            .transpose()?;
        let mut st = self.lock();
        if st.server != server {
            st.session = None;
        }
        st.server = server;
        self.save(&st)
    }

    /// Who is signed in here, if anyone.
    #[must_use]
    pub fn username(&self) -> Option<String> {
        self.lock().session.as_ref().map(|s| s.username.clone())
    }

    fn wire(&self) -> Result<Wire, Error> {
        self.lock()
            .server
            .clone()
            .map(Wire::new)
            .ok_or(Error::NoServer)
    }

    fn session(&self) -> Result<StoredSession, Error> {
        self.lock().session.clone().ok_or(Error::NotSignedIn)
    }

    /// A call with the session's token. If the server says the session has
    /// ended, it ends here too.
    fn authed<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<T, Error> {
        let wire = self.wire()?;
        let session = self.session()?;
        let result = wire.call(method, path, Some(&session.token), body);
        if result.as_ref().err() == Some(&Error::Unauthorised) {
            self.forget()?;
        }
        result
    }

    fn vault_key(&self) -> Result<Key, Error> {
        let s = self.session()?;
        let token = unb64(&s.token)?;
        crypto::open_key(
            &crypto::device_key(&token),
            &unb64(&s.device_box)?,
            aad::DEVICE,
        )
    }

    fn begin(&self, reply: SessionReply, vault_key: &Key) -> Result<(), Error> {
        let token = unb64(&reply.token)?;
        let device_box = crypto::seal(&crypto::device_key(&token), &vault_key[..], aad::DEVICE)?;
        let mut st = self.lock();
        st.session = Some(StoredSession {
            username: reply.username,
            token: reply.token,
            expires_at: reply.expires_at,
            device_box: b64(&device_box),
        });
        self.save(&st)
    }

    /// Ends the session on this device without asking the server.
    pub fn forget(&self) -> Result<(), Error> {
        let mut st = self.lock();
        st.session = None;
        self.save(&st)
    }

    pub fn info(&self) -> Result<Info, Error> {
        self.wire()?.call("GET", "/v0/info", None, None)
    }

    /// The server's own list of what it keeps (`docs/transparency.md`).
    pub fn transparency(&self) -> Result<Value, Error> {
        self.wire()?.call("GET", "/v0/transparency", None, None)
    }

    /// Creates an account and signs in. The recovery key is returned once and
    /// is never stored: the application must show it and let it go.
    pub fn register(
        &self,
        username: &str,
        password: &str,
        device_name: &str,
    ) -> Result<RecoveryKey, Error> {
        let username = normalise_username(username)?;
        check_password(password)?;
        let wire = self.wire()?;
        let reg = registration_start(password)?;
        let answer: Value = wire.call(
            "POST",
            "/v0/register/start",
            None,
            Some(&json!({"username": username, "request": reg.request})),
        )?;
        let (record, password_key) =
            registration_finish(reg, password, field(&answer, "response")?)?;
        let (vault_key, recovery, vault) = new_vault(&username, &password_key)?;
        let reply: SessionReply = wire.call(
            "POST",
            "/v0/register/finish",
            None,
            Some(&json!({"username": username, "record": record, "vault": vault, "device": device(device_name)})),
        )?;
        self.begin(reply, &vault_key)?;
        Ok(recovery)
    }

    /// Signs in with a username or a verified e-mail address.
    pub fn login(&self, login: &str, password: &str, device_name: &str) -> Result<(), Error> {
        let login = login.trim().to_lowercase();
        let wire = self.wire()?;
        let start = ClientLogin::<Suite>::start(&mut OsRng, password.as_bytes()).map_err(opaque)?;
        let answer: Value = wire.call(
            "POST",
            "/v0/login/start",
            None,
            Some(&json!({"login": login, "request": b64(&start.message.serialize())})),
        )?;
        let response =
            CredentialResponse::<Suite>::deserialize(&unb64(field(&answer, "response")?)?)
                .map_err(opaque)?;
        let ksf = crypto::ksf()?;
        // A wrong password (or an unknown login) fails here, on this device:
        // OPAQUE's envelope does not open.
        let done = start
            .state
            .finish(
                &mut OsRng,
                password.as_bytes(),
                response,
                ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf)),
            )
            .map_err(|_| Error::Unauthorised)?;
        let reply: Value = wire.call(
            "POST",
            "/v0/login/finish",
            None,
            Some(&json!({
                "login_id": field(&answer, "login_id")?,
                "finalization": b64(&done.message.serialize()),
                "device": device(device_name),
            })),
        )?;
        let session: SessionReply =
            serde_json::from_value(reply.clone()).map_err(|e| Error::Network(e.to_string()))?;
        let wrap = unb64(reply["vault"]["password_wrap"].as_str().unwrap_or(""))?;
        let vault_key = crypto::open_key(
            &crypto::password_key(&done.export_key),
            &wrap,
            &aad::wrap_password(&session.username),
        )?;
        self.begin(session, &vault_key)
    }

    /// Ends the session, on the server if it can be reached and here always.
    pub fn logout(&self) -> Result<(), Error> {
        let sent = match (self.wire(), self.session()) {
            (Ok(w), Ok(s)) => w
                .raw("POST", "/v0/logout", Some(&s.token), None)
                .map(|_| ()),
            _ => Ok(()),
        };
        self.forget()?;
        match sent {
            Ok(()) | Err(Error::Network(_) | Error::Unauthorised) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn me(&self) -> Result<Me, Error> {
        self.authed("GET", "/v0/me", None)
    }

    pub fn sessions(&self) -> Result<Vec<Session>, Error> {
        let v: Value = self.authed("GET", "/v0/me/sessions", None)?;
        serde_json::from_value(v["sessions"].clone()).map_err(|e| Error::Network(e.to_string()))
    }

    pub fn end_session(&self, id: &str) -> Result<(), Error> {
        self.authed::<Value>("DELETE", &format!("/v0/me/sessions/{id}"), None)
            .map(|_| ())
    }

    /// A new password; the vault keeps its contents. Other sessions end.
    pub fn change_password(&self, new_password: &str) -> Result<(), Error> {
        check_password(new_password)?;
        let username = self.session()?.username;
        let vault_key = self.vault_key()?;
        let reg = registration_start(new_password)?;
        let answer: Value = self.authed(
            "POST",
            "/v0/me/password/start",
            Some(&json!({"request": reg.request})),
        )?;
        let (record, password_key) =
            registration_finish(reg, new_password, field(&answer, "response")?)?;
        let wrap = crypto::seal(
            &password_key,
            &vault_key[..],
            &aad::wrap_password(&username),
        )?;
        self.authed::<Value>(
            "POST",
            "/v0/me/password/finish",
            Some(&json!({"record": record, "password_wrap": b64(&wrap)})),
        )
        .map(|_| ())
    }

    /// A new password with the recovery key; the vault keeps its contents.
    pub fn recover_with_key(
        &self,
        username: &str,
        recovery: &str,
        new_password: &str,
        device_name: &str,
    ) -> Result<(), Error> {
        let username = normalise_username(username)?;
        let recovery = RecoveryKey::parse(recovery)?;
        check_password(new_password)?;
        let wire = self.wire()?;
        let proof = b64(&crypto::recovery_proof(&recovery)[..]);
        let reg = registration_start(new_password)?;
        let answer: Value = wire.call(
            "POST",
            "/v0/recover/start",
            None,
            Some(&json!({"username": username, "proof": proof, "request": reg.request})),
        )?;
        let vault_key = crypto::open_key(
            &crypto::recovery_wrap_key(&recovery),
            &unb64(field(&answer, "recovery_wrap")?)?,
            &aad::wrap_recovery(&username),
        )?;
        let (record, password_key) =
            registration_finish(reg, new_password, field(&answer, "response")?)?;
        let wrap = crypto::seal(
            &password_key,
            &vault_key[..],
            &aad::wrap_password(&username),
        )?;
        let reply: SessionReply = wire.call(
            "POST",
            "/v0/recover/finish",
            None,
            Some(
                &json!({"username": username, "proof": proof, "record": record,
                         "password_wrap": b64(&wrap), "device": device(device_name)}),
            ),
        )?;
        self.begin(reply, &vault_key)
    }

    /// Asks for a code at a verified e-mail address or phone number. The
    /// answer is the same whether or not the contact belongs to an account.
    pub fn reset_request(&self, contact: &str) -> Result<(), Error> {
        self.wire()?
            .raw(
                "POST",
                "/v0/reset/request",
                None,
                Some(&json!({"contact": contact.trim()})),
            )
            .map(|_| ())
    }

    pub fn reset_verify(&self, contact: &str, code: &str) -> Result<ResetTicket, Error> {
        let v: Value = self.wire()?.call(
            "POST",
            "/v0/reset/verify",
            None,
            Some(&json!({"contact": contact.trim(), "code": code.trim()})),
        )?;
        Ok(ResetTicket {
            token: field(&v, "reset_token")?.to_owned(),
            username: field(&v, "username")?.to_owned(),
        })
    }

    /// A new password after a code: the old vault cannot be opened, so a new,
    /// empty one begins, with a new recovery key.
    pub fn reset_with_ticket(
        &self,
        ticket: &ResetTicket,
        new_password: &str,
        device_name: &str,
    ) -> Result<RecoveryKey, Error> {
        check_password(new_password)?;
        let wire = self.wire()?;
        let reg = registration_start(new_password)?;
        let answer: Value = wire.call(
            "POST",
            "/v0/reset/start",
            None,
            Some(&json!({"reset_token": ticket.token, "request": reg.request})),
        )?;
        let (record, password_key) =
            registration_finish(reg, new_password, field(&answer, "response")?)?;
        let (vault_key, recovery, vault) = new_vault(&ticket.username, &password_key)?;
        let reply: SessionReply = wire.call(
            "POST",
            "/v0/reset/finish",
            None,
            Some(
                &json!({"reset_token": ticket.token, "record": record, "vault": vault,
                         "device": device(device_name)}),
            ),
        )?;
        self.begin(reply, &vault_key)?;
        Ok(recovery)
    }

    /// Adds (or replaces) the e-mail address; a code is sent to it.
    pub fn set_email(&self, address: &str) -> Result<(), Error> {
        self.authed::<Value>(
            "PUT",
            "/v0/me/email",
            Some(&json!({"address": address.trim()})),
        )
        .map(|_| ())
    }

    pub fn verify_email(&self, code: &str) -> Result<(), Error> {
        self.authed::<Value>(
            "POST",
            "/v0/me/email/verify",
            Some(&json!({"code": code.trim()})),
        )
        .map(|_| ())
    }

    pub fn remove_email(&self) -> Result<(), Error> {
        self.authed::<Value>("DELETE", "/v0/me/email", None)
            .map(|_| ())
    }

    /// Adds (or replaces) the phone number, in E.164 form; a code is sent to it.
    pub fn set_phone(&self, number: &str) -> Result<(), Error> {
        self.authed::<Value>(
            "PUT",
            "/v0/me/phone",
            Some(&json!({"number": number.trim()})),
        )
        .map(|_| ())
    }

    pub fn verify_phone(&self, code: &str) -> Result<(), Error> {
        self.authed::<Value>(
            "POST",
            "/v0/me/phone/verify",
            Some(&json!({"code": code.trim()})),
        )
        .map(|_| ())
    }

    pub fn remove_phone(&self) -> Result<(), Error> {
        self.authed::<Value>("DELETE", "/v0/me/phone", None)
            .map(|_| ())
    }

    pub fn vault_list(&self) -> Result<Vec<VaultEntry>, Error> {
        let v: Value = self.authed("GET", "/v0/vault", None)?;
        serde_json::from_value(v["entries"].clone()).map_err(|e| Error::Network(e.to_string()))
    }

    /// An entry's version and decrypted contents, if it exists.
    pub fn vault_get(&self, app: &str, name: &str) -> Result<Option<(u64, Vec<u8>)>, Error> {
        let username = self.session()?.username;
        let v: Value = match self.authed("GET", &format!("/v0/vault/{app}/{name}"), None) {
            Ok(v) => v,
            Err(Error::NotFound) => return Ok(None),
            Err(e) => return Err(e),
        };
        let version = v["version"]
            .as_u64()
            .ok_or_else(|| Error::Network("the answer has no `version`".into()))?;
        let key = self.vault_key()?;
        let plain = crypto::open(
            &key,
            &unb64(field(&v, "data")?)?,
            &aad::vault(&username, app, name),
        )?;
        Ok(Some((version, crypto::unpad(&plain)?)))
    }

    /// Writes an entry if nobody else has since `base_version` (0: a new entry).
    pub fn vault_put(
        &self,
        app: &str,
        name: &str,
        base_version: u64,
        data: &[u8],
    ) -> Result<PutOutcome, Error> {
        let username = self.session()?.username;
        let key = self.vault_key()?;
        let padded: Zeroizing<Vec<u8>> = crypto::pad(data)?;
        let sealed = crypto::seal(&key, &padded, &aad::vault(&username, app, name))?;
        let body = json!({"base_version": base_version, "data": b64(&sealed)});
        match self.authed::<Value>("PUT", &format!("/v0/vault/{app}/{name}"), Some(&body)) {
            Ok(v) => Ok(PutOutcome::Saved(v["version"].as_u64().unwrap_or(0))),
            Err(Error::Conflict(now)) => Ok(PutOutcome::Conflict(now)),
            Err(e) => Err(e),
        }
    }

    /// Brings an entry and `local` together: reads it, merges with `merge(local,
    /// remote)`, writes the result if it differs, and retries if someone wrote
    /// in between. Returns what is now in the vault.
    pub fn vault_sync(
        &self,
        app: &str,
        name: &str,
        local: &[u8],
        merge: impl Fn(&[u8], &[u8]) -> Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let mut last = 0;
        for _ in 0..4 {
            let (base, merged) = match self.vault_get(app, name)? {
                None => (0, local.to_vec()),
                Some((version, remote)) => {
                    let merged = merge(local, &remote);
                    if merged == remote {
                        return Ok(remote);
                    }
                    (version, merged)
                }
            };
            match self.vault_put(app, name, base, &merged)? {
                PutOutcome::Saved(_) => return Ok(merged),
                PutOutcome::Conflict(now) => last = now,
            }
        }
        Err(Error::Conflict(last))
    }

    pub fn vault_delete(&self, app: &str, name: &str) -> Result<(), Error> {
        self.authed::<Value>("DELETE", &format!("/v0/vault/{app}/{name}"), None)
            .map(|_| ())
    }

    /// A five-minute assertion for another service (`audience` is its origin).
    pub fn assertion(&self, audience: &str, share_username: bool) -> Result<String, Error> {
        let v: Value = self.authed(
            "POST",
            "/v0/assertions",
            Some(&json!({"audience": audience, "share_username": share_username})),
        )?;
        Ok(field(&v, "assertion")?.to_owned())
    }

    /// Everything the server holds about the account.
    pub fn export(&self) -> Result<Value, Error> {
        self.authed("GET", "/v0/me/export", None)
    }

    /// Deletes the account on the server, and the session here.
    pub fn delete_account(&self) -> Result<(), Error> {
        self.authed::<Value>("DELETE", "/v0/me", None)?;
        self.forget()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_ke::{ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup};

    /// The whole OPAQUE exchange against an in-process server half: the
    /// export key at sign-in equals the one at sign-up, so the wrapped vault
    /// key opens; a wrong password fails on the client.
    #[test]
    fn sign_up_then_sign_in_opens_the_same_vault() {
        let setup = ServerSetup::<Suite>::new(&mut OsRng);
        let id = crypto::credential_identifier("deniz");
        let reg = registration_start("a long enough password").expect("start");
        let req = opaque_ke::RegistrationRequest::<Suite>::deserialize(
            &unb64(&reg.request).expect("b64"),
        )
        .expect("request");
        let resp = ServerRegistration::<Suite>::start(&setup, req, &id).expect("server start");
        let (record, password_key) = registration_finish(
            reg,
            "a long enough password",
            &b64(&resp.message.serialize()),
        )
        .expect("finish");
        let (vault_key, recovery, vault) = new_vault("deniz", &password_key).expect("vault");
        let file = ServerRegistration::finish(
            opaque_ke::RegistrationUpload::<Suite>::deserialize(&unb64(&record).expect("b64"))
                .expect("upload"),
        );

        let attempt = |password: &str| -> Result<Key, Error> {
            let start =
                ClientLogin::<Suite>::start(&mut OsRng, password.as_bytes()).map_err(opaque)?;
            let server = ServerLogin::start(
                &mut OsRng,
                &setup,
                Some(file.clone()),
                start.message,
                &id,
                ServerLoginParameters::default(),
            )
            .map_err(opaque)?;
            let ksf = crypto::ksf()?;
            let done = start
                .state
                .finish(
                    &mut OsRng,
                    password.as_bytes(),
                    server.message,
                    ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf)),
                )
                .map_err(|_| Error::Unauthorised)?;
            server
                .state
                .finish(done.message, ServerLoginParameters::default())
                .map_err(opaque)?;
            Ok(crypto::password_key(&done.export_key))
        };
        let again = attempt("a long enough password").expect("sign in");
        let wrap = unb64(vault["password_wrap"].as_str().expect("wrap")).expect("b64");
        let opened = crypto::open_key(&again, &wrap, &aad::wrap_password("deniz")).expect("open");
        assert_eq!(*opened, *vault_key);
        assert_eq!(
            attempt("the wrong password!").err(),
            Some(Error::Unauthorised)
        );

        // The recovery key opens the other wrap, and its proof is what the server hashes.
        let rwrap = unb64(vault["recovery_wrap"].as_str().expect("wrap")).expect("b64");
        let by_recovery = crypto::open_key(
            &crypto::recovery_wrap_key(&RecoveryKey::parse(&recovery.display()).expect("parse")),
            &rwrap,
            &aad::wrap_recovery("deniz"),
        )
        .expect("open");
        assert_eq!(*by_recovery, *vault_key);
        // Under another username the same wrap does not open.
        assert!(crypto::open_key(&again, &wrap, &aad::wrap_password("someone")).is_err());
    }

    #[test]
    fn nothing_is_sent_without_a_server_or_a_session() {
        let dir = std::env::temp_dir().join(format!("eon-account-client-{}", std::process::id()));
        let account = Account::open(&dir);
        assert_eq!(account.info().err(), Some(Error::NoServer));
        assert_eq!(
            account
                .register("deniz", "a long enough password", "test")
                .err(),
            Some(Error::NoServer)
        );
        account
            .set_server(Some("http://127.0.0.1:9"))
            .expect("server");
        assert_eq!(account.me().err(), Some(Error::NotSignedIn));
        assert_eq!(
            account.register("deniz", "short", "test").err(),
            Some(Error::WeakPassword)
        );
        assert!(account.set_server(Some("http://example.org")).is_err());
        assert_eq!(
            Account::open(&dir).server().as_deref(),
            Some("http://127.0.0.1:9")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
