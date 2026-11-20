// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 EON contributors

//! The cryptography of `eon-account-spec/docs/cryptography.md`, suite
//! `opaque-3dh-ristretto255-sha512-argon2id-v0`. Every constant here is part
//! of the contract: changing one is a new suite, not an edit.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::Error;

/// The name `GET /v0/info` gives this suite.
pub const SUITE: &str = "opaque-3dh-ristretto255-sha512-argon2id-v0";

/// The OPAQUE cipher suite.
pub struct Suite;

impl opaque_ke::CipherSuite for Suite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

/// Argon2id, m = 64 MiB, t = 3, p = 1: the suite's key stretching, on the client.
pub fn ksf() -> Result<Argon2<'static>, Error> {
    let params = Params::new(65_536, 3, 1, None)
        .map_err(|e| Error::Protocol(format!("argon2 parameters: {e}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// The credential identifier OPAQUE binds an account's record to.
#[must_use]
pub fn credential_identifier(username: &str) -> Vec<u8> {
    format!("u:{username}").into_bytes()
}

/// A 32-byte key that is wiped when dropped.
pub type Key = Zeroizing<[u8; 32]>;

fn hkdf(ikm: &[u8], info: &str) -> Key {
    let mut out = Zeroizing::new([0u8; 32]);
    // 32 bytes is far below HKDF-SHA256's limit of 8160, so expand cannot fail.
    let _ = Hkdf::<Sha256>::new(None, ikm).expand(info.as_bytes(), out.as_mut());
    out
}

/// The key that wraps the vault key under the password.
#[must_use]
pub fn password_key(export_key: &[u8]) -> Key {
    hkdf(export_key, "eon-account v0 password key")
}

/// The key that wraps the vault key under the recovery key.
#[must_use]
pub fn recovery_wrap_key(recovery: &RecoveryKey) -> Key {
    hkdf(&recovery.0[..], "eon-account v0 recovery key")
}

/// What proves knowledge of the recovery key to the server.
#[must_use]
pub fn recovery_proof(recovery: &RecoveryKey) -> Key {
    hkdf(&recovery.0[..], "eon-account v0 recovery proof")
}

/// The key that keeps the vault key on this device for a session.
#[must_use]
pub fn device_key(token: &[u8]) -> Key {
    hkdf(token, "eon-account v0 device key")
}

/// A fresh random vault key.
#[must_use]
pub fn new_vault_key() -> Key {
    let mut k = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(k.as_mut());
    k
}

/// The associated data of each kind of box.
pub mod aad {
    #[must_use]
    pub fn wrap_password(username: &str) -> Vec<u8> {
        format!("eon-account v0 wrap password {username}").into_bytes()
    }
    #[must_use]
    pub fn wrap_recovery(username: &str) -> Vec<u8> {
        format!("eon-account v0 wrap recovery {username}").into_bytes()
    }
    #[must_use]
    pub fn vault(username: &str, app: &str, name: &str) -> Vec<u8> {
        format!("eon-account v0 vault {username} {app}/{name}").into_bytes()
    }
    pub const DEVICE: &[u8] = b"eon-account v0 device";
}

const BOX_VERSION: u8 = 1;
const NONCE: usize = 24;
const TAG: usize = 16;

/// `0x01 ‖ nonce ‖ XChaCha20-Poly1305(key, nonce, plaintext, aad)`.
pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; NONCE];
    OsRng.fill_bytes(&mut nonce);
    let sealed = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Protocol("sealing failed".into()))?;
    let mut out = Vec::with_capacity(1 + NONCE + sealed.len());
    out.push(BOX_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Opens a box made by [`seal`]; fails if the key, the associated data or a
/// single byte differs.
pub fn open(key: &[u8; 32], sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if sealed.len() < 1 + NONCE + TAG || sealed[0] != BOX_VERSION {
        return Err(Error::Protocol("not a sealed box".into()));
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(&sealed[1..=NONCE]),
            Payload {
                msg: &sealed[1 + NONCE..],
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Protocol("a sealed box did not open".into()))
}

/// Opens a box that holds a 32-byte key.
pub fn open_key(key: &[u8; 32], sealed: &[u8], aad: &[u8]) -> Result<Key, Error> {
    let plain = open(key, sealed, aad)?;
    let mut k = Zeroizing::new([0u8; 32]);
    if plain.len() != 32 {
        return Err(Error::Protocol("a wrapped key has the wrong length".into()));
    }
    k.copy_from_slice(&plain);
    Ok(k)
}

const PAD: usize = 4096;

/// `length (4 bytes, big-endian) ‖ data ‖ zeros` up to a multiple of 4096.
pub fn pad(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let len = u32::try_from(data.len()).map_err(|_| Error::TooLarge)?;
    let total = (4 + data.len()).div_ceil(PAD) * PAD;
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    out.resize(total, 0);
    Ok(out)
}

/// The data inside a padded plaintext.
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>, Error> {
    let prefix: [u8; 4] = padded
        .get(..4)
        .and_then(|p| p.try_into().ok())
        .ok_or_else(|| Error::Protocol("a vault entry is too short".into()))?;
    let len = u32::from_be_bytes(prefix) as usize;
    padded
        .get(4..4 + len)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| Error::Protocol("a vault entry's length is wrong".into()))
}

/// SHA-256, for comparing secrets by their hash.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// The recovery key: 20 random bytes, shown once as 32 base32 characters.
pub struct RecoveryKey(Zeroizing<[u8; 20]>);

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

impl RecoveryKey {
    #[must_use]
    pub fn generate() -> Self {
        let mut k = Zeroizing::new([0u8; 20]);
        OsRng.fill_bytes(k.as_mut());
        Self(k)
    }

    /// Reads what a person typed: hyphens and spaces ignored, either case.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut bits: u64 = 0;
        let mut have = 0u32;
        let mut out = Zeroizing::new([0u8; 20]);
        let mut n = 0usize;
        for c in text.chars().filter(|c| !matches!(c, '-' | ' ')) {
            let up = c.to_ascii_uppercase();
            let value = B32
                .iter()
                .position(|&b| char::from(b) == up)
                .ok_or(Error::BadRecoveryKey)?;
            bits = (bits << 5) | value as u64;
            have += 5;
            if have >= 8 {
                have -= 8;
                if n == 20 {
                    return Err(Error::BadRecoveryKey);
                }
                out[n] = u8::try_from((bits >> have) & 0xff).unwrap_or(0);
                n += 1;
            }
        }
        bits.zeroize();
        if n == 20 && have == 0 {
            Ok(Self(out))
        } else {
            Err(Error::BadRecoveryKey)
        }
    }

    /// `ABCD-EFGH-…`, eight groups of four.
    #[must_use]
    pub fn display(&self) -> String {
        let mut plain = String::with_capacity(32);
        let mut bits: u64 = 0;
        let mut have = 0u32;
        for &byte in self.0.iter() {
            bits = (bits << 8) | u64::from(byte);
            have += 8;
            while have >= 5 {
                have -= 5;
                plain.push(char::from(B32[((bits >> have) & 31) as usize]));
            }
        }
        let groups: Vec<&str> = (0..8).map(|i| &plain[i * 4..i * 4 + 4]).collect();
        groups.join("-")
    }
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey(…)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_box_opens_only_with_its_key_and_its_label() {
        let key = new_vault_key();
        let other = new_vault_key();
        let sealed = seal(&key, b"progress", b"label").expect("seal");
        assert_eq!(
            &open(&key, &sealed, b"label").expect("open")[..],
            b"progress"
        );
        assert!(open(&other, &sealed, b"label").is_err());
        assert!(open(&key, &sealed, b"another label").is_err());
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(open(&key, &tampered, b"label").is_err());
        assert_ne!(
            seal(&key, b"progress", b"label").expect("seal"),
            sealed,
            "a fresh nonce every time"
        );
    }

    #[test]
    fn padding_hides_the_length_and_comes_off_cleanly() {
        for data in [&b""[..], b"{}", &[0u8; 5000][..], &[7u8; 4092][..]] {
            let padded = pad(data).expect("pad");
            assert_eq!(padded.len() % 4096, 0);
            assert_eq!(unpad(&padded).expect("unpad"), data);
        }
        assert_eq!(pad(&[1u8; 4092]).expect("pad").len(), 4096);
        assert_eq!(pad(&[1u8; 4093]).expect("pad").len(), 8192);
        assert!(unpad(&[0, 0, 0, 9, 1]).is_err());
    }

    #[test]
    fn the_recovery_key_reads_back_however_it_is_typed() {
        let k = RecoveryKey::generate();
        let shown = k.display();
        assert_eq!(shown.len(), 39);
        assert_eq!(shown.matches('-').count(), 7);
        for typed in [
            shown.clone(),
            shown.to_lowercase(),
            shown.replace('-', ""),
            shown.replace('-', " "),
        ] {
            let back = RecoveryKey::parse(&typed).expect("parse");
            assert_eq!(*back.0, *k.0);
        }
        assert!(RecoveryKey::parse("ABCD").is_err());
        assert!(RecoveryKey::parse(&shown.replace('A', "1")).is_err() || !shown.contains('A'));
        assert!(RecoveryKey::parse(&format!("{shown}-AAAA")).is_err());
        assert_eq!(
            format!("{k:?}"),
            "RecoveryKey(…)",
            "never printed by accident"
        );
    }

    #[test]
    fn derived_keys_are_separate() {
        let k = RecoveryKey::generate();
        assert_ne!(*recovery_wrap_key(&k), *recovery_proof(&k));
        assert_ne!(*password_key(&[1; 64]), *device_key(&[1; 64]));
    }
}
