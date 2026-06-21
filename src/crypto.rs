use aes::Aes256;
use cfb8::cipher::{AsyncStreamCipher, KeyIvInit};
use p384::ecdh::diffie_hellman;
use p384::ecdsa::signature::Signer;
use p384::ecdsa::{Signature, SigningKey};
use p384::pkcs8::{DecodePublicKey, EncodePublicKey};
use p384::PublicKey;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::io;

use crate::proto::{b64_decode_any, b64_std, b64_url_no_pad};

type Aes256Cfb8Enc = cfb8::Encryptor<Aes256>;
type Aes256Cfb8Dec = cfb8::Decryptor<Aes256>;

pub struct AuthKey {
    pub signing_key: SigningKey,
    pub public_key_b64: String,
}

impl AuthKey {
    pub fn new() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let public_key_der = signing_key
            .verifying_key()
            .to_public_key_der()
            .expect("P-384 публичный ключ DER кодировка должна сработать");
        Self {
            signing_key,
            public_key_b64: b64_std(public_key_der.as_bytes()),
        }
    }

    pub fn jwt(&self, payload: &str, legacy_standard_segments: bool) -> String {
        let header = format!("{{\"alg\":\"ES384\",\"x5u\":\"{}\"}}", self.public_key_b64);
        let encode = |data: &[u8]| {
            if legacy_standard_segments {
                b64_std(data)
            } else {
                b64_url_no_pad(data)
            }
        };
        let signing_input = format!(
            "{}.{}",
            encode(header.as_bytes()),
            encode(payload.as_bytes())
        );
        let signature: Signature = self.signing_key.sign(signing_input.as_bytes());
        format!("{}.{}", signing_input, encode(&signature.to_bytes()))
    }

    pub fn derive_encryption_key(
        &self,
        server_public_key: &[u8],
        salt: &[u8],
    ) -> io::Result<[u8; 32]> {
        let server_public_key = std::str::from_utf8(server_public_key)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let server_public_der = b64_decode_any(server_public_key.trim()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "серверный ключ не base64",
            )
        })?;
        let server_public = PublicKey::from_public_key_der(&server_public_der)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let shared = diffie_hellman(
            self.signing_key.as_nonzero_scalar(),
            server_public.as_affine(),
        );

        let mut digest = Sha256::new();
        digest.update(salt);
        digest.update(shared.raw_secret_bytes());
        Ok(digest.finalize().into())
    }
}

pub struct EncryptionState {
    key: [u8; 32],
    encrypt_iv: [u8; 16],
    decrypt_iv: [u8; 16],
    send_counter: u64,
    recv_counter: u64,
}

impl EncryptionState {
    pub fn new(key: [u8; 32]) -> io::Result<Self> {
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&key[..16]);
        Ok(Self {
            key,
            encrypt_iv: iv,
            decrypt_iv: iv,
            send_counter: 0,
            recv_counter: 0,
        })
    }

    pub fn encrypt(&mut self, payload: Vec<u8>) -> Vec<u8> {
        let checksum = encryption_checksum(self.send_counter, &payload, &self.key);
        self.send_counter = self.send_counter.wrapping_add(1);
        let mut encrypted = payload;
        encrypted.extend_from_slice(&checksum);
        Aes256Cfb8Enc::new_from_slices(&self.key, &self.encrypt_iv)
            .expect("AES-256-CFB8 ключ и IV фиксированного размера")
            .encrypt(&mut encrypted);
        advance_cfb8_iv(&mut self.encrypt_iv, &encrypted);
        encrypted
    }

    pub fn decrypt(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut decrypted = payload.to_vec();
        let mut next_iv = self.decrypt_iv;
        Aes256Cfb8Dec::new_from_slices(&self.key, &next_iv)
            .expect("AES-256-CFB8 ключ и IV фиксированного размера")
            .decrypt(&mut decrypted);
        advance_cfb8_iv(&mut next_iv, payload);
        if decrypted.len() < 9 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "зашифрованный пакет слишком короткий",
            ));
        }
        let checksum_offset = decrypted.len() - 8;
        let checksum = decrypted.split_off(checksum_offset);
        let expected = encryption_checksum(self.recv_counter, &decrypted, &self.key);
        if checksum != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "контрольная сумма зашифрованного пакета не совпадает",
            ));
        }
        self.recv_counter = self.recv_counter.wrapping_add(1);
        self.decrypt_iv = next_iv;
        Ok(decrypted)
    }
}

fn advance_cfb8_iv(iv: &mut [u8; 16], ciphertext: &[u8]) {
    let len = ciphertext.len();
    let iv_len = iv.len();
    if len >= iv_len {
        iv.copy_from_slice(&ciphertext[len - iv_len..]);
    } else if len > 0 {
        iv.copy_within(len.., 0);
        iv[iv_len - len..].copy_from_slice(ciphertext);
    }
}

fn encryption_checksum(counter: u64, payload: &[u8], key: &[u8; 32]) -> [u8; 8] {
    let mut digest = Sha256::new();
    digest.update(counter.to_le_bytes());
    digest.update(payload);
    digest.update(key);
    let hash = digest.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash[..8]);
    out
}
