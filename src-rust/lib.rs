#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde::{Deserialize, Serialize};
use ed25519_dalek::{SigningKey, Signature, Signer, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use blake3::Hasher;
use subtle::ConstantTimeEq;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

#[napi(object)]
pub struct TokenContext {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

// Core structure for Aegiss token payload serialization
#[derive(Serialize, Deserialize)]
struct AegissPayload {
    pub data: String, // Stringified JSON or any string
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    pub fprint: [u8; 32], // Context fingerprint
}

#[inline(always)]
fn generate_fingerprint(context: &Option<TokenContext>) -> [u8; 32] {
    let mut hasher = Hasher::new();
    if let Some(ctx) = context {
        if let Some(ip) = &ctx.ip {
            hasher.update(ip.as_bytes());
        } else {
            hasher.update(b"0.0.0.0");
        }
        hasher.update(b"|||");
        if let Some(ua) = &ctx.user_agent {
            hasher.update(ua.as_bytes());
        }
    } else {
        hasher.update(b"0.0.0.0|||");
    }
    *hasher.finalize().as_bytes()
}

#[inline(always)]
fn get_current_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// sign(payload: String, secret: String, expiresInSec: u32, context: Context)
#[napi]
pub fn sign(
    payload: String,
    secret_hex: String, // Hex string of 32-byte Ed25519 secret
    expires_in_sec: u32, // Expiration time in seconds
    context: Option<TokenContext>
) -> Result<String> {
    
    let secret_bytes = hex::decode(&secret_hex)
        .map_err(|_| Error::new(Status::InvalidArg, "Invalid Hex secret key"))?;
    
    if secret_bytes.len() != 32 {
        return Err(Error::new(Status::InvalidArg, "Secret key must be exactly 32 bytes for Ed25519"));
    }

    let mut secret_array = [0u8; 32];
    secret_array.copy_from_slice(&secret_bytes);
    let signing_key = SigningKey::from_bytes(&secret_array);

    let fprint = generate_fingerprint(&context);

    let iat = get_current_time();
    let exp = iat + expires_in_sec as u64;
    let jti = uuid::Uuid::new_v4().to_string();

    let token_payload = AegissPayload {
        data: payload,
        iat,
        exp,
        jti,
        fprint,
    };

    let cbor_data = serde_cbor::to_vec(&token_payload)
        .map_err(|e| Error::new(Status::GenericFailure, format!("CBOR serialization failed: {}", e)))?;

    let signature: Signature = signing_key.sign(&cbor_data);

    let encoded_payload = URL_SAFE_NO_PAD.encode(&cbor_data);
    let encoded_signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let final_token = format!("{}.{}", encoded_payload, encoded_signature);
    
    Ok(final_token)
}

/// verify(token: String, public_key: String, context: TokenContext): Stringified Payload
#[napi]
pub fn verify(token: String, public_key_hex: String, context: Option<TokenContext>) -> Result<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 2 {
        return Err(Error::new(Status::InvalidArg, "Invalid token format"));
    }

    // 1. Parse the public key
    let pub_key_bytes = hex::decode(&public_key_hex)
        .map_err(|_| Error::new(Status::InvalidArg, "Invalid Hex public key"))?;
    
    if pub_key_bytes.len() != 32 {
        return Err(Error::new(Status::InvalidArg, "Public key must be exactly 32 bytes for Ed25519"));
    }
    
    let mut pub_key_array = [0u8; 32];
    pub_key_array.copy_from_slice(&pub_key_bytes);
    
    let verifying_key = VerifyingKey::from_bytes(&pub_key_array)
        .map_err(|_| Error::new(Status::InvalidArg, "Public key conversion failed"))?;

    // 2. Decode the Base64 payload and signature
    let decoded_payload = URL_SAFE_NO_PAD.decode(parts[0])
        .map_err(|_| Error::new(Status::InvalidArg, "Invalid payload encoding"))?;
    
    let decoded_signature = URL_SAFE_NO_PAD.decode(parts[1])
        .map_err(|_| Error::new(Status::InvalidArg, "Invalid signature encoding"))?;
    
    if decoded_signature.len() != 64 {
        return Err(Error::new(Status::InvalidArg, "Signature must be 64 bytes"));
    }
    
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&decoded_signature);
    let signature = Signature::from_bytes(&sig_array);

    // 3. Verify the cryptographic signature
    if verifying_key.verify(&decoded_payload, &signature).is_err() {
        return Err(Error::new(Status::GenericFailure, "Invalid Signature"));
    }

    // 4. Decode the CBOR-serialized payload
    let mut payload: AegissPayload = serde_cbor::from_slice(&decoded_payload)
        .map_err(|_| Error::new(Status::GenericFailure, "Failed to decode CBOR Payload"))?;

    // 5. Validate the token expiration time
    let current_time = get_current_time();
    if payload.exp < current_time {
        return Err(Error::new(Status::GenericFailure, "Token Expired"));
    }

    // 6. Perform timing-attack resistant fingerprint validation (Protection against IP/UA spoofing/theft)
    let current_fprint = generate_fingerprint(&context);
    
    let is_fingerprint_valid = current_fprint.ct_eq(&payload.fprint);
    if !bool::from(is_fingerprint_valid) {
        return Err(Error::new(Status::GenericFailure, "Invalid Context Fingerprint"));
    }

    Ok(payload.data)
}

/// decode(token: String): Returns the parsed payload without evaluating the signature (Unsafe)
#[napi]
pub fn decode(token: String) -> Result<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 2 {
        return Err(Error::new(Status::InvalidArg, "Invalid token format"));
    }

    let cbor_data = URL_SAFE_NO_PAD.decode(parts[0])
        .map_err(|_| Error::new(Status::InvalidArg, "Invalid base64 payload"))?;
    
    let payload: AegissPayload = serde_cbor::from_slice(&cbor_data)
        .map_err(|_| Error::new(Status::InvalidArg, "Failed to decode CBOR"))?;

    Ok(payload.data)
}

/// encrypt(payload: String, secret_hex: String) -> String
/// Encrypts data using ChaCha20Poly1305 with a 32-byte hex secret.
#[napi]
pub fn encrypt(payload: String, secret_hex: String) -> Result<String> {
    let secret_bytes = hex::decode(&secret_hex)
        .map_err(|_| Error::new(Status::InvalidArg, "Invalid Hex secret key"))?;
    
    if secret_bytes.len() != 32 {
        return Err(Error::new(Status::InvalidArg, "Secret key must be exactly 32 bytes for ChaCha20Poly1305"));
    }
    
    let key = Key::from_slice(&secret_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, payload.as_bytes())
        .map_err(|_| Error::new(Status::GenericFailure, "Encryption failed"))?;
        
    let encoded_nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
    let encoded_ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
    
    Ok(format!("{}.{}", encoded_nonce, encoded_ciphertext))
}

/// decrypt(encrypted_data: String, secret_hex: String) -> String
/// Decrypts ChaCha20Poly1305 encrypted data using a 32-byte hex secret.
#[napi]
pub fn decrypt(encrypted_data: String, secret_hex: String) -> Result<String> {
    let parts: Vec<&str> = encrypted_data.split('.').collect();
    if parts.len() != 2 {
        return Err(Error::new(Status::InvalidArg, "Invalid encrypted data format"));
    }
    
    let secret_bytes = hex::decode(&secret_hex)
        .map_err(|_| Error::new(Status::InvalidArg, "Invalid Hex secret key"))?;
        
    if secret_bytes.len() != 32 {
        return Err(Error::new(Status::InvalidArg, "Secret key must be exactly 32 bytes"));
    }
    
    let key = Key::from_slice(&secret_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    
    let nonce_bytes = URL_SAFE_NO_PAD.decode(parts[0])
        .map_err(|_| Error::new(Status::InvalidArg, "Invalid nonce encoding"))?;
        
    if nonce_bytes.len() != 12 {
        return Err(Error::new(Status::InvalidArg, "Invalid nonce length"));
    }
    
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = URL_SAFE_NO_PAD.decode(parts[1])
        .map_err(|_| Error::new(Status::InvalidArg, "Invalid ciphertext encoding"))?;
        
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| Error::new(Status::GenericFailure, "Decryption failed or invalid key"))?;
        
    String::from_utf8(plaintext)
        .map_err(|_| Error::new(Status::GenericFailure, "Invalid UTF-8 in decrypted data"))
}
