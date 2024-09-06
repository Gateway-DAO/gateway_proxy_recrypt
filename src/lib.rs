use log::{info, debug, warn, error};
pub use recrypt::{
    api::{Plaintext, PrivateKey, PublicKey, SigningKeypair, EncryptedValue, TransformKey},
    prelude::*,
};
pub use bincode;
pub use recrypt::api::DefaultRng;
use solana_sdk::signature::{Keypair, Signer};


// Define chunk_size as a constant
const CHUNK_SIZE: usize = 384; // You can set this to any appropriate value

// Function to generate a transform key
pub fn generate_transform_key(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>,
    initial_priv_key: &PrivateKey,
    target_pub_key: &PublicKey,
    signing_keypair: &SigningKeypair,
) -> Result<TransformKey, Box<dyn std::error::Error>> {
    info!("Generating transform key...");
    let transform_key = recrypt.generate_transform_key(
        initial_priv_key,
        target_pub_key,
        signing_keypair,
    )?;
    debug!("Transform Key: {:?}", transform_key);
    debug!("Transform key generated successfully.");
    Ok(transform_key)
}

// Function to transform an encrypted value
pub fn transform_encrypted_value(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>,
    encrypted_value: EncryptedValue,
    transform_key: TransformKey,
    signing_keypair: &SigningKeypair,
) -> Result<EncryptedValue, Box<dyn std::error::Error>> {
    info!("Transforming encrypted value...");
    let transformed_value = recrypt.transform(
        encrypted_value,
        transform_key,
        signing_keypair,
    )?;
    debug!("Encrypted value transformed successfully.");
    Ok(transformed_value)
}

pub fn pad_vec(mut vec: Vec<u8>, size: usize, pad_value: u8) -> Vec<u8> {
    vec.resize(size, pad_value);
    vec
}

pub fn get_symmetric_key(input: &str) -> String {
    input.to_string()
}

pub fn get_serialized_symmetric_key(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    info!("Serializing symmetric key...");
    let symm_key = get_symmetric_key(input);
    let serialized_symm_key = bincode::serialize(&symm_key)?;
    debug!("Symmetric key serialized successfully.");
    Ok(serialized_symm_key)
}

pub fn generate_asymmetric_key(recrypt: &mut Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>) -> Result<(PrivateKey, PublicKey), Box<dyn std::error::Error>> {
    info!("Generating asymmetric key pair...");
    let (priv_key, pub_key) = recrypt.generate_key_pair()?;
    debug!("Asymmetric Public Key: {:?}", pub_key);
    debug!("Asymmetric key pair generated successfully.");
    Ok((priv_key, pub_key))
}

pub fn generate_signing_key(recrypt: &mut Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>) -> SigningKeypair {
    info!("Generating signing keypair...");
    let keypair = recrypt.generate_ed25519_key_pair();
    debug!("Signing Public Key: {:?}", keypair.public_key());
    debug!("Signing keypair generated successfully.");
    keypair
}

pub fn split_and_pad_serialized_data(serialized_data: &[u8]) -> Vec<Plaintext> {
    info!("Splitting and padding serialized data...");
    let chunks: Vec<Plaintext> = serialized_data
        .chunks(CHUNK_SIZE)
        .map(|chunk| {
            let padded_chunk = pad_vec(chunk.to_vec(), CHUNK_SIZE, 0);
            Plaintext::new_from_slice(&padded_chunk).unwrap()
        })
        .collect();
    debug!("Data split and padded into {} chunks.", chunks.len());
    chunks
}

pub fn encrypt_chunk(recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>, plaintext: &Plaintext, public_key: &PublicKey, signing_keypair: &SigningKeypair) -> Result<EncryptedValue, Box<dyn std::error::Error>> {
    info!("Encrypting chunk...");
    let encrypted_val = recrypt.encrypt(plaintext, public_key, signing_keypair)?;
    debug!("Chunk encrypted successfully.");
    Ok(encrypted_val)
}

pub fn decrypt_chunk(recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>, encrypted_val: EncryptedValue, private_key: &PrivateKey) -> Result<Plaintext, Box<dyn std::error::Error>> {
    info!("Decrypting chunk...");
    let decrypted_val = recrypt.decrypt(encrypted_val, private_key)?;
    debug!("Chunk decrypted successfully.");
    Ok(decrypted_val)
}

pub fn encrypt_all_chunks(recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>, chunks: &[Plaintext], public_key: &PublicKey, signing_keypair: &SigningKeypair) -> Result<Vec<EncryptedValue>, Box<dyn std::error::Error>> {
    info!("Encrypting all chunks...");
    let mut encrypted_chunks = Vec::new();
    for pt in chunks {
        let encrypted_val = encrypt_chunk(recrypt, pt, public_key, signing_keypair)?;
        encrypted_chunks.push(encrypted_val);
    }
    debug!("All chunks encrypted successfully.");
    Ok(encrypted_chunks)
}

pub fn decrypt_all_chunks(recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>, encrypted_chunks: &[EncryptedValue], private_key: &PrivateKey) -> Result<Vec<Plaintext>, Box<dyn std::error::Error>> {
    info!("Decrypting all chunks...");
    let mut decrypted_chunks = Vec::new();
    for encrypted_val in encrypted_chunks {
        let decrypted_val = decrypt_chunk(recrypt, encrypted_val.clone(), private_key)?;
        decrypted_chunks.push(decrypted_val);
    }
    debug!("All chunks decrypted successfully.");
    Ok(decrypted_chunks)
}

pub fn encrypt_all_chunks_as_one(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>,
    chunks: &[Plaintext],
    public_key: &PublicKey,
    signing_keypair: &SigningKeypair,
) -> Result<EncryptedValue, Box<dyn std::error::Error>> {
    info!("Encrypting all chunks as one...");
    let mut combined_data = Vec::new();
    for pt in chunks {
        combined_data.extend_from_slice(pt.bytes());
    }

    let combined_plaintext = Plaintext::new_from_slice(&combined_data)?;

    let encrypted_val = recrypt.encrypt(&combined_plaintext, public_key, signing_keypair)?;
    debug!("All chunks encrypted as one successfully.");
    Ok(encrypted_val)
}

pub fn decrypt_all_chunks_as_one(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>,
    encrypted_value: EncryptedValue,
    private_key: &PrivateKey,
) -> Result<Plaintext, Box<dyn std::error::Error>> {
    info!("Decrypting all chunks as one...");
    let decrypted_plaintext = recrypt.decrypt(encrypted_value, private_key)?;
    debug!("All chunks decrypted as one successfully.");
    Ok(decrypted_plaintext)
}

pub fn verify_decryption(decrypted_val: &Plaintext, expected_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    info!("Verifying decryption...");
    let decrypted_bytes = decrypted_val.bytes();
    let deserialized_str: String = bincode::deserialize(decrypted_bytes)?;
    debug!("Decrypted String: {}", deserialized_str);
    debug!("Expected Key: {}", expected_key);
    assert_eq!(expected_key, deserialized_str);
    info!("Decryption verified successfully.");
    Ok(())
}

/// Generates a new Solana key pair.
///
/// # Returns
/// A tuple containing:
/// - `String`: The public key as a base58 encoded string.
/// - `Vec<u8>`: The secret key as a byte array.
pub fn generate_solana_keypair() -> (String, Vec<u8>) {
    // Generate a new keypair
    let keypair = Keypair::new();

    // Get the public key as a base58 string
    let public_key = keypair.pubkey().to_string();

    // Get the secret key as a byte array
    let secret_key = keypair.to_bytes().to_vec();

    (public_key, secret_key)
}