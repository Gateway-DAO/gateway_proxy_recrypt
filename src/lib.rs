pub use recrypt::{
    api::{Plaintext, PrivateKey, PublicKey, SigningKeypair, EncryptedValue, TransformKey},
    prelude::*,
};
pub use bincode;
pub use recrypt::api::DefaultRng;

// Define chunk_size as a constant
const CHUNK_SIZE: usize = 384; // You can set this to any appropriate value

// Function to generate a transform key
pub fn generate_transform_key(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>,
    initial_priv_key: &PrivateKey,
    target_pub_key: &PublicKey,
    signing_keypair: &SigningKeypair,
) -> Result<TransformKey, Box<dyn std::error::Error>> {
    let transform_key = recrypt.generate_transform_key(
        initial_priv_key,
        target_pub_key,
        signing_keypair,
    )?;
    Ok(transform_key)
}

// Function to transform an encrypted value
pub fn transform_encrypted_value(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>,
    encrypted_value: EncryptedValue,
    transform_key: TransformKey,
    signing_keypair: &SigningKeypair,
) -> Result<EncryptedValue, Box<dyn std::error::Error>> {
    let transformed_value = recrypt.transform(
        encrypted_value,
        transform_key,
        signing_keypair,
    )?;
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
    let symm_key = get_symmetric_key(input);
    let serialized_symm_key = bincode::serialize(&symm_key)?;
    Ok(serialized_symm_key)
}

pub fn generate_asymmetric_key(recrypt: &mut Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>) -> Result<(PrivateKey, PublicKey), Box<dyn std::error::Error>> {
    let (priv_key, pub_key) = recrypt.generate_key_pair()?;
    Ok((priv_key, pub_key))
}

pub fn generate_signing_key(recrypt: &mut Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>) -> SigningKeypair {
    recrypt.generate_ed25519_key_pair()
}

pub fn split_and_pad_serialized_data(serialized_data: &[u8]) -> Vec<Plaintext> {
    serialized_data
        .chunks(CHUNK_SIZE)
        .map(|chunk| {
            let padded_chunk = pad_vec(chunk.to_vec(), CHUNK_SIZE, 0);
            Plaintext::new_from_slice(&padded_chunk).unwrap()
        })
        .collect()
}

pub fn encrypt_chunk(recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>, plaintext: &Plaintext, public_key: &PublicKey, signing_keypair: &SigningKeypair) -> Result<EncryptedValue, Box<dyn std::error::Error>> {
    let encrypted_val = recrypt.encrypt(plaintext, public_key, signing_keypair)?;
    Ok(encrypted_val)
}

pub fn decrypt_chunk(recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>, encrypted_val: EncryptedValue, private_key: &PrivateKey) -> Result<Plaintext, Box<dyn std::error::Error>> {
    let decrypted_val = recrypt.decrypt(encrypted_val, private_key)?;
    Ok(decrypted_val)
}

pub fn encrypt_all_chunks(recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>, chunks: &[Plaintext], public_key: &PublicKey, signing_keypair: &SigningKeypair) -> Result<Vec<EncryptedValue>, Box<dyn std::error::Error>> {
    let mut encrypted_chunks = Vec::new();
    for pt in chunks {
        let encrypted_val = encrypt_chunk(recrypt, pt, public_key, signing_keypair)?;
        encrypted_chunks.push(encrypted_val);
    }
    Ok(encrypted_chunks)
}

pub fn decrypt_all_chunks(recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>, encrypted_chunks: &[EncryptedValue], private_key: &PrivateKey) -> Result<Vec<Plaintext>, Box<dyn std::error::Error>> {
    let mut decrypted_chunks = Vec::new();
    for encrypted_val in encrypted_chunks {
        let decrypted_val = decrypt_chunk(recrypt, encrypted_val.clone(), private_key)?;
        decrypted_chunks.push(decrypted_val);
    }
    Ok(decrypted_chunks)
}

pub fn encrypt_all_chunks_as_one(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>,
    chunks: &[Plaintext],
    public_key: &PublicKey,
    signing_keypair: &SigningKeypair,
) -> Result<EncryptedValue, Box<dyn std::error::Error>> {
    let mut combined_data = Vec::new();
    for pt in chunks {
        combined_data.extend_from_slice(pt.bytes());
    }

    let combined_plaintext = Plaintext::new_from_slice(&combined_data)?;

    let encrypted_val = recrypt.encrypt(&combined_plaintext, public_key, signing_keypair)?;
    Ok(encrypted_val)
}

pub fn decrypt_all_chunks_as_one(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>,
    encrypted_value: EncryptedValue,
    private_key: &PrivateKey,
) -> Result<Plaintext, Box<dyn std::error::Error>> {
    let decrypted_plaintext = recrypt.decrypt(encrypted_value, private_key)?;
    Ok(decrypted_plaintext)
}

pub fn verify_decryption(decrypted_val: &Plaintext, expected_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let decrypted_bytes = decrypted_val.bytes();
    let deserialized_str: String = bincode::deserialize(decrypted_bytes)?;
    // Print the parameters before the assertion
    println!("Decrypted String: {}", deserialized_str);
    println!("Expected Key: {}", expected_key);
    assert_eq!(expected_key, deserialized_str);
    Ok(())
}