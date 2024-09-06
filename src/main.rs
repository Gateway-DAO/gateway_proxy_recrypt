use std::time::Instant;
use gw_proxy_recrypt::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();

    let mut recrypt = Recrypt::new();

    let signing_keypair = generate_signing_key(&mut recrypt);

    let (initial_priv_key, initial_pub_key) = generate_asymmetric_key(&mut recrypt)?;

    let input = "This is symmtery key";

    let serialized_symm_keys = get_serialized_symmetric_key(input)?;

    let symm_key_chunks = split_and_pad_serialized_data(&serialized_symm_keys);

    let encrypted_value = encrypt_all_chunks_as_one(&recrypt, &symm_key_chunks, &initial_pub_key, &signing_keypair)?;

    let (target_priv_key, target_pub_key) = generate_asymmetric_key(&mut recrypt)?;

    // Generate a transform key
    let initial_to_target_transform_key = generate_transform_key(
        &recrypt,
        &initial_priv_key,
        &target_pub_key,
        &signing_keypair,
    )?;

    // Transform the encrypted value
    let transformed_val = transform_encrypted_value(
        &recrypt,
        encrypted_value,
        initial_to_target_transform_key,
        &signing_keypair,
    )?;

    let decrypted_val = decrypt_all_chunks_as_one(&recrypt, transformed_val, &target_priv_key)?;

    verify_decryption(&decrypted_val,input)?;

    println!("All chunks successfully encrypted and decrypted in {:?}", start.elapsed());

    Ok(())
}