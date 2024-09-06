use std::time::Instant;
use gw_proxy_recrypt::*;
use log::{debug, error, info, warn};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let start = Instant::now();
    info!("Program started for PRE.");

    let mut recrypt = Recrypt::new();
    debug!("Recrypt object created.");

    let signing_keypair = generate_signing_key(&mut recrypt);
    debug!("Signing keypair generated.");

    let (initial_priv_key, initial_pub_key) = generate_asymmetric_key(&mut recrypt)?;
    debug!("Initial asymmetric key pair generated.");

    let input = "This is symmtery key";
    info!("Input symmetric key: {}", input);

    let serialized_symm_keys = get_serialized_symmetric_key(input)?;
    debug!("Serialized symmetric key obtained.");

    let symm_key_chunks = split_and_pad_serialized_data(&serialized_symm_keys);
    debug!("Symmetric key chunks split and padded.");

    let encrypted_value = encrypt_all_chunks_as_one(&recrypt, &symm_key_chunks, &initial_pub_key, &signing_keypair)?;
    info!("Symmetric key chunks encrypted.");

    let (target_priv_key, target_pub_key) = generate_asymmetric_key(&mut recrypt)?;
    debug!("Target asymmetric key pair generated.");

    // Generate a transform key
    let initial_to_target_transform_key = generate_transform_key(
        &recrypt,
        &initial_priv_key,
        &target_pub_key,
        &signing_keypair,
    )?;
    info!("Transform key generated from initial to target key.");

    // Transform the encrypted value
    let transformed_val = transform_encrypted_value(
        &recrypt,
        encrypted_value,
        initial_to_target_transform_key,
        &signing_keypair,
    )?;
    info!("Encrypted value transformed.");

    let decrypted_val = decrypt_all_chunks_as_one(&recrypt, transformed_val, &target_priv_key)?;
    info!("Transformed value decrypted.");

    verify_decryption(&decrypted_val, input)?;
    info!("Decryption verified successfully.");

  //  println!("All chunks successfully encrypted and decrypted in {:?}", start.elapsed());
    info!("Program completed successfully in {:?}", start.elapsed());

    Ok(())
}