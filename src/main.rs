use std::time::Instant;
use gw_proxy_recrypt::*;
use log::{debug, error, info, warn};
use util::{serialize_public_key_to_json, serialize_private_key_to_json, write_json_to_file, read_json_from_file, save_signing_keypair_to_file};
mod init_client;
mod target_client;



fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let start = Instant::now();
    info!("Program started for PRE.");

    let mut recrypt = Recrypt::new();
    debug!("Recrypt object created.");

    let signing_keypair = generate_signing_key(&mut recrypt);
    debug!("Signing keypair generated.");

    save_signing_keypair_to_file(&signing_keypair, "/Users/manjeetsingh/test-certs/signing_keypair");

    //let (initial_priv_key, initial_pub_key) = init_member_key_gen(&mut recrypt)?;
    let (initial_priv_key, initial_pub_key) = init_client::init_member_key_gen(&mut recrypt)?;

    let (target_priv_key, target_pub_key) = target_client::init_target_key_gen(&mut recrypt)?;

    let input = "This is symmtery key";

    let encrypted_value = generate_encrypted_val(&recrypt,input,&initial_pub_key,&signing_keypair)?;
  
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

    info!("Program completed successfully in {:?}", start.elapsed());

    Ok(())
}

    
    


    