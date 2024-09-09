use std::env;
use std::time::Instant;
use gw_proxy_recrypt::*;
use log::{debug, error, info};

mod init_client;
mod target_client;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let start = Instant::now();
    info!("Program started for PRE.");

    // Capture command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        error!("Please provide the input as a command-line argument.");
        return Err("Missing input argument".into());
    }
    let input = &args[1];
    info!("Input provided: {}", input);

    let mut recrypt = Recrypt::new();
    debug!("Recrypt object created.");

    // Define directories and obtain target public key
    let signing_pair_dir = "/Users/manjeetsingh/test-certs/initiator/signing_keypair";
    let asymm_key_gen_dir = "/Users/manjeetsingh/test-certs/initiator";
    let target_pub_key_loc = "/Users/manjeetsingh/test-certs/target";
    let target_certs_dir = "/Users/manjeetsingh/test-certs/target";

    // Initiator Operations
    let (encrypted_value) = encrypt_data_with_pre(
        &mut recrypt,
        input,
        signing_pair_dir,
        asymm_key_gen_dir,
        target_pub_key_loc,
    )?;

    // Target Party Operations
    let decrypted_val = decrypt_pre_data(
        &mut recrypt,
        encrypted_value,
        target_certs_dir,
    )?;

    verification(&decrypted_val, input) ?;
    info!("Program completed successfully in {:?}", start.elapsed());

    Ok(())
}

