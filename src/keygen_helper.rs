 use recrypt::{
    api::{ PrivateKey, PublicKey,SigningKeypair},
    prelude::*,
};
use crate::util::{serialize_public_key_to_json, serialize_private_key_to_json, write_json_to_file, deserialize_public_key_from_str, deserialize_private_key_from_str};
use std::fs;
use std::path::Path;
use log::{debug, error, info, warn};
use recrypt::api::DefaultRng;
use crate::generate_asymmetric_key;
use std::fs::File;
use std::io::Write;
use std::io;

pub fn asymm_key_gen_save_load(
    recrypt: &mut Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>,
    file_directory: &str,
    client_name: &str
) -> Result<(PrivateKey, PublicKey), Box<dyn std::error::Error>> {
    let pub_key_x_path = Path::new(file_directory).join(format!("{}_pub_key-x", client_name));
    let pub_key_y_path = Path::new(file_directory).join(format!("{}_pub_key-y", client_name));
    let priv_key_path = Path::new(file_directory).join(format!("{}_priv_key", client_name));

    // Check if the files already exist
    if pub_key_x_path.exists() && pub_key_y_path.exists() && priv_key_path.exists() {
        // Deserialize and return the existing keys
        let serialized_pub_key_x = fs::read_to_string(&pub_key_x_path)?;
        let serialized_pub_key_y = fs::read_to_string(&pub_key_y_path)?;
        let serialized_priv_key = fs::read_to_string(&priv_key_path)?;
        info!("****Using existing keys for {} member ****", client_name);
        let client_pub_key = deserialize_public_key_from_str(&serialized_pub_key_x, &serialized_pub_key_y);
        let client_priv_key = deserialize_private_key_from_str(&serialized_priv_key);

        return Ok((client_priv_key, client_pub_key));
    }
    info!("****Generating new keys for {} member****", client_name);
    // Generate new keys if files do not exist
    let (client_priv_key, client_pub_key) = generate_asymmetric_key(recrypt)?;
    let (serialized_pub_key_x, serialized_pub_key_y) = serialize_public_key_to_json(&client_pub_key);
    let serialized_priv_key = serialize_private_key_to_json(&client_priv_key);

    // Save the serialized keys to files
    write_json_to_file(file_directory, &format!("{}_pub_key-x", client_name), &serialized_pub_key_x);
    write_json_to_file(file_directory, &format!("{}_pub_key-y", client_name), &serialized_pub_key_y);
    write_json_to_file(file_directory, &format!("{}_priv_key", client_name), &serialized_priv_key);

    Ok((client_priv_key, client_pub_key))
}

pub fn save_signing_keypair_to_file(signing_keypair: &SigningKeypair, file_path: &str) -> io::Result<()> {
    // Check if the file already exists
    if Path::new(file_path).exists() {
        info!("*** Using existing signing pair keys  at {} ****", file_path);
        return Ok(()); // Return early if the file exists
    }

    info!("*** Generating new signing key pair and saving to {} ****", file_path);
    let bytes = signing_keypair.bytes();

    let mut file = File::create(file_path)?;
    file.write_all(bytes)?;

    Ok(())
}


pub fn get_target_party_public_key(
    file_directory: &str,
    client_name: &str
) -> Result<PublicKey, Box<dyn std::error::Error>> {
    let pub_key_x_path = Path::new(file_directory).join(format!("{}_pub_key-x", client_name));
    let pub_key_y_path = Path::new(file_directory).join(format!("{}_pub_key-y", client_name));

    // Check if the public key files exist
    if pub_key_x_path.exists() && pub_key_y_path.exists() {
        // Deserialize and return the existing public key
        let serialized_pub_key_x = fs::read_to_string(&pub_key_x_path)?;
        let serialized_pub_key_y = fs::read_to_string(&pub_key_y_path)?;
        info!("****Using existing public key for {} member ****", client_name);
        let client_pub_key = deserialize_public_key_from_str(&serialized_pub_key_x, &serialized_pub_key_y);
        return Ok(client_pub_key);
    }

    // Return an error if the public key files do not exist
    error!("Public key files for {} not found in directory {}", client_name, file_directory);
    Err(Box::new(io::Error::new(io::ErrorKind::NotFound, "Public key files not found")))
}
