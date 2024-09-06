use serde_json;
use recrypt::api::{PrivateKey, PublicKey,SigningKeypair};
use log::{info, debug, warn, error};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::io::Read;
use serde_json::Value;
use std::io;


/// Serializes the x and y values of a public key to JSON strings.
pub fn serialize_public_key_to_json(pub_key: &PublicKey) -> (String, String) {
    // Convert the x value of the public key to a JSON string
    let x = serde_json::to_string(&pub_key.bytes_x_y().0).unwrap();
    // Convert the y value of the public key to a JSON string
    let y = serde_json::to_string(&pub_key.bytes_x_y().1).unwrap();
    info!("Serialized PublicKey x: {}", x);
    info!("Serialized PublicKey y: {}", y);
    (x, y)
}

/// Serializes a private key to a JSON string.pub 
pub fn serialize_private_key_to_json(priv_key: &PrivateKey) -> String {
    // Convert the private key bytes to a JSON string
    let serialized = serde_json::to_string(priv_key.bytes()).unwrap();
    debug!("Serialized PrivateKey: {}", serialized);
    serialized
}

/// Serializes the x and y values of a public key to byte vectors.
pub fn serialize_public_key_to_vec(pub_key: &PublicKey) -> (Vec<u8>, Vec<u8>) {
    // Convert the x value of the public key to a byte vector
    let x = serde_json::to_vec(&pub_key.bytes_x_y().0).unwrap();
    // Convert the y value of the public key to a byte vector
    let y = serde_json::to_vec(&pub_key.bytes_x_y().1).unwrap();
    (x, y)
}

/// Serializes a private key to a byte vector.
pub fn serialize_private_key_to_vec(priv_key: &PrivateKey) -> Vec<u8> {
    // Convert the private key bytes to a byte vector
    serde_json::to_vec(priv_key.bytes()).unwrap()
}

/// Deserializes a JSON string into a PrivateKey.
pub fn deserialize_private_key_from_str(json_str: &str) -> PrivateKey {
    // Convert the JSON string back to a vector of bytes
    let bytes: Vec<u8> = serde_json::from_str(json_str).unwrap();
    // Create a PrivateKey from the byte slice
    PrivateKey::new_from_slice(&bytes).unwrap()
}

/// Deserializes JSON bytes into a PrivateKey.
pub fn deserialize_private_key_from_bytes(json_bytes: &[u8]) -> PrivateKey {
    // Convert the JSON bytes back to a vector of bytes
    let bytes: Vec<u8> = serde_json::from_slice(json_bytes).unwrap();
    // Create a PrivateKey from the byte slice
    PrivateKey::new_from_slice(&bytes).unwrap()
}

/// Deserializes JSON strings into a PublicKey.
pub fn deserialize_public_key_from_str(json_str_x: &str, json_str_y: &str) -> PublicKey {
    // Convert the JSON string for x back to a vector of bytes
    let bytes_x: Vec<u8> = serde_json::from_str(json_str_x).unwrap();
    // Convert the JSON string for y back to a vector of bytes
    let bytes_y: Vec<u8> = serde_json::from_str(json_str_y).unwrap();
    // Create a PublicKey from the byte slices
    PublicKey::new_from_slice((&bytes_x, &bytes_y)).unwrap()
}

/// Deserializes JSON bytes into a PublicKey.
pub fn deserialize_public_key_from_bytes(json_bytes_x: &[u8], json_bytes_y: &[u8]) -> PublicKey {
    // Convert the JSON bytes for x back to a vector of bytes
    let bytes_x: Vec<u8> = serde_json::from_slice(json_bytes_x).unwrap();
    // Convert the JSON bytes for y back to a vector of bytes
    let bytes_y: Vec<u8> = serde_json::from_slice(json_bytes_y).unwrap();
    // Create a PublicKey from the byte slices
    PublicKey::new_from_slice((&bytes_x, &bytes_y)).unwrap()
}

/// Writes a JSON string to a file in the specified directory with the given file name.
///
/// # Arguments
///
/// * `dir_path` - A string slice that holds the path to the directory.
/// * `file_name` - A string slice that holds the name of the file to be created.
/// * `json` - A string slice that holds the JSON content to be written.
pub fn write_json_to_file(dir_path: &str, file_name: &str, json: &str) -> std::io::Result<()> {
    // Ensure the directory exists
    fs::create_dir_all(dir_path)?;

    // Construct the full path to the output file
    let file_path = Path::new(dir_path).join(file_name);

    // Create and open the file in write mode
    let mut file = File::create(file_path)?;

    // Write the JSON string to the file
    file.write_all(json.as_bytes())?;

    Ok(())
}


/// Reads a JSON file from the specified file path and prints its contents.
///
/// # Arguments
///
/// * `file_path` - A string slice that holds the path to the JSON file.
pub fn read_json_from_file(file_path: &str) -> io::Result<()> {
    // Open the file in read mode
    let mut file = File::open(file_path)?;

    // Read the file contents into a string
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    // Parse the string as JSON
    let json_data: Value = serde_json::from_str(&contents)?;

    // Print the JSON data in a pretty format
    println!("{}", serde_json::to_string_pretty(&json_data)?);

    Ok(())
}

pub fn save_signing_keypair_to_file(signing_keypair: &SigningKeypair, file_path: &str) -> io::Result<()> {
    let bytes = signing_keypair.bytes();

    let mut file = File::create(file_path)?;
    file.write_all(bytes)?;

    Ok(())
}
