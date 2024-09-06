use gw_proxy_recrypt::*;
use util::{serialize_public_key_to_json, serialize_private_key_to_json, write_json_to_file};
use log::{debug, error, info, warn};

pub fn init_target_key_gen(recrypt: &mut Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>) -> Result<(PrivateKey, PublicKey), Box<dyn std::error::Error>> {
    let (target_priv_key, target_pub_key) = generate_asymmetric_key(recrypt)?;
    debug!("Target asymmetric key pair generated.");

    let (serialized_target_pub_key_x, serialized_target_pub_key_y) = serialize_public_key_to_json(&target_pub_key);
    write_json_to_file("/Users/manjeetsingh/test-certs", "target_public_key-x", &serialized_target_pub_key_x);
    write_json_to_file("/Users/manjeetsingh/test-certs", "target_public_key-y", &serialized_target_pub_key_y);

    let serialized_target_priv_key = serialize_private_key_to_json(&target_priv_key);
    write_json_to_file("/Users/manjeetsingh/test-certs", "target_priv_key", &serialized_target_priv_key);

    debug!("Target public key serialized to JSON: x = {}, y = {}", serialized_target_pub_key_x, serialized_target_pub_key_y);
    debug!("Target private key serialized to JSON: {}", serialized_target_priv_key);

    Ok((target_priv_key, target_pub_key))
}