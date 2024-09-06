use gw_proxy_recrypt::*;
use util::{serialize_public_key_to_json, serialize_private_key_to_json, write_json_to_file};

pub fn init_member_key_gen(
    recrypt: &mut Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>
) -> Result<(PrivateKey, PublicKey), Box<dyn std::error::Error>> {
    let (initial_priv_key, initial_pub_key) = generate_asymmetric_key(recrypt)?;
    let (serialized_pub_key_x, serialized_pub_key_y) = serialize_public_key_to_json(&initial_pub_key);
    let serialized_priv_key = serialize_private_key_to_json(&initial_priv_key);

    write_json_to_file("/Users/manjeetsingh/test-certs", "initial_pub_key-x", &serialized_pub_key_x);
    write_json_to_file("/Users/manjeetsingh/test-certs", "initial_pub_key-y", &serialized_pub_key_y);
    write_json_to_file("/Users/manjeetsingh/test-certs", "initial_priv_key", &serialized_priv_key);

    Ok((initial_priv_key, initial_pub_key))
}