// use gw_proxy_recrypt::*;
// use keygen_helper::asymm_key_gen_save_load;

// pub fn target_key_use(recrypt: &mut Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>) -> Result<(PrivateKey, PublicKey), Box<dyn std::error::Error>> {
//     let file_directory = "/Users/manjeetsingh/test-certs";
//     // Call the asymm_key_gen_save_load method
//     let keys = asymm_key_gen_save_load(recrypt, file_directory,"target")?;
    
//     Ok(keys)
    
// }