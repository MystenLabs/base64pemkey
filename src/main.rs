use anyhow::{anyhow, Result};
use base64::encode;
use openssl::ec::{EcGroup, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use sui_types::base_types::SuiAddress;
use sui_types::crypto::{EncodeDecodeBase64, PublicKey};

// Prints out corresponding Address and Sui Pubkey from a pem file in AWS.

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <pem-file>", args[0]);
        return Ok(());
    }
    let pem_filename = &args[1];

    let mut file = File::open(Path::new(pem_filename))
        .map_err(|e| anyhow!("Failed to open PEM file: {:?}", e))?;
    let mut pem_bytes = Vec::new();
    file.read_to_end(&mut pem_bytes)
        .map_err(|e| anyhow!("Failed to read PEM file: {:?}", e))?;

    let group =
        EcGroup::from_curve_name(Nid::SECP256K1).map_err(|_| anyhow!("Failed to get EC group"))?;
    let pkey = PKey::public_key_from_pem(&pem_bytes)
        .map_err(|_| anyhow!("Failed to get public key from PEM"))?;
    let ec_key = pkey.ec_key().map_err(|_| anyhow!("Failed to get EC key"))?;
    let public_key_bytes = ec_key
        .public_key()
        .to_bytes(
            &group,
            PointConversionForm::COMPRESSED,
            &mut openssl::bn::BigNumContext::new().unwrap(),
        )
        .map_err(|_| anyhow!("Failed to get public key bytes"))?;

    let mut arr = Vec::new();
    arr.extend_from_slice(&[0x01]);
    arr.extend_from_slice(&public_key_bytes);

    // If `arr` should be base64 encoded, encode it
    let base64_str = encode(&arr);

    // If you need to decode it back into bytes
    let decoded_bytes =
        base64::decode(&base64_str).map_err(|e| anyhow!("Failed to decode base64: {:?}", e))?;

    // Assuming PublicKey::decode_base64 expects a base64 encoded string
    let pk_owner = PublicKey::decode_base64(&base64_str)
        .map_err(|e| anyhow!("Invalid base64 key: {:?}", e))?;

    let address_owner = SuiAddress::from(&pk_owner);
    println!("Address For Corresponding KMS Key: {}", address_owner);
    println!("Base64 Encoded Public Key: {}", base64_str);

    Ok(())
}
