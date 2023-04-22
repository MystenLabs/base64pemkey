use std::fs::File;
use std::io::Read;
use std::path::Path;
use openssl::ec::{EcGroup, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use base64::encode;

fn main() {
    // Get the filename of the PEM-encoded public key from the command-line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <pem-file>", args[0]);
        return;
    }
    let pem_filename = &args[1];

    // Open the PEM-encoded public key file
    let mut file = File::open(Path::new(pem_filename)).unwrap();
    let mut pem_bytes = Vec::new();
    file.read_to_end(&mut pem_bytes).unwrap();
    let group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    //let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();

    

    // Parse the PEM-encoded public key and extract the raw bytes
    let pkey = PKey::public_key_from_pem(&pem_bytes).unwrap();
    let d = pkey.ec_key().unwrap().public_key().to_bytes(&group,
        PointConversionForm::COMPRESSED,
        &mut openssl::bn::BigNumContext::new().unwrap(),);
    let mut arr = Vec::new();
    arr.extend_from_slice(&[0x01]);
    //arr.extend_from_slice(&[0x02]);
    arr.extend_from_slice(&d.unwrap());
    println!("{}", encode(arr));
}
