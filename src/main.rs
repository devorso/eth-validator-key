
use ethsign::{KeyFile, Protected, SecretKey};

pub fn hex_convert(buf: &mut String, blob: &[u8]) {
    for ch in blob {
        fn hex_from_digit(num: u8) -> char {
            if num < 10 {
                (b'0' + num) as char
            } else {
                (b'A' + num - 10) as char
            }
        }
        buf.push(hex_from_digit(ch / 16));
        buf.push(hex_from_digit(ch % 16));
    }
}
fn main() {

let val = std::fs::File::open("keystore.json").unwrap();
    let pattern = std::env::args().nth(1);
    let mut password: Protected = "".into();

    if let Some(value) = pattern{


        if value == "--password" {
            let path = std::env::args().nth(2);
            if let Some(password_given) = path {
                password = password_given.into();
            }
        }
    }

    let key:KeyFile = serde_json::from_reader(val).unwrap();

    let secret = key.to_secret_key(&password);

    match secret {

        Ok(data) => {

            println!("Key recover for Ethereum validator.");
            let eth_address = data.public();
            let crypto = key.crypto;

            let decrypted_value = crypto.decrypt(&password);
            match decrypted_value {
                Ok(data_decrypted) => {


                    let mut private_key = String::new();

                    hex_convert(&mut private_key, &data_decrypted);

                    let mut eth_addr = String::new();

                    hex_convert(&mut eth_addr, eth_address.address());

                    println!("Decrypted private key: {} for the validator address: 0x{}",private_key.to_lowercase(), eth_addr );

                },
                Err(e) => {
                    println!("Error on recover process.. {:?}",e);
                }
            }
        },
        Err(e) => {
            println!(" Error: {:?}",e);
        }
    }




}
