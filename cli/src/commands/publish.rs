use std::io::Write;
use std::{
    fs::read_to_string,
    path::{Path, PathBuf},
};

use anyhow::anyhow;

use clap::ArgMatches;
use pkarr::{Keypair, SignedPacket, Timestamp};

use crate::external_ip::{resolve_ipv4, resolve_ipv6};
use crate::helpers::nts_to_chrono;
use crate::{helpers::construct_pkarr_client, simple_zone::SimpleZone};

const SECRET_KEY_LENGTH: usize = 32;

/// Replaces {externl_ipv4} and {external_ipv6} variables in the zone file
/// with the according ips.
/// Errors if ips can't be resolved.
async fn fill_dyndns_variables(zone: &mut String) -> Result<(), anyhow::Error> {
    if zone.contains("{external_ipv4}") {
        let ip_result = resolve_ipv4().await;
        if let Err(e) = ip_result {
            return Err(anyhow!(e));
        }
        let (external_ipv4, _) = ip_result.unwrap();
        *zone = zone.replace("{external_ipv4}", &external_ipv4.to_string());
    };

    if zone.contains("{external_ipv6}") {
        let ip_result = resolve_ipv6().await;
        if let Err(e) = ip_result {
            return Err(anyhow!(e));
        }
        let (external_ipv6, _) = ip_result.unwrap();
        *zone = zone.replace("{external_ipv6}", &external_ipv6.to_string());
    };

    Ok(())
}

async fn read_zone_file(matches: &ArgMatches, pubkey: &str) -> SimpleZone {
    let unexpanded_path: &String = matches.get_one("zonefile").unwrap();
    let csv_path_str: String = shellexpand::full(unexpanded_path).expect("Valid shell path.").into();
    let path = Path::new(&csv_path_str);
    let path = PathBuf::from(path);

    let zone = read_to_string(path);
    if let Err(e) = zone {
        eprintln!("Failed to read zone at {csv_path_str}. {e}");
        std::process::exit(1);
    };
    let mut zone = zone.unwrap();
    if let Err(e) = fill_dyndns_variables(&mut zone).await {
        panic!("Failed to fetch external ips. {e}");
    };

    let zone = SimpleZone::read(zone, pubkey);
    if let Err(e) = zone {
        eprintln!("Failed to parse zone file. {e}");
        std::process::exit(1);
    };
    zone.unwrap()
}

fn read_seed_file(matches: &ArgMatches) -> Keypair {
    let unexpanded_path: &String = matches.get_one("seed").unwrap();
    let expanded_path: String = shellexpand::full(unexpanded_path).expect("Valid shell path.").into();
    let path = Path::new(&expanded_path);
    let path = PathBuf::from(path);

    let seed = read_to_string(path);
    if let Err(e) = seed {
        eprintln!("Failed to read seed at {expanded_path}. {e}");
        std::process::exit(1);
    };
    let seed = seed.unwrap();
    parse_seed(&seed)
}

fn parse_seed(seed: &str) -> Keypair {
    let seed = seed.trim();
    let decode_result = zbase32::decode_full_bytes_str(&seed);
    if let Err(e) = decode_result {
        eprintln!("Failed to parse the seed file. {e} {seed}");
        std::process::exit(1);
    };

    let plain_secret = decode_result.unwrap();

    let slice: &[u8; SECRET_KEY_LENGTH] = &plain_secret[0..SECRET_KEY_LENGTH].try_into().unwrap();
    let keypair = Keypair::from_secret_key(slice);
    keypair
}

pub async fn cli_publish(matches: &ArgMatches) {
    let keypair = read_seed_file(matches);
    let pubkey = keypair.to_z32();
    let client = construct_pkarr_client();

    let zone = read_zone_file(matches, &pubkey).await;
    println!("{}", zone.packet);
    let packet = zone.packet.parsed();
    let packet = SignedPacket::new(&keypair, &packet.answers, Timestamp::now());
    if let Err(e) = packet {
        eprintln!("Failed to sign the pkarr packet. {e}");
        std::process::exit(1);
    }
    let packet = packet.unwrap();

    print!("Hang on... {}", nts_to_chrono(packet.timestamp()));
    std::io::stdout().flush().unwrap();
    let result = client.publish(&packet, None).await;
    print!("\r");
    match result {
        Ok(_) => {
            println!("{} Successfully announced.", nts_to_chrono(packet.timestamp()))
        }
        Err(e) => {
            println!("Error {}", e.to_string())
        }
    };
}
