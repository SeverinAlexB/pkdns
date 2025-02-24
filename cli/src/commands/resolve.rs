use chrono::{DateTime, Utc};
use clap::ArgMatches;
use pkarr::PublicKey;

use crate::{
    helpers::{construct_pkarr_client, nts_to_chrono},
    pkarr_packet::PkarrPacket,
};

async fn resolve_pkarr(uri: &str) -> (PkarrPacket, DateTime<Utc>) {
    let client = construct_pkarr_client();
    let pubkey: PublicKey = uri.try_into().expect("Should be valid pkarr public key.");
    let res = client.resolve_most_recent(&pubkey).await;
    if res.is_none() {
        println!("Failed to find the packet.");
        return (PkarrPacket::empty(), DateTime::<Utc>::MIN_UTC);
    };
    let signed_packet = res.unwrap();
    let timestamp = nts_to_chrono(signed_packet.timestamp());

    let data = signed_packet.encoded_packet();

    (PkarrPacket::by_data(data.to_vec()), timestamp)
}

fn get_arg_pubkey(matches: &ArgMatches) -> Option<PublicKey> {
    let uri_arg: &String = matches.get_one("pubkey").unwrap();
    let trying: Result<PublicKey, _> = uri_arg.as_str().try_into();
    trying.ok()
}

pub async fn cli_resolve(matches: &ArgMatches) {
    let pubkey_opt = get_arg_pubkey(matches);

    if pubkey_opt.is_none() {
        eprintln!("pubkey is not a valid pkarr public key.");
        std::process::exit(1);
    };
    let pubkey = pubkey_opt.unwrap();
    let uri = pubkey.to_uri_string();

    println!("Resolve dns records of {}", uri);
    let (packet, timestamp) = resolve_pkarr(&uri).await;

    println!("{packet}");
    if !packet.is_emtpy() {
        println!("Last updated at: {timestamp}");
    };
}
