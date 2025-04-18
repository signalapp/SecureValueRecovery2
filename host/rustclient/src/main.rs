// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#[macro_use]
extern crate simple_error;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use hmac::Mac;
use prost::Message;
use std::env;
use std::time::SystemTime;
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
use tokio_tungstenite::tungstenite::http::HeaderValue;

pub mod svr2 {
    include!(concat!(env!("OUT_DIR"), "/svr2.rs"));
    pub mod error {
        include!(concat!(env!("OUT_DIR"), "/svr2.error.rs"));
    }
    pub mod minimums {
        include!(concat!(env!("OUT_DIR"), "/svr2.minimums.rs"));
    }
    pub mod metrics {
        include!(concat!(env!("OUT_DIR"), "/svr2.metrics.rs"));
    }
    pub mod enclaveconfig {
        include!(concat!(env!("OUT_DIR"), "/svr2.enclaveconfig.rs"));
    }
}

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

static PATTERN: &'static str = "Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    // AUTH
    let now = SystemTime::now();
    let unix_secs = now.duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
    println!("Timestamp: {}", unix_secs);
    let key = if let Ok(k) = std::env::var("AUTH_KEY") {
        BASE64_STANDARD.decode(k)?
    } else {
        b"123456".to_vec()
    };
    let mut mac = HmacSha256::new_from_slice(&key)?;
    let user = &[1u8; 16];
    let to_mac: Vec<u8> = [
        hex::encode(user).as_bytes(),
        format!(":{}", unix_secs).as_bytes(),
    ]
    .concat();
    println!("bytes: {:02x?}", to_mac);
    mac.update(&to_mac);
    let token = format!(
        "{}:{}",
        unix_secs,
        hex::encode(&mac.finalize().into_bytes()[..10])
    );

    let mut request = args[1].to_owned().into_client_request()?;
    request.headers_mut().insert(
        AUTHORIZATION,
        basic_authorization(hex::encode(user).as_str(), token.to_owned().as_str()),
    );

    println!(
        "Connecting to {} with user {} token {}",
        &args[1],
        hex::encode(user),
        token
    );
    let (mut stream, _) = tungstenite::connect(request)?;

    println!("Connected");

    println!("Recv ClientHandshakeStart");
    let msg1 = stream.read()?;
    let bin1 = if let tungstenite::Message::Binary(b) = msg1 {
        b
    } else {
        bail!("received message not binary");
    };
    let pb1 = svr2::ClientHandshakeStart::decode(&bin1[..])?;

    println!("Starting Noise Handshake");
    let mut buf = [0u8; 8192];
    let mut initiator = snow::Builder::new(PATTERN.parse()?)
        .remote_public_key(&pb1.test_only_pubkey[..])
        .build_initiator()?;
    let len = initiator.write_message(&[], &mut buf)?;

    println!("Send handshake start");
    stream.write(tungstenite::Message::Binary(buf[..len].to_vec().into()))?;
    stream.flush()?;

    println!("Recv handshake start");
    let msg2 = stream.read()?;
    let bin2 = if let tungstenite::Message::Binary(b) = msg2 {
        println!("Received!");
        b
    } else {
        bail!("received message not binary");
    };

    println!("Finishing Noise Handshake");
    initiator.read_message(&bin2[..], &mut buf)?;
    if !initiator.is_handshake_finished() {
        bail!("noise handshake not complete");
    }
    initiator.into_transport_mode()?;

    Ok(())
}

pub fn basic_authorization(username: &str, password: &str) -> HeaderValue {
    let auth = BASE64_STANDARD.encode(format!("{}:{}", username, password).as_bytes());
    let auth = format!("Basic {}", auth);
    HeaderValue::try_from(auth).expect("valid header value")
}
