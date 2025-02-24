//! Aggregate signatures from multiple contributors over the BN254 curve.
//!
//! # Usage (3 of 4 Threshold)
//!
//! _To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install) and [protoc](https://grpc.io/docs/protoc-installation)._
//!
//! ## Orchestrator
//! ```bash
//! cargo run --release -- --me 0@3000 --participants 0,1,2,3,4 --contributors 1,2,3,4
//! ```
//!
//! ## Contributor 1
//! ```bash
//! cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 1@3001 --participants 0,1,2,3,4  --orchestrator 0 --contributors 1,2,3,4
//! ```
//!
//! ## Contributor 2
//! ```bash
//! cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 2@3002 --participants 0,1,2,3,4  --orchestrator 0 --contributors 1,2,3,4
//! ```
//!
//! ## Contributor 3
//! ```bash
//! cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 3@3003 --participants 0,1,2,3,4  --orchestrator 0 --contributors 1,2,3,4
//! ```
//!
//! ## Contributor 4
//!
//! ```bash
//! cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 4@3004 --participants 0,1,2,3,4 --orchestrator 0 --contributors 1,2,3,4
//! ```

mod bn254;
mod handlers;

use ark_ff::{Fp, PrimeField};
use ark_bn254::Fr;
use bn254::{Bn254, PrivateKey};
use clap::{value_parser, Arg, Command};
use commonware_cryptography::Scheme;
use commonware_p2p::authenticated::{self, Network};
use commonware_runtime::{
    tokio::{self, Executor},
    Runner, Spawner,
};
use commonware_utils::quorum;
use governor::Quota;
use prometheus_client::registry::Registry;
use commonware_restaking::eigenlayer::EigenStakingClient;
use eigen_logging::{init_logger, log_level::LogLevel};
use eigen_crypto_bls::{convert_to_g1_point, convert_to_g2_point};
use alloy_primitives::{address, hex::hex};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
};
use std::{str::FromStr, time::Duration};
use tracing::info;
// TODO change this to match the avs namespace 
// Unique namespace to avoid message replay attacks.
const APPLICATION_NAMESPACE: &[u8] = b"_COMMONWARE_AGGREGATION_";
const PRIVATE_KEY_LENGTH: usize = 32;

fn main() {
        // Initialize EigenStaking client
        // let eigen_client = EigenStakingClient::new(
        //     String::from("https://withered-convincing-meadow.quiknode.pro/89fd706450ed0a8279f87c01e52ae78d9b308ce7"),
        //     String::from("wss://withered-convincing-meadow.quiknode.pro/89fd706450ed0a8279f87c01e52ae78d9b308ce7"),
        //     address!("0xeCd099fA5048c3738a5544347D8cBc8076E76494").into(),
        //     20227142,
        // ).await.expect("Failed to initialize EigenStaking client");

        // // Get operator states
        // let quorum_infos = eigen_client.get_operator_states().await
        //     .expect("Failed to retrieve operator states");

        // println!("\nEigenLayer Operator Summary:");
        // println!("Number of Quorums: {}", quorum_infos.len());
        // for quorum in &quorum_infos {
        //     println!("\nQuorum {} Summary:", quorum.quorum_number);
        //     println!("Total Operators: {}", quorum.operator_count);
        //     println!("Total Stake: {} wei", quorum.total_stake);
        //     println!("Operators with Public Keys: {}", 
        //         quorum.operators.iter().filter(|op| op.pub_keys.is_some()).count());
        //     println!("Operators with Sockets: {}", 
        //         quorum.operators.iter().filter(|op| op.socket.is_some()).count());
        // }
    // TODO Last indexed block should probably be included in the eigen staking client 
    // In order to allow the oracle to register updates to the peer set
    // Initialize runtime
    let runtime_cfg = tokio::Config::default();
    let (executor, runtime) = Executor::init(runtime_cfg.clone());
    init_logger(LogLevel::Info);
        // Parse arguments
    // TODO - add args for RPC/WS , Reg Coord and Start Block 
    let matches = Command::new("commonware-aggregation")
        .about("generate and verify BN254 Multi-Signatures")
        .arg(
            Arg::new("bootstrappers") 
                .long("bootstrappers")
                .required(false)
                .value_delimiter(',')
                .value_parser(value_parser!(String)),
        )
        .arg(Arg::new("me").long("me").required(true))
        .arg(
            Arg::new("participants")
                .long("participants")
                .required(true) // TODO change this to not be required in order to support Eigenlayer participant discovery  
                .value_delimiter(',')
                .value_parser(value_parser!(u64))
                .help("All participants (orchestrator and contributors)"),
        )
        .arg(
            Arg::new("orchestrator")
                .long("orchestrator")
                .required(false)
                .value_parser(value_parser!(u64))
                .help("If set, run as a contributor otherwise run as the orchestrator"),
        )
        .arg(
            Arg::new("contributors")
                .long("contributors")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(u64))
                .help("contributors"),
        )
        .get_matches();

    // Configure my identity
    let me = matches
        .get_one::<String>("me")
        .expect("Please provide identity");
    let parts = me.split('@').collect::<Vec<&str>>();
    if parts.len() != 2 {
        panic!("Identity not well-formed");
    }
    let scalar = hex::decode(parts[0]).expect("Invalid hex string for private key");
    let fr = Fr::from_be_bytes_mod_order(&scalar);
    let key = PrivateKey::from(fr);
    
    let signer = <Bn254 as Scheme>::from(key).expect("Failed to create signer");
    // tracing::info!(key = ?signer.public_key(), "loaded signer");
    let public_key = signer.public_g1();
    print!("{}", public_key);
    std::process::exit(0);
    // Configure my port
    let port = parts[1].parse::<u16>().expect("Port not well-formed");
    tracing::info!(port, "loaded port");

    // Configure allowed peers
    let mut recipients = Vec::new();
    let participants = matches
        .get_many::<u64>("participants") // TODO Change this get the participants from eigenlayer 
        .expect("Please provide allowed keys")
        .copied();
    if participants.len() == 0 {
        panic!("Please provide at least one participant");
    }
    for peer in participants { // TODO Instead of initing signers, load the G2 pubkeys from Eigenlayer
        let verifier = Bn254::from_seed(peer).public_key();
        tracing::info!(key = ?verifier, "registered authorized key",);
        recipients.push(verifier);
    }

    // Configure bootstrappers (if provided)
    // TODO ask patrick if there's any value in having bootstrappers if we can get away from needing them 
    let bootstrappers = matches.get_many::<String>("bootstrappers");
    let mut bootstrapper_identities = Vec::new();
    if let Some(bootstrappers) = bootstrappers {
        for bootstrapper in bootstrappers {
            let parts = bootstrapper.split('@').collect::<Vec<&str>>();
            let bootstrapper_key = parts[0]
                .parse::<u64>()
                .expect("Bootstrapper key not well-formed");
            let verifier = Bn254::from_seed(bootstrapper_key).public_key();
            let bootstrapper_address =
                SocketAddr::from_str(parts[1]).expect("Bootstrapper address not well-formed");
            bootstrapper_identities.push((verifier, bootstrapper_address));
        }
    }

    // Configure network
    // TODO take this from env 
    const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1 MB
    // TODO ask patrick what the prod config should be 
    let p2p_cfg = authenticated::Config::aggressive(
        signer.clone(),
        APPLICATION_NAMESPACE,
        Arc::new(Mutex::new(Registry::default())),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        bootstrapper_identities.clone(),
        MAX_MESSAGE_SIZE,
    );

    // Start runtime
    executor.start(async move {
        let (mut network, mut oracle) = Network::new(runtime.clone(), p2p_cfg);

        // Provide authorized peers
        //
        // In a real-world scenario, this would be updated as new peer sets are created (like when
        // the composition of a validator set changes).
        // TODO create a thread which uses the EL staking client to invoke this oracle routinely 
        oracle.register(0, recipients).await;

        // Parse contributors
        let mut contributors = Vec::new();
        let mut contributors_map = HashMap::new();
        // TODO ask patrick why we are using participants here but indexing contributors
        // Possibly name collision? confusing 
        // Actually not relevant because this should all be inited from the EL staking client
        let participants = matches
            .get_many::<u64>("contributors")
            .expect("Please provide contributors")
            .copied();
        if participants.len() == 0 {
            panic!("Please provide at least one contributor");
        }
        for peer in participants {
            let signer = Bn254::from_seed(peer);
            let verifier = signer.public_key();
            let verifier_g1 = signer.public_g1(); // TODO ask patrick why g1 is used here
            tracing::info!(key = ?verifier, "registered contributor",);
            contributors.push(verifier.clone());
            contributors_map.insert(verifier, verifier_g1);
        }

        // Infer threshold
        let threshold = quorum(contributors.len() as u32).expect("insufficient participants");
        info!(threshold, "inferred parameters");

        // Check if I am the orchestrator
        // TODO ask what the first 2 variables are, may need to create an 
        // on-demand orchestrator 
        // It seems that there can only be one orchestrator , need to ask patrick why that is 
        const DEFAULT_MESSAGE_BACKLOG: usize = 256;
        const COMPRESSION_LEVEL: Option<i32> = Some(3);
        const AGGREGATION_FREQUENCY: Duration = Duration::from_secs(10);
        if let Some(orchestrator) = matches.get_one::<u64>("orchestrator") {
            // Create contributor
            // Why are we creating a contributor if this is for the orchestator handling?
            let (sender, receiver) = network.register(
                0,
                Quota::per_second(NonZeroU32::new(10).unwrap()),
                DEFAULT_MESSAGE_BACKLOG,
                COMPRESSION_LEVEL,
            );
            let orchestrator = Bn254::from_seed(*orchestrator).public_key(); // TODO change this to take a private key from ENV or remote signer
            let contributor =
                handlers::Contributor::new(orchestrator, signer, contributors, threshold as usize); //TODO ask patrick if we can uncouple the contributor from the orchestrator
            runtime.spawn("contributor", contributor.run(sender, receiver));
        } else {
            let (sender, receiver) = network.register(
                0,
                Quota::per_second(NonZeroU32::new(10).unwrap()),
                DEFAULT_MESSAGE_BACKLOG,
                COMPRESSION_LEVEL,
            );
            let orchestrator = handlers::Orchestrator::new( //TODO ask patrick, if there's no orchestrator we create one anyways?
                runtime.clone(),
                AGGREGATION_FREQUENCY,
                contributors,
                contributors_map,
                threshold as usize,
            );
            runtime.spawn("orchestrator", orchestrator.run(sender, receiver));
        }
        network.run().await;
    });
}
