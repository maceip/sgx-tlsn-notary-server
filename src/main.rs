
use log::Level;
use log::{info, warn};
use std::fs::File;
use tokio::fs;
use std::io;
use std::io::Read;
use std::path::Path;
use eyre::{eyre, Result};
use structopt::StructOpt;
use tracing::debug;
use notary_server::{
    init_tracing, parse_config_file, run_server, CliFields, NotaryServerError,
    NotaryServerProperties,
};
use openssl::ec::EcKey;
use openssl::pkey::PKey;

#[tokio::main]
async fn main() -> Result<(), NotaryServerError> {
    // Load command line arguments which contains the config file location

    let cli_fields: CliFields = CliFields::from_args();
	 let eph = fs::read("/tmp/key.pem").await.expect("gramine key not found");
	let pl = EcKey::private_key_from_pem(&eph).expect("s");
    let pkey = PKey::from_ec_key(pl.clone()).expect("ss");
    let private_key = pkey.private_key_to_pem_pkcs8().expect("key");

   fs::write("/tmp/fixed_key.pem", private_key).await.expect("cant write");

    let config: NotaryServerProperties = parse_config_file(&cli_fields.config_file)?;

    init_tracing(&config).map_err(|err| eyre!("Failed to set up tracing: {err}"))?;

    debug!(?config, "Server config loaded");

   run_server(&config).await?;

    Ok(())
}
