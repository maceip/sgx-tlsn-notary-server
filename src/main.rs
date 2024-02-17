use std::{
    error::Error,
    io::{self, Read},
};
use tokio::fs;

use eyre::{eyre, Result};
use notary_server::{
    init_tracing, parse_config_file, run_server, CliFields, NotaryServerError,
    NotaryServerProperties,
};
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    ec::EcKey,
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, PKeyRef, Private},
    rsa::Rsa,
    x509::{
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
            SubjectKeyIdentifier,
        },
        X509NameBuilder, X509NameEntries, X509Ref, X509Req, X509ReqBuilder, X509VerifyResult, X509,
    },
};
use structopt::StructOpt;
use tracing::debug;

fn mk_ca_signed_cert(
    ca_cert: &X509Ref,
    ca_key_pair: &PKeyRef<Private>,
) -> Result<(X509, PKey<Private>), ErrorStack> {
    let rsa = Rsa::generate(2048)?;
    let key_pair = PKey::from_rsa(rsa)?;

    let req = mk_request(&key_pair)?;

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(req.subject_name())?;
    cert_builder.set_issuer_name(ca_cert.subject_name())?;
    cert_builder.set_pubkey(&key_pair)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(365)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().build()?)?;

    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .non_repudiation()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    let auth_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(auth_key_identifier)?;

    let subject_alt_name = SubjectAlternativeName::new()
        .dns("*.localhost")
        .dns("localhost")
        .dns("*.orb.codes")
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(subject_alt_name)?;

    cert_builder.sign(ca_key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok((cert, key_pair))
}

fn mk_request(key_pair: &PKey<Private>) -> Result<X509Req, ErrorStack> {
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(key_pair)?;

    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "US")?;
    x509_name.append_entry_by_text("ST", "PR")?;
    x509_name.append_entry_by_text("O", "tlsn")?;
    x509_name.append_entry_by_text("CN", "localhost")?;
    let x509_name = x509_name.build();
    req_builder.set_subject_name(&x509_name)?;

    req_builder.sign(key_pair, MessageDigest::sha256())?;
    let req = req_builder.build();
    Ok(req)
}

#[tokio::main]
async fn main() -> Result<(), NotaryServerError> {

    let cli_fields: CliFields = CliFields::from_args();

    /// gramine bootstraps the libOs enclave with its RA-TLS wrapper
    /// the wrapper writes /tmp/key.pem & /tmp/cert.pem to tmpfs for the TEE but they are in a funky format so we need to fix:
    
    let eph = fs::read("/tmp/key.pem").await.expect("gramine ratls rootCA.key not found");
    let gram_crt = fs::read("/tmp/crt.pem").await.expect("gramine ratls rootCA.crt not found");
    let mut gram_crt_print = fs::read_to_string("/tmp/crt.pem").await.expect("gramine ratls rootCA.crt not found");
    
    /// gramine uses old X509 header: BEGIN TRUSTED CERTIFICATE, tlsn wont parse it unless "TRUSTED is removed ->
    let remove_str = "TRUSTED C";
    let mut remove_offset = gram_crt_print.find(remove_str).unwrap_or(gram_crt_print.len());
    gram_crt_print.replace_range(remove_offset..remove_offset + remove_str.len(), "C");
    remove_offset = gram_crt_print.find(remove_str).unwrap_or(gram_crt_print.len());
    gram_crt_print.replace_range(remove_offset..remove_offset + remove_str.len(), "C");


    let pl = EcKey::private_key_from_pem(&eph).expect("failed to deserialize PEM");
    let pkey = PKey::from_ec_key(pl.clone()).expect("failed to create PK");
    let private_key = pkey.private_key_to_pem_pkcs8().expect("failed to write PKCS8");

    let gramine_cert =
        X509::from_pem(&gram_crt_print.as_bytes()).expect("cant deserialize cert string");

    let config: NotaryServerProperties = parse_config_file(&cli_fields.config_file)?;

    let (cert, key_pair) = mk_ca_signed_cert(&gramine_cert, &pkey).expect("failed to create TLS keys from Gramine RATLS CA");
    let cert_as_pem = cert.to_pem().expect("cant convert X509 to pem");
    let key_pair_pem = key_pair.private_key_to_pem_pkcs8().expect("cant serialize pk to pkcs8");

    fs::write("/tmp/fixed_key.pem", key_pair_pem).await.expect("cant write key pair to tmpfs");
    fs::write("/tmp/fixed_crt.pem", cert_as_pem).await.expect("cant write cert to tmpfs");

    // rootCA.crt to give to provers / the world 🌎:
    fs::write("/fixture/tls/gramine_crt.pem", gram_crt_print).await.expect("cant write rootCA.crt");

    init_tracing(&config).map_err(|err| eyre!("Failed to set up tracing: {err}"))?;

    debug!(?config, "Server config loaded");

    run_server(&config).await?;

    Ok(())
}
