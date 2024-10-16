use crate::utils;
use chrono::{DateTime, Utc};
use cms::cert::x509::name::Name;
use cms::{
    builder::{SignedDataBuilder, SignerInfoBuilder},
    cert::{
        x509::{
            attr::Attribute, der::Decode, name::RdnSequence, serial_number::SerialNumber,
            spki::AlgorithmIdentifierOwned, Certificate,
        },
        CertificateChoices, IssuerAndSerialNumber,
    },
    content_info::ContentInfo,
    signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier},
};
use der::{
    asn1::{OctetString, SetOfVec},
    Any, DecodePem, Encode, Tag, Tagged,
};
use p12_keystore::{KeyStore, KeyStoreEntry, PrivateKeyChain};
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::digest::const_oid;
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs1v15::SigningKey};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::cmp::PartialEq;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use x509_parser::der_parser::oid;
use x509_parser::nom::AsBytes;
use x509_parser::prelude::*;

pub fn generate_cms(
    hash_data: &[u8],
    hashes_plist: &[u8],
    code_directory_slot256: &[u8],
    cert: bool,
    my_private_key: &[u8],
    issuer: &[u8],
    serial_number: &[u8],
) {
    let apple_dev_ca_cert = include_str!("../certificates/apple_dev_ca_cert.pem");
    let apple_dev_ca_cert_g3 = include_str!("../certificates/apple_dev_ca_cert_g3.pem");
    let apple_root_ca_cert = include_str!("../certificates/apple_root_ca_cert.pem");

    let issuer_cert = if cert {
        apple_dev_ca_cert
    } else {
        apple_dev_ca_cert_g3
    };

    let other_certs = vec![
        Certificate::from_pem(issuer_cert.as_bytes()).unwrap(),
        Certificate::from_pem(apple_root_ca_cert.as_bytes()).unwrap(),
    ];
    let encapsulated_content_info = EncapsulatedContentInfo {
        econtent_type: const_oid::db::rfc5911::ID_CONTENT_TYPE,
        econtent: Some(
            Any::new(
                Tag::OctetString,
                OctetString::new(hash_data).unwrap().to_der().unwrap(),
            )
            .unwrap(),
        ),
    };

    let mut builder = SignedDataBuilder::new(&encapsulated_content_info);

    for cert in other_certs {
        builder
            .add_certificate(CertificateChoices::Certificate(cert))
            .unwrap();
    }

    let private_key = rsa::RsaPrivateKey::from_pkcs8_der(my_private_key).unwrap();
    let signer = SigningKey::<Sha256>::new(private_key);

    let issuer_serial_number = IssuerAndSerialNumber {
        issuer: Name::from_der(issuer).unwrap(),
        serial_number: SerialNumber::new(serial_number).unwrap(),
    };
    let mut signer_info = SignerInfoBuilder::new(
        &signer,
        SignerIdentifier::IssuerAndSerialNumber(issuer_serial_number),
        AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_SHA_256,
            parameters: None,
        },
        &encapsulated_content_info,
        None,
    )
    .unwrap();

    let mut cd_hashes_attr = Attribute {
        oid: const_oid::db::rfc5911::ID_CONTENT_TYPE,
        values: SetOfVec::new(),
    };
    cd_hashes_attr
        .values
        .insert(Any::new(Tag::Utf8String, hashes_plist).unwrap())
        .unwrap();
    signer_info.add_signed_attribute(cd_hashes_attr).unwrap();

    //add SHA256 hash attribute
    let mut sha256_attr = Attribute {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        values: SetOfVec::new(),
    };
    sha256_attr
        .values
        .insert(Any::new(Tag::Utf8String, code_directory_slot256).unwrap())
        .unwrap();
    signer_info.add_signed_attribute(sha256_attr).unwrap();

    builder.add_signer_info(signer_info).unwrap();

    //build the cms
    let content_info = builder.build().unwrap();
    let cms = content_info.to_der().unwrap();
}
pub fn extract_plist_xml(data: &[u8]) -> &[u8] {
    let xml_start = b"<?xml";
    let start_pos = data
        .windows(xml_start.len())
        .position(|window| window == xml_start)
        .unwrap();

    let xml_end = b"</plist>";
    let end_pos = data
        .windows(xml_end.len())
        .position(|window| window == xml_end)
        .unwrap()
        + xml_end.len();
    &data[start_pos..end_pos]
}

fn read_p12() -> Vec<u8> {
    let password = "1";
    let private_key_pem = fs::read("./iphone.p12").unwrap();
    let store = KeyStore::from_pkcs12(&private_key_pem, password).unwrap();
    let (_, private_key_chain) = store.private_key_chain().unwrap();
    private_key_chain.key().to_vec()
}

#[derive(Debug, Deserialize, Clone)]
pub struct PlistInfo {
    #[serde(rename = "TeamIdentifier")]
    pub team_identifier: Vec<String>,
    #[serde(rename = "DeveloperCertificates")]
    pub developer_certificates: Vec<Data>,
    #[serde(rename = "Entitlements")]
    pub entitlements: Map<String, Value>,
}
#[derive(Deserialize, Debug, Clone)]
pub struct Data(#[serde(with = "serde_bytes")] pub(crate) Vec<u8>);
fn read_info() -> (Vec<u8>, Vec<u8>) {
    //issuer,serial_number
    let provision_pem = fs::read("./iphone.mobileprovision").unwrap();
    let provision_content = extract_plist_xml(&provision_pem);
    let provision: PlistInfo = plist::from_bytes(&provision_content).unwrap();

    let mut certificate_opt = None;
    for cert in &provision.developer_certificates {
        let cert_data = cert.0.as_bytes(); // utils::base64::decode(cert.0)?;
                                           // let (_, pem2) = parse_x509_pem(&cert_data).map_err(SignError::PEMError)?;
        let (_, certificate) = X509Certificate::from_der(cert_data).unwrap(); //.map_err(SignError::DerError)?; // pem2.parse_x509().map_err(SignError::X509Error)?;
        certificate_opt = Some(certificate.clone());
        break;
    }
    let certificate = certificate_opt.unwrap();

    (
        certificate.issuer.as_raw().to_vec(),
        certificate.raw_serial().to_vec()
    )
}

fn main() {
    let hash_data = vec![0; 20];
    let hashes_plist = vec![1; 20];
    let code_directory_slot256 = vec![2; 32];
    let cert = false;
    let my_private_key = read_p12();
    let (issuer, serial_number) = read_info();

    generate_cms(
        &hash_data,
        &hashes_plist,
        &code_directory_slot256,
        cert,
        &my_private_key,
        &issuer,
        &serial_number,
    );
}
