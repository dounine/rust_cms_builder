use crate::utils;
use bcder::encode::PrimitiveContent;
use bcder::Oid;
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
use cryptographic_message_syntax::asn1::rfc5652::OID_ID_DATA;
use cryptographic_message_syntax::{Bytes, SignerBuilder};
use der::{
    asn1::{OctetString, SetOfVec},
    Any, DecodePem, Document, Encode, SecretDocument, Tag, Tagged,
};
use log::info;
use p12_keystore::{KeyStore, KeyStoreEntry, PrivateKeyChain};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, PrivateKeyInfo};
use rsa::signature::digest::const_oid;
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs1v15::SigningKey, pkcs8};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::cmp::PartialEq;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use x509_certificate::rfc5652::AttributeValue;
use x509_certificate::{CapturedX509Certificate, DigestAlgorithm, InMemorySigningKeyPair};
use x509_parser::der_parser::oid;
use x509_parser::nom::AsBytes;
use x509_parser::prelude::*;

mod mybase64;
pub fn create_cms_signature(
    code_data: &[u8],
    hashes_plist: &[u8],
    code_directory_slot256: &[u8],
    cert: bool,
    private_key_data: &[u8],
    private_key_cert: &CapturedX509Certificate, //这个应该从p12文件中取出来证书来
) {
    // 1.2.840.113635.100.9.1
    pub const CD_DIGESTS_PLIST_OID: bcder::ConstOid = Oid(&[42, 134, 72, 134, 247, 99, 100, 9, 1]);
    /// 1.2.840.113635.100.9.2
    pub const CD_DIGESTS_OID: bcder::ConstOid = Oid(&[42, 134, 72, 134, 247, 99, 100, 9, 2]);

    let private_key = InMemorySigningKeyPair::from_pkcs8_der(private_key_data).unwrap();

    let signer = SignerBuilder::new(&private_key, private_key_cert.clone())
        .message_id_content(code_data.to_vec())
        .signed_attribute_octet_string(
            Oid(Bytes::copy_from_slice(CD_DIGESTS_PLIST_OID.as_ref())),
            hashes_plist,
        );
    let mut attributes: Vec<AttributeValue> = vec![];
    // let alg = x509_certificate::DigestAlgorithm::try_from(OID_SHA256);

    let apple_dev_ca_cert = include_str!("../certificates/apple_dev_ca_cert.pem");
    let apple_dev_ca_cert_g3 = include_str!("../certificates/apple_dev_ca_cert_g3.pem");
    let apple_root_ca_cert = include_str!("../certificates/apple_root_ca_cert.pem");

    let issuer_cert = if cert {
        apple_dev_ca_cert
    } else {
        apple_dev_ca_cert_g3
    };

    let other_certs = vec![issuer_cert, apple_root_ca_cert];

    attributes.push(AttributeValue::new(bcder::Captured::from_values(
        bcder::Mode::Der,
        bcder::encode::sequence((
            Oid::from(DigestAlgorithm::Sha256).encode_ref(),
            bcder::OctetString::new(code_directory_slot256.to_vec().into()).encode_ref(),
        )),
    )));

    let signer = signer.signed_attribute(Oid(CD_DIGESTS_OID.as_ref().into()), attributes);

    let mut certs = vec![];
    for cert_str in other_certs {
        certs.push(CapturedX509Certificate::from_pem(cert_str).unwrap());
    }
    let builder = cryptographic_message_syntax::SignedDataBuilder::default()
        .content_type(Oid(OID_ID_DATA.as_ref().into()))
        .signer(signer)
        // .certificate(scert.clone());
        .certificates(certs.into_iter());

    let der = builder.build_der().unwrap();

    let len = der.len();
    println!("{}", len);
    let bas = mybase64::encode(der);

    println!("{}", bas);
}

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

    let pki = PrivateKeyInfo::from_der(my_private_key).unwrap();
    let private_key = rsa::RsaPrivateKey::from_pkcs8_der(my_private_key).unwrap();
    let signer = SigningKey::<Sha256>::new(private_key);

    let issuer_serial_number = IssuerAndSerialNumber {
        issuer: Name::from_der(issuer).unwrap(),
        serial_number: SerialNumber::new(serial_number).unwrap(),
    };

    // let signer = SignerBuilder::new(signing_key, signing_cert.clone())
    //     .message_id_content(main_cd.to_blob_bytes()?)
    //     .signed_attribute_octet_string(
    //         Oid(Bytes::copy_from_slice(CD_DIGESTS_PLIST_OID.as_ref())),
    //         &plist_xml,
    //     );

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
        oid: const_oid::db::rfc5912::ID_CMC_TRANSACTION_ID,
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

fn read_p12() -> (Vec<u8>, CapturedX509Certificate) {
    let password = "1";
    let private_key_pem = fs::read("./iphone.p12").unwrap();
    let store = KeyStore::from_pkcs12(&private_key_pem, password).unwrap();
    let (_, private_key_chain) = store.private_key_chain().unwrap();
    let certificate =
        CapturedX509Certificate::from_der(private_key_chain.chain().first().unwrap().as_der())
            .unwrap();
    (private_key_chain.key().to_vec(), certificate)
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
fn read_public_key() -> CapturedX509Certificate {
    //issuer,serial_number
    let provision_pem = fs::read("./iphone.mobileprovision").unwrap(); //public key公钥在mobileprovision里面，私钥在p12文件里面
    let provision_content = extract_plist_xml(&provision_pem);
    let provision: PlistInfo = plist::from_bytes(&provision_content).unwrap();

    let mut certificate_opt = None;
    for cert in &provision.developer_certificates {
        let cert_data = cert.0.as_bytes(); // utils::base64::decode(cert.0)?;
                                           // let (_, pem2) = parse_x509_pem(&cert_data).map_err(SignError::PEMError)?;
                                           // let (_, certificate) = X509Certificate::from_der(cert_data).unwrap(); //.map_err(SignError::DerError)?; // pem2.parse_x509().map_err(SignError::X509Error)?;
        let certificate = CapturedX509Certificate::from_der(cert_data).unwrap();
        certificate_opt = Some(certificate.clone());
        break;
    }
    certificate_opt.unwrap()
}

fn main() {
    let code_data = vec![0; 20];
    let hashes_plist = vec![1; 20];
    let code_directory_slot256 = vec![2; 32];
    let is_cert = false;
    let (private_key, cert) = read_p12();
    // let public_key = read_public_key();

    // generate_cms(
    //     &hash_data,
    //     &hashes_plist,
    //     &code_directory_slot256,
    //     cert,
    //     &private_key,
    //     &[],
    //     &[],
    // );
    create_cms_signature(
        &code_data,
        &hashes_plist,
        &code_directory_slot256,
        is_cert,
        &private_key,
        &cert,
    );
}
