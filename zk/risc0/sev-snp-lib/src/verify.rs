use x509_verifier_rust_crypto::x509_parser::oid_registry::asn1_rs::{oid, Oid};
use x509_verifier_rust_crypto::x509_parser::prelude::{X509Certificate, X509Extension, X509Name};
use x509_verifier_rust_crypto::p384::ecdsa::{
    signature::Verifier,
    Signature,
    VerifyingKey
};

use super::attestation::AttestationReport;
use super::types::CertType;

const BOOTLOADER_OID: Oid = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .1);
const TEE_OID: Oid = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .2);
const SNP_OID: Oid = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .3);
const UCODE_OID: Oid = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .8);
const HWID_OID: Oid = oid!(1.3.6 .1 .4 .1 .3704 .1 .4);

const VCEK_SUBJECT_CN: &str = "SEV-VCEK";
const VLEK_SUBJECT_CN: &str = "SEV-VLEK";

pub fn verify_attestation_signature(
    vek_cert: &X509Certificate,
    report: &AttestationReport
) -> bool {
    let tbs = report.tbs;
    let pubkey = vek_cert.public_key().subject_public_key.as_ref();

    match report.sig_algo {
        1 => {
            // P384 ECDSA

            let mut big_endian_r = report.signature.r.clone();
            big_endian_r.reverse();

            let mut big_endian_s = report.signature.s.clone();
            big_endian_s.reverse();

            let mut sig_slice: Vec<u8> = Vec::with_capacity(96);
            sig_slice.extend_from_slice(&big_endian_r[24..]);
            sig_slice.extend_from_slice(&big_endian_s[24..]);

            let verifying_key = VerifyingKey::from_sec1_bytes(&pubkey).unwrap();
            let signature = Signature::from_slice(&sig_slice).unwrap();

            verifying_key.verify(&tbs, &signature).is_ok()
        },
        _ => {
            panic!("Unsupported sig algo");
        }
    }
}

pub fn verify_attestation_tcb(
    vek_type: CertType,
    vek_cert: &X509Certificate,
    report: &AttestationReport,
) -> bool {
    let extensions = vek_cert.extensions_map().unwrap();

    let common_name_is_valid = check_common_name(vek_type, vek_cert.subject());
    if !common_name_is_valid {
        panic!("Unrecognized VEK Cert Subject Name");
    }

    // Check bootloaders
    if let Some(cert_bl) = extensions.get(&BOOTLOADER_OID) {
        if !check_cert_bytes(cert_bl, &report.reported_tcb.bootloader.to_le_bytes()) {
            panic!("Attestation Report TCB Boot Loader and Certificate Boot Loader do not match!");
        }
    }

    // Check TEE information
    if let Some(cert_tee) = extensions.get(&TEE_OID) {
        if !check_cert_bytes(cert_tee, &report.reported_tcb.tee.to_le_bytes()) {
            panic!("Attestation Report TCB TEE and Certificate TEE do not match!");
        }
    }

    // Check SNP information
    if let Some(cert_snp) = extensions.get(&SNP_OID) {
        if !check_cert_bytes(cert_snp, &report.reported_tcb.snp.to_le_bytes()) {
            panic!("Attestation Report TCB SNP and Certificate SNP do not match!");
        }
    }

    // Check Microcode information
    if let Some(cert_ucode) = extensions.get(&UCODE_OID) {
        if !check_cert_bytes(cert_ucode, &report.reported_tcb.microcode.to_le_bytes()) {
            panic!("Attestation Report TCB Microcode and Certificate Microcode do not match!");
        }
    }

    // Check HWID information (only for VCEK)
    if vek_type == CertType::VCEK {
        if let Some(cert_hwid) = extensions.get(&HWID_OID) {
            if !check_cert_bytes(cert_hwid, &report.chip_id) {
                panic!("Attestation Report TCB ID and Certificate ID do not match!");
            }
        }
    }

    true
}

fn check_common_name(vek_type: CertType, subject: &X509Name) -> bool {
    let subject_cn = subject.iter_common_name().next().unwrap().as_str().unwrap();
    let ret: bool;
    match vek_type {
        CertType::VCEK => ret = subject_cn == VCEK_SUBJECT_CN,
        CertType::VLEK => ret = subject_cn == VLEK_SUBJECT_CN,
        _ => panic!("Not a valid VEK Cert Type"),
    };
    ret
}

/// Check the cert extension byte to value
fn check_cert_bytes(ext: &X509Extension, val: &[u8]) -> bool {
    match ext.value[0] {
        // Integer
        0x2 => {
            if ext.value[1] != 0x1 && ext.value[1] != 0x2 {
                panic!("check_cert_bytes: Invalid integer encountered!");
            } else if let Some(byte_value) = ext.value.last() {
                return byte_value == &val[0];
            } else {
                return false;
            }
        }
        // Octet String
        0x4 => {
            if ext.value[1] != 0x40 {
                panic!("check_cert_bytes: Invalid octet length encountered!");
            }
            if ext.value[2..].len() != 0x40 {
                panic!("check_cert_bytes: Invalid number of bytes encountered!");
            }
            if val.len() != 0x40 {
                panic!("check_cert_bytes: Invalid certificate harward id length encountered!");
            }

            return &ext.value[2..] == val;
        }
        // Legacy and others.
        _ => {
            // Old VCEK without x509 DER encoding, might be deprecated in the future.
            if ext.value.len() == 0x40 && val.len() == 0x40 {
                return ext.value == val;
            }
        }
    }
    panic!("check_cert_bytes: Invalid type encountered!");
}
