use p256::ecdsa::{
    signature::Verifier as ECDSASha256Verifier, Signature as P256Signature,
    VerifyingKey as P256VerifyingKey,
};
use p384::ecdsa::{
    signature::hazmat::PrehashVerifier,
    Signature as P384Signature, VerifyingKey as P384VerifyingKey,
};
use rsa::{
    RsaPublicKey,
    pkcs1::DecodeRsaPublicKey,
    pkcs1v15::{Signature as PKCS1v15Signature, VerifyingKey as PKCS1v15VerifyingKey},
    pss::{Signature as PSSSignature, VerifyingKey as PSSVerifyingKey}
};
use sha2::{Digest, Sha256, Sha384};
use x509_parser::der_parser::{ber::BerObjectContent, der::parse_der};

enum ECKeyType {
    P256,
    P384,
}

enum ECDSADigestHash {
    Sha256ECDSA,
    Sha384ECDSA,
}

pub fn verify_p256_sha256(tbs: &[u8], der_encoded_sig: &[u8], signer_pub_key: &[u8]) -> bool {
    ecdsa_verify(
        ECKeyType::P256,
        ECDSADigestHash::Sha256ECDSA,
        tbs,
        der_encoded_sig,
        signer_pub_key,
    )
}

pub fn verify_p384_sha256(tbs: &[u8], der_encoded_sig: &[u8], signer_pub_key: &[u8]) -> bool {
    ecdsa_verify(
        ECKeyType::P384,
        ECDSADigestHash::Sha256ECDSA,
        tbs,
        der_encoded_sig,
        signer_pub_key,
    )
}

pub fn verify_p384_sha384(tbs: &[u8], der_encoded_sig: &[u8], signer_pub_key: &[u8]) -> bool {
    ecdsa_verify(
        ECKeyType::P384,
        ECDSADigestHash::Sha384ECDSA,
        tbs,
        der_encoded_sig,
        signer_pub_key,
    )
}

pub fn verify_pkcs1_rsa_sha256(tbs: &[u8], sig: &[u8], der_encoded_signer_pub_key: &[u8]) -> bool {
    let pub_key = RsaPublicKey::from_pkcs1_der(der_encoded_signer_pub_key).unwrap();
    let verifying_key: PKCS1v15VerifyingKey<Sha256> = PKCS1v15VerifyingKey::new(pub_key);
    let signature = PKCS1v15Signature::try_from(sig).unwrap();
    verifying_key.verify(&tbs, &signature).is_ok()
}

pub fn verify_pss_pkcs1_mgf_rsa_sha384(tbs: &[u8], sig: &[u8], der_encoded_signer_pub_key: &[u8]) -> bool  {
    let pub_key = RsaPublicKey::from_pkcs1_der(der_encoded_signer_pub_key).unwrap();
    let verifying_key: PSSVerifyingKey<Sha384> = PSSVerifyingKey::new(pub_key);
    let signature = PSSSignature::try_from(sig).unwrap();
    verifying_key.verify(&tbs, &signature).is_ok()
}

fn ecdsa_verify(
    signer_key_type: ECKeyType,
    digest_hash_algo: ECDSADigestHash,
    tbs: &[u8],
    der_encoded_sig: &[u8],
    signer_pub_key: &[u8],
) -> bool {
    // Parse the signature
    let parsed_sig = process_sig(der_encoded_sig);

    match signer_key_type {
        ECKeyType::P256 => {
            if matches!(digest_hash_algo, ECDSADigestHash::Sha384ECDSA) {
                panic!("incompatible sig algo");
            }
            let verifying_key: P256VerifyingKey =
                P256VerifyingKey::from_sec1_bytes(&signer_pub_key).unwrap();
            let signature = P256Signature::from_slice(&parsed_sig).unwrap();
            verifying_key.verify(tbs, &signature).is_ok()
        }
        ECKeyType::P384 => {
            let verifying_key: P384VerifyingKey =
                P384VerifyingKey::from_sec1_bytes(&signer_pub_key).unwrap();
            let signature = P384Signature::from_slice(&parsed_sig).unwrap();
            if matches!(digest_hash_algo, ECDSADigestHash::Sha256ECDSA) {
                let digest = Sha256::digest(&tbs);
                verifying_key.verify_prehash(&digest, &signature).is_ok()
            } else {
                verifying_key.verify(tbs, &signature).is_ok()
            }
        }
    }
}

fn process_sig(der_encoded_sig: &[u8]) -> Vec<u8> {
    let decoded = parse_der(der_encoded_sig).unwrap().1.content;
    let mut ret: Vec<u8> = Vec::new();

    match decoded {
        BerObjectContent::Sequence(sig_obj) => {
            // ECDSA
            for v in sig_obj.iter() {
                let mut sig_slice = v.as_biguint().unwrap().to_bytes_be();
                ret.append(&mut sig_slice);
            }
        }
        _ => {
            panic!("DER is not of SEQUENCE type")
        }
    }

    ret
}
