use crate::constants::*;
use anyhow::anyhow;
use oid::ObjectIdentifier;
use p256::ecdsa::{
    signature::Verifier as ECDSASha256Verifier, Signature as P256Signature,
    VerifyingKey as P256VerifyingKey,
};
use p384::ecdsa::{
    signature::hazmat::PrehashVerifier, Signature as P384Signature,
    VerifyingKey as P384VerifyingKey,
};
use rsa::{
    pkcs1::DecodeRsaPublicKey,
    pkcs1v15::{Signature as PKCS1v15Signature, VerifyingKey as PKCS1v15VerifyingKey},
    pss::{Signature as PSSSignature, VerifyingKey as PSSVerifyingKey},
    RsaPublicKey,
};
use sha2::{Digest, Sha256, Sha384};
use x509_parser::der_parser::Oid;
use x509_parser::{
    der_parser::{ber::BerObjectContent, der::parse_der},
    x509::AlgorithmIdentifier,
};

#[derive(Debug, PartialEq, Clone)]
pub struct PubKey<'a> {
    pub algo: KeyAlgo,
    pub val: &'a [u8],
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum KeyAlgoParams {
    P256,
    P384,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum KeyAlgo {
    ECDSA(KeyAlgoParams),
    RSA,
}

impl KeyAlgo {
    pub fn from_algo(algo: &AlgorithmIdentifier) -> anyhow::Result<Self> {
        if algo.oid() == &OID_KEY_ALGO_EC {
            let Some(key_params) = &algo.parameters else {
                return Err(anyhow!("ECDSA public key parameters are missing"));
            };
            let param_oid = ObjectIdentifier::try_from(key_params.data).map_err(|err| {
                anyhow!("Failed to parse ECDSA public key parameters OID: {:?}", err)
            })?;
            let param_oid: String = param_oid.into();
            let key_params = if param_oid == OLD_KEY_ALGO_PARAM_P256.to_string() {
                KeyAlgoParams::P256
            } else if param_oid == OLD_KEY_ALGO_PARAM_P384.to_string() {
                KeyAlgoParams::P384
            } else {
                return Err(anyhow!(
                    "Unsupported ECDSA key parameter OID: {}",
                    param_oid
                ));
            };
            Ok(Self::ECDSA(key_params))
        } else if algo.oid() == &OID_KEY_ALGO_PKCS1_V1_5 {
            Ok(KeyAlgo::RSA)
        } else {
            Err(anyhow!("Invalid algo: {:?}", algo))
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SigAlgo {
    EcdsaSHA256,
    EcdsaSHA384,
    RsaSSAPSS,
    RsaSHA256,
}

impl SigAlgo {
    pub fn from_oid(oid: &Oid) -> anyhow::Result<Self> {
        if oid == &OID_SIG_ALGO_ECDSA_SHA256 {
            Ok(SigAlgo::EcdsaSHA256)
        } else if oid == &OID_SIG_ALGO_ECDSA_SHA384 {
            Ok(SigAlgo::EcdsaSHA384)
        } else if oid == &OID_SIG_ALGO_RSASSA_PSS {
            Ok(SigAlgo::RsaSSAPSS)
        } else if oid == &OID_SIG_ALGO_RSA_SHA256 {
            Ok(SigAlgo::RsaSHA256)
        } else {
            Err(anyhow!("invalid sig oid: {:?}", oid.to_id_string()))
        }
    }

    pub fn check_compatible_with(self, key_algo: KeyAlgo) -> anyhow::Result<()> {
        match (self, key_algo) {
            (SigAlgo::EcdsaSHA256, KeyAlgo::ECDSA(KeyAlgoParams::P256)) => Ok(()),
            (SigAlgo::EcdsaSHA256, KeyAlgo::ECDSA(KeyAlgoParams::P384)) => Ok(()),
            (SigAlgo::EcdsaSHA384, KeyAlgo::ECDSA(KeyAlgoParams::P384)) => Ok(()),
            (SigAlgo::RsaSHA256, KeyAlgo::RSA) => Ok(()),
            (SigAlgo::RsaSSAPSS, KeyAlgo::RSA) => Ok(()),
            _ => Err(anyhow!(
                "Incompatible key and signature algorithm, issuer_pubkey: {:?}, subject_sig: {:?}",
                key_algo,
                self,
            )),
        }
    }
}

pub fn ec_decode_sig(sig: &[u8], params: KeyAlgoParams) -> anyhow::Result<Vec<u8>> {
    let (_, decoded) = parse_der(sig).map_err(|err| anyhow!("decode der failed: {:?}", err))?;
    let mut ret: Vec<u8> = Vec::new();

    let expected_len = match params {
        KeyAlgoParams::P256 => 32usize,
        KeyAlgoParams::P384 => 48usize,
    };

    match decoded.content {
        BerObjectContent::Sequence(sig_obj) => {
            // ECDSA
            for v in sig_obj.iter() {
                let mut sig_slice = v.as_biguint().unwrap().to_bytes_be();
                sig_slice = pad_zero_to_length(sig_slice, expected_len);
                if sig_slice.len() != expected_len {
                    return Err(anyhow!(
                        "decode ec sig failed: does not match expected length, want: {}, got: {}",
                        expected_len,
                        sig_slice.len()
                    ));
                }
                ret.append(&mut sig_slice);
            }
        }
        content => return Err(anyhow!("DER is not of SEQUENCE type: {:?}", content)),
    }

    Ok(ret)
}

pub fn verify_signature(
    pubkey: PubKey,
    sig_algo: SigAlgo,
    sig: &[u8],
    msg: &[u8],
) -> anyhow::Result<bool> {
    // println!("pubkey: {:?}, sig: {:?}", pubkey.algo, sig_algo);
    let result = match (pubkey.algo, sig_algo) {
        (KeyAlgo::ECDSA(KeyAlgoParams::P256), SigAlgo::EcdsaSHA256) => {
            let verifying_key = P256VerifyingKey::from_sec1_bytes(pubkey.val)
                .map_err(|err| anyhow!("parse verifying key failed: {}", err))?;
            let signature = P256Signature::from_slice(&sig)
                .map_err(|err| anyhow!("parse signature failed: {}", err))?;
            verifying_key.verify(msg, &signature).is_ok()
        }
        (KeyAlgo::ECDSA(KeyAlgoParams::P384), SigAlgo::EcdsaSHA256) => {
            let verifying_key: P384VerifyingKey =
                P384VerifyingKey::from_sec1_bytes(pubkey.val).unwrap();
            let signature = P384Signature::from_slice(&sig)
                .map_err(|err| anyhow!("parse p384 signature failed: {:?}", err))?;
            let digest = Sha256::digest(msg);
            verifying_key.verify_prehash(&digest, &signature).is_ok()
        }
        (KeyAlgo::ECDSA(KeyAlgoParams::P384), SigAlgo::EcdsaSHA384) => {
            let verifying_key = P384VerifyingKey::from_sec1_bytes(pubkey.val)
                .map_err(|err| anyhow!("parse verifying key failed: {}", err))?;
            let signature = P384Signature::from_slice(&sig)
                .map_err(|err| anyhow!("parse p384 signature failed: {:?}", err))?;
            verifying_key.verify(msg, &signature).is_ok()
        }
        (KeyAlgo::RSA, SigAlgo::RsaSHA256) => {
            let pub_key = RsaPublicKey::from_pkcs1_der(pubkey.val)
                .map_err(|err| anyhow!("parse verifying key failed: {}", err))?;
            let verifying_key = <PKCS1v15VerifyingKey<Sha256>>::new(pub_key);
            let signature = PKCS1v15Signature::try_from(sig).unwrap();
            verifying_key.verify(msg, &signature).is_ok()
        }
        (KeyAlgo::RSA, SigAlgo::RsaSSAPSS) => {
            let pub_key = RsaPublicKey::from_pkcs1_der(pubkey.val).unwrap();
            let verifying_key: PSSVerifyingKey<Sha384> = PSSVerifyingKey::new(pub_key);
            let signature = PSSSignature::try_from(sig).unwrap();
            verifying_key.verify(msg, &signature).is_ok()
        }
        _ => {
            return Err(anyhow!(
                "Incompatible key and signature algorithm, key: {:?}, sig: {:?}",
                pubkey.algo,
                sig_algo,
            ))
        }
    };
    Ok(result)
}

pub(crate) fn pad_zero_to_length(input: Vec<u8>, expected_length: usize) -> Vec<u8> {
    if input.len() < expected_length {
        let padding = expected_length - input.len();
        let mut padded = vec![0; padding];
        padded.extend(input);
        padded
    } else {
        input
    }
}
