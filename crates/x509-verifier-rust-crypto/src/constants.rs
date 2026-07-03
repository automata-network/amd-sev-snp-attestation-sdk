// OID

use x509_parser::der_parser::{oid, Oid};

// Key Algo OIDs
pub const OID_KEY_ALGO_EC: Oid = oid!(1.2.840 .10045 .2 .1);
pub const OID_KEY_ALGO_PKCS1_V1_5: Oid = oid!(1.2.840 .113549 .1 .1 .1);

pub const OLD_KEY_ALGO_PARAM_P256: Oid = oid!(1.2.840 .10045 .3 .1 .7);
pub const OLD_KEY_ALGO_PARAM_P384: Oid = oid!(1.3.132 .0 .34);
pub const RSA_PKCS1_V1_5_KEY_OID: &str = "1.2.840.113549.1.1.1";

// Signature Algo OIDs
pub const OID_SIG_ALGO_ECDSA_SHA256: Oid = oid!(1.2.840 .10045 .4 .3 .2);
pub const OID_SIG_ALGO_ECDSA_SHA384: Oid = oid!(1.2.840 .10045 .4 .3 .3);
pub const OID_SIG_ALGO_RSASSA_PSS: Oid = oid!(1.2.840 .113549 .1 .1 .10);
pub const OID_SIG_ALGO_RSA_SHA256: Oid = oid!(1.2.840 .113549 .1 .1 .11);

// Hash Algo OIDs
pub const SHA384_HASH_OID: &str = "2.16.840.1.101.3.4.2.2";
