// Reference manual: https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf

// Table 9
pub const TPM_ALG_SHA1: u16 = 0x0004;
pub const TPM_ALG_SHA256: u16 = 0x000b;

// Table 7
pub const TPM_GENERATED_VALUE: u32 = 0xff544347;
// Table 19
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

pub const CA_ISSUERS_OID: &str = "1.3.6.1.5.5.7.48.2";
