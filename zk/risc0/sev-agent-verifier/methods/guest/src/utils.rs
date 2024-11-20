use tpm_lib::constants::{TPM_ALG_SHA1, TPM_ALG_SHA256};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ApiOpt {
    Sev,
    SevIma,
    SevTpm
}

impl ApiOpt {
    pub fn from_bytes(raw: u8) -> Self {
        match raw {
            0 => ApiOpt::Sev,
            1 => ApiOpt::SevIma,
            2 => ApiOpt::SevTpm,
            _ => panic!("Unknown ApiOpt"),
        }
    }

    pub fn to_bytes(&self) -> u8 {
        match self {
            ApiOpt::Sev => 0,
            ApiOpt::SevIma => 1,
            ApiOpt::SevTpm => 2
        }
    }
}

#[derive(Debug)]
pub struct Tpm {
    pub quote: Vec<u8>,
    pub signature: Vec<u8>,
    pub pcr10_hash_algo: u16,
    pub pcr10_value: Vec<u8>,
    pub ak_der_chain: Vec<Vec<u8>>,
    pub ek_der_chain: Option<Vec<Vec<u8>>>
}

impl Tpm {
    pub fn from_bytes(raw_tpm_bytes: &[u8]) -> Self {
        let mut offset = 0usize;
        
        let quote_len = u32::from_le_bytes([
            raw_tpm_bytes[0],
            raw_tpm_bytes[1],
            raw_tpm_bytes[2],
            raw_tpm_bytes[3]
        ]) as usize;
        offset += 4;
        
        let mut quote = Vec::with_capacity(quote_len);
        quote.extend_from_slice(&raw_tpm_bytes[offset..offset + quote_len]);
        offset += quote_len;

        let sig_len = u16::from_le_bytes([
            raw_tpm_bytes[offset],
            raw_tpm_bytes[offset + 1]
        ]) as usize;
        offset += 2;

        let mut signature = Vec::with_capacity(sig_len);
        signature.extend_from_slice(&raw_tpm_bytes[offset..offset + sig_len]);
        offset += sig_len;

        let pcr10_hash_algo = u16::from_le_bytes([
            raw_tpm_bytes[offset],
            raw_tpm_bytes[offset + 1]
        ]);
        offset += 2;

        let mut pcr10_value = vec![];
        match pcr10_hash_algo {
            TPM_ALG_SHA1 => {
                pcr10_value.extend_from_slice(&raw_tpm_bytes[offset..offset + 20]);
                offset += 20;
            },
            TPM_ALG_SHA256 => {
                pcr10_value.extend_from_slice(&raw_tpm_bytes[offset..offset + 32]);
                offset += 32;
            },
            _ => panic!("Unknown PCR10 hash algorithm")
        }

        let (ak_der_chain, ak_offset) = get_raw_der_chain_and_offset(
            &raw_tpm_bytes[offset..]
        );
        offset += ak_offset;

        let mut ek_der_chain: Option<Vec<Vec<u8>>> = None;
        if offset < raw_tpm_bytes.len() {
            let (ek_chain, ek_offset) = get_raw_der_chain_and_offset(
                &raw_tpm_bytes[offset..]
            );
            ek_der_chain = Some(ek_chain);
            offset += ek_offset;
        }

        assert!(offset == raw_tpm_bytes.len());

        Tpm {
            quote,
            signature,
            pcr10_hash_algo,
            pcr10_value,
            ak_der_chain,
            ek_der_chain
        }
    }
}

pub fn get_raw_der_chain_and_offset(input: &[u8]) -> (Vec<Vec<u8>>, usize) {
    let mut offset = 0usize;
    let data_count = u32::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ]) as usize;

    let mut data: Vec<Vec<u8>> = Vec::with_capacity(data_count);

    if data_count > 0 {
        offset += 4;
        let mut data_offset = offset + 4 * data_count;
        for _ in 0..data_count {
            let data_len = u32::from_le_bytes([
                input[offset],
                input[offset + 1],
                input[offset + 2],
                input[offset + 3],
            ]) as usize;
            offset += 4;

            let mut element: Vec<u8> = Vec::with_capacity(data_len);
            element.extend_from_slice(&input[data_offset..data_offset + data_len]);
            data_offset += data_len;

            data.push(element);
        }
        offset = data_offset;
    }

    (data, offset)
}