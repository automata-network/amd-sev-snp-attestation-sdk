use super::{ApiOpt, Tpm};

impl Tpm {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ret = Vec::new();

        ret.extend_from_slice(&u32::to_le_bytes(self.quote.len() as u32));
        ret.extend_from_slice(&self.quote);
        ret.extend_from_slice(&u16::to_le_bytes(self.signature.len() as u16));
        ret.extend_from_slice(&self.signature);
        ret.extend_from_slice(&u16::to_le_bytes(self.pcr10_hash_algo));
        ret.extend_from_slice(&self.pcr10_value);
        ret.extend_from_slice(&flatten_der_chain(self.ak_der_chain.clone()));

        if let Some(ek) = self.ek_der_chain.clone() {
            ret.extend_from_slice(&flatten_der_chain(ek));
        }

        ret
    }
}

pub fn serialize_guest_input(
    api_opt: ApiOpt,
    nonce: &[u8],
    raw_sev_attestation: &[u8],
    vek_der_chain: Vec<Vec<u8>>,
    ima_measurement: Option<&str>,
    tpm_pcr10_obj: Option<Tpm>,
) -> Vec<u8> {
    let mut ret = Vec::new();

    ret.extend_from_slice(&[api_opt.to_bytes()]);
    ret.extend_from_slice(&u32::to_le_bytes(nonce.len() as u32));
    ret.extend_from_slice(nonce);
    ret.extend_from_slice(&u32::to_le_bytes(raw_sev_attestation.len() as u32));
    ret.extend_from_slice(raw_sev_attestation);
    ret.extend_from_slice(&flatten_der_chain(vek_der_chain));

    if let Some(ima_str) = ima_measurement {
        let ima_bytes = ima_str.as_bytes();
        let ima_len = ima_bytes.len() as u32;
        ret.extend_from_slice(&u32::to_le_bytes(ima_len));
        ret.extend_from_slice(ima_bytes);
    }

    if let Some(tpm_quote_att) = tpm_pcr10_obj {
        ret.extend_from_slice(&tpm_quote_att.to_bytes());
    }

    ret
}

fn flatten_der_chain(der_chain: Vec<Vec<u8>>) -> Vec<u8> {
    let mut ret = Vec::new();

    let der_count = der_chain.len() as u32;
    ret.extend_from_slice(&der_count.to_le_bytes());

    if der_count > 0 {
        // Get the length of each element
        for d in der_chain.iter() {
            let d_len = d.len() as u32;
            ret.extend_from_slice(&d_len.to_le_bytes());
        }

        let flattened: Vec<u8> = der_chain.into_iter().flatten().collect();
        ret.extend_from_slice(&flattened);
    }

    ret
}
