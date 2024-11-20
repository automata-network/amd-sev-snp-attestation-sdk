// Reference manual: https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
use crate::constants::{TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE};

const CLOCK_LEN: usize = 17;

pub trait FromBytes {
    fn from_bytes(raw: &[u8]) -> Self;
}

// Table 122
#[derive(Debug)]
pub struct TPMSAttest {
    pub magic: u32,
    pub att_type: u16,
    pub qualified_signer: Vec<u8>,
    pub extra_data: Vec<u8>,
    pub tpms_clock_info: ClockInfo,
    pub firmware_version: u64,
    pub attested: TPMUAttest
}
impl FromBytes for TPMSAttest {
    fn from_bytes(raw_attest: &[u8]) -> Self {
        let magic = u32::from_be_bytes([
            raw_attest[0],
            raw_attest[1],
            raw_attest[2],
            raw_attest[3]
        ]);

        assert!(magic == TPM_GENERATED_VALUE, "Invalid magic value");

        let att_type = u16::from_be_bytes([
            raw_attest[4],
            raw_attest[5]
        ]);

        let qualified_signer_len = u16::from_be_bytes([
            raw_attest[6],
            raw_attest[7]
        ]) as usize;
        let mut offset = 8usize;
        let mut qualified_signer: Vec<u8> = Vec::with_capacity(qualified_signer_len);
        qualified_signer.extend_from_slice(&raw_attest[offset..offset + qualified_signer_len]);
        offset += qualified_signer_len;

        let extra_data_len = u16::from_be_bytes([
            raw_attest[offset],
            raw_attest[offset + 1]
        ]) as usize;
        offset += 2;
        let mut extra_data: Vec<u8> = Vec::with_capacity(extra_data_len);
        extra_data.extend_from_slice(&raw_attest[offset..offset + extra_data_len]);
        offset += extra_data_len;

        let clock_info_slice = &raw_attest[offset..offset + CLOCK_LEN];
        let tpms_clock_info = ClockInfo::from_bytes(clock_info_slice);
        offset += CLOCK_LEN;

        let firmware_version = u64::from_be_bytes([
            raw_attest[offset],
            raw_attest[offset + 1],
            raw_attest[offset + 2],
            raw_attest[offset + 3],
            raw_attest[offset + 4],
            raw_attest[offset + 5],
            raw_attest[offset + 6],
            raw_attest[offset + 7]
        ]);
        offset += 8;

        let attested = match att_type {
            TPM_ST_ATTEST_QUOTE => {
                let tpms_quote_info = TPMSQuoteInfo::from_bytes(&raw_attest[offset..]);
                TPMUAttest::Quote(tpms_quote_info)
            },
            _ => panic!("Unsupported attested type")
        };

        TPMSAttest {
            magic,
            att_type,
            qualified_signer,
            extra_data,
            tpms_clock_info,
            firmware_version,
            attested
        }
    }
}

// 10.11.1
#[derive(Debug)]
pub struct ClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: bool
}
impl FromBytes for ClockInfo {
    fn from_bytes(raw_clock_info: &[u8]) -> Self {
        assert!(raw_clock_info.len() == CLOCK_LEN, "Incorrect TPMS_CLOCK_INFO length");
        let clock = u64::from_be_bytes([
            raw_clock_info[0],
            raw_clock_info[1],
            raw_clock_info[2],
            raw_clock_info[3],
            raw_clock_info[4],
            raw_clock_info[5],
            raw_clock_info[6],
            raw_clock_info[7],
        ]);
        let reset_count = u32::from_be_bytes([
            raw_clock_info[8],
            raw_clock_info[9],
            raw_clock_info[10],
            raw_clock_info[11]
        ]);
        let restart_count = u32::from_be_bytes([
            raw_clock_info[12],
            raw_clock_info[13],
            raw_clock_info[14],
            raw_clock_info[15]
        ]);
        let safe = match raw_clock_info[16] {
            0 => false,
            1 => true,
            _ => panic!("Invalid bool value")
        };

        ClockInfo {
            clock,
            reset_count,
            restart_count,
            safe
        }
    }
}

// 10.12.7
#[derive(Debug)]
pub enum TPMUAttest {
    Quote(TPMSQuoteInfo)
}

// 10.12.1
#[derive(Debug)]
pub struct TPMSQuoteInfo {
    // TPML_PCR_SELECTION is defined here rather than its own struct
    pub count: u32,
    pub pcr_selections: Vec<TPMSPCRSelection>,
    pub pcr_digest: Vec<u8>
}
impl FromBytes for TPMSQuoteInfo {
    fn from_bytes(raw_tpms_quote_info: &[u8]) -> Self {
        let count = u32::from_be_bytes([
            raw_tpms_quote_info[0],
            raw_tpms_quote_info[1],
            raw_tpms_quote_info[2],
            raw_tpms_quote_info[3]
        ]);

        // TODO: support multiple PCRSelections
        assert!(count == 1, "Currently does not support more than one PCRSelections");
        let mut pcr_selections: Vec<TPMSPCRSelection> = Vec::with_capacity(count as usize);
        let pcr_selection = TPMSPCRSelection::from_bytes(&raw_tpms_quote_info[4..]);
        let offset = 4usize + pcr_selection.size();
        pcr_selections.push(pcr_selection);

        let pcr_digest_slice = &raw_tpms_quote_info[offset..];
        let pcr_digest_size = u16::from_be_bytes([
            pcr_digest_slice[0],
            pcr_digest_slice[1]
        ]) as usize;
        let mut pcr_digest: Vec<u8> = Vec::with_capacity(pcr_digest_size as usize);
        pcr_digest.extend_from_slice(&pcr_digest_slice[2..2 + pcr_digest_size]);

        TPMSQuoteInfo {
            count,
            pcr_selections,
            pcr_digest
        }
    }
}


// 10.6.2
#[derive(Debug)]
pub struct TPMSPCRSelection {
    pub hash: u16,
    pub size_of_select: u8,
    pub pcr_select: Vec<u8>
}
impl FromBytes for TPMSPCRSelection {
    fn from_bytes(raw_tpms_pcr_selection: &[u8]) -> Self {
        let hash = u16::from_be_bytes([
            raw_tpms_pcr_selection[0],
            raw_tpms_pcr_selection[1]
        ]);

        let size_of_select = raw_tpms_pcr_selection[2];

        let mut pcr_select: Vec<u8> = Vec::with_capacity(size_of_select as usize);
        pcr_select.extend_from_slice(&raw_tpms_pcr_selection[3..3 + size_of_select as usize]);

        TPMSPCRSelection {
            hash,
            size_of_select,
            pcr_select
        }
    }
}
impl TPMSPCRSelection {
    pub fn size(&self) -> usize {
        (3 + self.size_of_select) as usize
    }

    // TODO: I need to figure out exactly how does TPM2 encode multiple PCRSelections
    // pub fn get_pcr_selections_arr(raw_tpms_pcr_selection_arr: &[u8]) -> Vec<Self> {
    //     let mut offset = 0usize;
    //     let mut ret: Vec<Self> = vec![];
    //     while offset < raw_tpms_pcr_selection_arr.len() {
    //         let current_selection = TPMSPCRSelection::from_bytes(&raw_tpms_pcr_selection_arr[offset..]);
    //         offset += current_selection.size();
    //         ret.push(current_selection);
    //     }
    //     ret
    // }

    // pub fn get_pcr_selection_arr_bytes_len(tpms_pcr_selections_arr: &[Self]) -> usize {
    //     let mut size = 0usize;
    //     for selection in tpms_pcr_selections_arr.iter() {
    //         size += selection.size()
    //     }
    //     size
    // }
}