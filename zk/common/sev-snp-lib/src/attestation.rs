// Modified from https://docs.rs/sev/latest/sev/firmware/guest/struct.AttestationReport.html
// Ref: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf (Table 22)

use super::types::CertType;
use std::fmt::{Display, Formatter, Result};

const REPORT_SIZE: usize = 1184;
const TCB_VERSION_SIZE: usize = 8;
const SIGNATURE_SIZE: usize = 512;
const R_S_SIZE: usize = 144;

#[derive(Debug, Clone, Copy)]
pub struct AttestationReport {
    /// Version number of this attestation report. Set to 2h for this specification.
    pub version: u32,
    /// The guest SVN.
    pub guest_svn: u32,
    /// The guest policy.
    pub guest_policy_raw: [u8; 8],
    /// The family ID provided at launch.
    pub family_id: [u8; 16],
    /// The image ID provided at launch.
    pub image_id: [u8; 16],
    /// The request VMPL for the attestation report.
    pub vmpl: u32,
    /// The signature algorithm used to sign this report.
    pub sig_algo: u32,
    /// Current TCB. See SNPTcbVersion
    pub current_tcb: TcbVersion,
    /// Information about the platform. See PlatformInfo
    pub plat_info_raw: [u8; 8],
    /// Private variable as only the first bit is important.
    /// See [`AttestationReport::_author_key_en`].
    author_key_en: u32,
    _reserved_0: u32,
    /// Guest-provided 512 Bits of Data
    pub report_data: [u8; 64],
    /// The measurement calculated at launch.
    pub measurement: [u8; 48],
    /// Data provided by the hypervisor at launch.
    pub host_data: [u8; 32],
    /// SHA-384 digest of the ID public key that signed the ID block provided
    /// in SNP_LANUNCH_FINISH.
    pub id_key_digest: [u8; 48],
    /// SHA-384 digest of the Author public key that certified the ID key,
    /// if provided in SNP_LAUNCH_FINSIH. Zeroes if AUTHOR_KEY_EN is 1.
    pub author_key_digest: [u8; 48],
    /// Report ID of this guest.
    pub report_id: [u8; 32],
    /// Report ID of this guest's migration agent (if applicable).
    pub report_id_ma: [u8; 32],
    /// Reported TCB version used to derive the VCEK that signed this report.
    pub reported_tcb: TcbVersion,
    _reserved_1: [u8; 24],
    /// If MaskChipId is set to 0, Identifier unique to the chip.
    /// Otherwise set to 0h.
    pub chip_id: [u8; 64],
    /// CommittedTCB
    pub committed_tcb: TcbVersion,
    /// The build number of CurrentVersion
    pub current_build: u8,
    /// The minor number of CurrentVersion
    pub current_minor: u8,
    /// The major number of CurrentVersion
    pub current_major: u8,
    _reserved_2: u8,
    /// The build number of CommittedVersion
    pub committed_build: u8,
    /// The minor number of CommittedVersion
    pub committed_minor: u8,
    /// The major number of CommittedVersion
    pub committed_major: u8,
    _reserved_3: u8,
    /// The CurrentTcb at the time the guest was launched or imported.
    pub launch_tcb: TcbVersion,
    _reserved_4: [u8; 168],
    /// Signature of bytes 0 to 0x29F inclusive of this report.
    /// The format of the signature is found within Signature.
    pub signature: Signature,

    // TEMP: I think it would be great,
    // if I can simply pull the tbs value directly from memory.
    // since the tbs is just a substring of the raw_attestation_report
    // occupies the first 672 bytes
    pub tbs: [u8; 672],
}

impl AttestationReport {
    pub fn from_bytes(raw_report: &[u8]) -> AttestationReport {
        assert!(
            raw_report.len() == REPORT_SIZE,
            "Provided data length is incorrect"
        );

        let mut guest_policy_raw = [0u8; 8];
        guest_policy_raw.copy_from_slice(&raw_report[8..16]);

        let mut family_id = [0u8; 16];
        family_id.copy_from_slice(&raw_report[16..32]);

        let mut image_id = [0u8; 16];
        image_id.copy_from_slice(&raw_report[32..48]);

        let mut current_tcb_raw = [0u8; 8];
        current_tcb_raw.copy_from_slice(&raw_report[56..64]);

        let mut plat_info_raw = [0u8; 8];
        plat_info_raw.copy_from_slice(&raw_report[64..72]);

        let mut report_data = [0u8; 64];
        report_data.copy_from_slice(&raw_report[80..144]);

        let mut measurement = [0u8; 48];
        measurement.copy_from_slice(&raw_report[144..192]);

        let mut host_data = [0u8; 32];
        host_data.copy_from_slice(&raw_report[192..224]);

        let mut id_key_digest = [0u8; 48];
        id_key_digest.copy_from_slice(&raw_report[224..272]);

        let mut author_key_digest = [0u8; 48];
        author_key_digest.copy_from_slice(&raw_report[272..320]);

        let mut report_id = [0u8; 32];
        report_id.copy_from_slice(&raw_report[320..352]);

        let mut report_id_ma = [0u8; 32];
        report_id_ma.copy_from_slice(&raw_report[352..384]);

        let mut reported_tcb_raw = [0u8; 8];
        reported_tcb_raw.copy_from_slice(&raw_report[384..392]);

        let mut reserved_1 = [0u8; 24];
        reserved_1.copy_from_slice(&raw_report[392..416]);

        let mut chip_id = [0u8; 64];
        chip_id.copy_from_slice(&raw_report[416..480]);

        let mut committed_tcb_raw = [0u8; 8];
        committed_tcb_raw.copy_from_slice(&raw_report[480..488]);

        let mut launch_tcb_raw = [0u8; 8];
        launch_tcb_raw.copy_from_slice(&raw_report[496..504]);

        let mut reserved_4 = [0u8; 168];
        reserved_4.copy_from_slice(&raw_report[504..672]);

        let mut signature_raw = [0u8; 512];
        signature_raw.copy_from_slice(&raw_report[672..1184]);

        let mut tbs = [0u8; 672];
        tbs.copy_from_slice(&raw_report[0..672]);

        AttestationReport {
            version: u32::from_le_bytes([
                raw_report[0],
                raw_report[1],
                raw_report[2],
                raw_report[3],
            ]),
            guest_svn: u32::from_le_bytes([
                raw_report[4],
                raw_report[5],
                raw_report[6],
                raw_report[7],
            ]),
            guest_policy_raw,
            family_id,
            image_id,
            vmpl: u32::from_le_bytes([
                raw_report[48],
                raw_report[49],
                raw_report[50],
                raw_report[51],
            ]),
            sig_algo: u32::from_le_bytes([
                raw_report[52],
                raw_report[53],
                raw_report[54],
                raw_report[55],
            ]),
            current_tcb: TcbVersion::from_bytes(&current_tcb_raw),
            plat_info_raw,
            author_key_en: u32::from_le_bytes([
                raw_report[72],
                raw_report[73],
                raw_report[74],
                raw_report[75],
            ]),
            _reserved_0: u32::from_le_bytes([
                raw_report[76],
                raw_report[77],
                raw_report[78],
                raw_report[79],
            ]),
            report_data,
            measurement,
            host_data,
            id_key_digest,
            author_key_digest,
            report_id,
            report_id_ma,
            reported_tcb: TcbVersion::from_bytes(&reported_tcb_raw),
            _reserved_1: reserved_1,
            chip_id,
            committed_tcb: TcbVersion::from_bytes(&committed_tcb_raw),
            current_build: raw_report[488],
            current_minor: raw_report[489],
            current_major: raw_report[490],
            _reserved_2: raw_report[491],
            committed_build: raw_report[492],
            committed_minor: raw_report[493],
            committed_major: raw_report[494],
            _reserved_3: raw_report[495],
            launch_tcb: TcbVersion::from_bytes(&launch_tcb_raw),
            _reserved_4: reserved_4,
            signature: Signature::from_bytes(&signature_raw),
            tbs,
        }
    }

    pub fn get_signing_cert_type(&self) -> CertType {
        let slice = self.author_key_en.to_le_bytes();
        let bits = slice[0];
        let signer_type = bits & 0b11100;
        if signer_type == 0b000 {
            return CertType::VCEK;
        } else if signer_type == 0b100 {
            return CertType::VLEK;
        }

        CertType::Empty
    }

    fn author_key_en(&self) -> bool {
        self.author_key_en == 1
    }
}

impl Display for AttestationReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"
Attestation Report ({} bytes):
Version:                      {}
Guest SVN:                    {}
Family ID:                    {}
Image ID:                     {}
VMPL:                         {}
Signature Algorithm:          {}
Current TCB:
{}
Author Key Encryption:        {}
Report Data:                  {}
Measurement:                  {}
Host Data:                    {}
ID Key Digest:                {}
Author Key Digest:            {}
Report ID:                    {}
Report ID Migration Agent:    {}
Reported TCB:                 
{}
Chip ID:                      {}
Committed TCB:
{}
Current Build:                {}
Current Minor:                {}
Current Major:                {}
Committed Build:              {}
Committed Minor:              {}
Committed Major:              {}
Launch TCB:
{}
Signing Cert Type:
{:?}
{}
"#,
            std::mem::size_of_val(self) - 672, // To exclude the tbs value in the object
            self.version,
            self.guest_svn,
            hex::encode(&self.family_id),
            hex::encode(&self.image_id),
            self.vmpl,
            self.sig_algo,
            self.current_tcb,
            self.author_key_en(),
            hex::encode(self.report_data),
            hex::encode(self.measurement),
            hex::encode(self.host_data),
            hex::encode(self.id_key_digest),
            hex::encode(self.author_key_digest),
            hex::encode(self.report_id),
            hex::encode(self.report_id_ma),
            self.reported_tcb,
            hex::encode(self.chip_id),
            self.committed_tcb,
            self.current_build,
            self.current_minor,
            self.current_major,
            self.committed_build,
            self.committed_minor,
            self.committed_major,
            self.launch_tcb,
            self.get_signing_cert_type(),
            self.signature
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TcbVersion {
    /// Current bootloader version.
    /// SVN of PSP bootloader.
    pub bootloader: u8,
    /// Current PSP OS version.
    /// SVN of PSP operating system.
    pub tee: u8,
    _reserved: [u8; 4],
    /// Version of the SNP firmware.
    /// Security Version Number (SVN) of SNP firmware.
    pub snp: u8,
    /// Lowest current patch level of all the cores.
    pub microcode: u8,
}

impl TcbVersion {
    pub fn new(bootloader: u8, tee: u8, snp: u8, microcode: u8) -> Self {
        TcbVersion {
            bootloader,
            tee,
            _reserved: [0u8; 4],
            snp,
            microcode,
        }
    }

    pub fn from_bytes(raw_tcb: &[u8; TCB_VERSION_SIZE]) -> Self {
        let mut reserved = [0u8; 4];
        reserved.copy_from_slice(&raw_tcb[2..6]);

        TcbVersion {
            bootloader: raw_tcb[0],
            tee: raw_tcb[1],
            _reserved: reserved,
            snp: raw_tcb[6],
            microcode: raw_tcb[7],
        }
    }
}

impl Display for TcbVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"
TCB Version:
  Microcode:   {}
  SNP:         {}
  TEE:         {}
  Boot Loader: {}
  "#,
            self.microcode, self.snp, self.tee, self.bootloader
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Signature {
    pub r: [u8; 72],
    pub s: [u8; 72],
    _reserved: [u8; SIGNATURE_SIZE - R_S_SIZE],
}

impl Signature {
    pub fn from_bytes(raw_signature: &[u8; SIGNATURE_SIZE]) -> Signature {
        let mut r = [0u8; 72];
        r.copy_from_slice(&raw_signature[0..72]);

        let mut s = [0u8; 72];
        s.copy_from_slice(&raw_signature[72..144]);

        let mut reserved = [0u8; SIGNATURE_SIZE - R_S_SIZE];
        reserved.copy_from_slice(&raw_signature[144..raw_signature.len()]);

        Signature {
            r,
            s,
            _reserved: reserved,
        }
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
Signature:
  R: {}
  S: {}
            "#,
            hex::encode(self.r),
            hex::encode(self.s)
        )
    }
}
