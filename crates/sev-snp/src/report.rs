use crate::cpu::ProcType;
use coco_provider::coco::snp::types::CertType;

use bitfield::bitfield;
use openssl::{bn, ecdsa};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::convert::TryFrom;
use std::io::{Error, Result};

#[repr(C)]
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]

pub struct AttestationReport {
    /// Version number of this attestation report.
    pub version: u32,
    /// The guest SVN.
    pub guest_svn: u32,
    /// The guest policy.
    pub policy: GuestPolicy,
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
    pub plat_info: PlatformInfo,
    /// Private variable as it contains multiple sub fields.
    /// Bit 0: AUTHOR_KEY_EN
    /// Bit 1: MASK_CHIP_KEY
    /// Bit 2,3,4: SIGNING_KEY type
    /// Bit 5-31: RESERVED. Must be zero.
    _key_settings: u32,
    _reserved_0: u32,
    #[serde(with = "BigArray")]
    /// Guest-provided 512 Bits of Data
    pub report_data: [u8; 64],
    #[serde(with = "BigArray")]
    /// The measurement calculated at launch.
    pub measurement: [u8; 48],
    /// Data provided by the hypervisor at launch.
    pub host_data: [u8; 32],
    #[serde(with = "BigArray")]
    /// SHA-384 digest of the ID public key that signed the ID block provided in SNP_LANUNCH_FINISH.
    pub id_key_digest: [u8; 48],
    #[serde(with = "BigArray")]
    /// SHA-384 digest of the Author public key that certified the ID key,
    /// if provided in SNP_LAUNCH_FINISH. Zeroes if AUTHOR_KEY_EN is 1.
    pub author_key_digest: [u8; 48],
    /// Report ID of this guest.
    pub report_id: [u8; 32],
    /// Report ID of this guest's migration agent (if applicable).
    pub report_id_ma: [u8; 32],
    /// Reported TCB version used to derive the VCEK that signed this report.
    pub reported_tcb: TcbVersion,
    /// Only added in report version 3 and above.
    /// Family ID (Combined Extended Family ID and Family ID)
    pub cpuid_fam_id: u8,
    /// Only added in report version 3 and above.
    /// Model (combined Extended Model and Model fields)
    pub cpuid_mod_id: u8,
    /// Only added in report version 3 and above.
    /// Stepping
    pub cpuid_step: u8,
    _reserved_1: [u8; 21],
    #[serde(with = "BigArray")]
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
    /// Only added in report version 4 and above.
    /// The verified mitigation vector value at the time the guest was launched (LaunchMitVector).
    pub launch_mit_vector: [u8; 8],
    /// Only added in report version 4 and above.
    /// Value is set to the current verified mitigation vector value (CurrentMitVector).
    pub current_mit_vector: [u8; 8],
    #[serde(with = "BigArray")]
    _reserved_4: [u8; 152],
    /// Signature of bytes 0 to 0x29F inclusive of this report.
    /// The format of the signature is found within Signature.
    pub signature: Signature,
}

impl AttestationReport {
    pub fn author_key_en(&self) -> bool {
        let author_key_en = self._key_settings & 0b1;
        author_key_en == 1
    }

    pub fn mask_chip_key(&self) -> u32 {
        self._key_settings & 0b10
    }
    /// Returns the Signing Key type used for this report.
    /// 0: VCEK
    /// 1: VLEK
    /// 2-6: RESERVED
    /// 7: None
    pub fn signing_key_type(&self) -> crate::error::Result<&CertType> {
        let signer_type = self._key_settings & 0b11100;
        if signer_type == 0b000 {
            return Ok(&CertType::VCEK);
        } else if signer_type == 0b100 {
            return Ok(&CertType::VLEK);
        }
        Err(crate::error::SevSnpError::Bincode(format!(
            "Unknown Signer for attestation report: 0x{:x}",
            signer_type
        )))
    }

    /// Returns the cpu codename of the CPU used in the report.
    pub fn get_cpu_codename(&self) -> crate::error::Result<&ProcType> {
        // Notes: Report version must be 3 or above to have these previously reserved fields populated.
        if self.version >= 3 {
            let fam_id = self.cpuid_fam_id;
            let mod_id = self.cpuid_mod_id;
            let stepping = self.cpuid_step;
            // 25: Zen 3, Zen 3+, Zen 4
            // Milan: Zen 3, Genoa: Zen 4, Bergamo: Zen 4c
            // Siena: Zen 4c, Turin: Zen 5, Venice: TBD.
            if fam_id == 25 && mod_id == 1 {
                return Ok(&ProcType::Milan);
            }
            // TODO: fill up more code types as it becomes available.
            println!(
                "Family: {}, Mod_id: {}, Stepping: {}",
                fam_id, mod_id, stepping
            );
        }
        // For Report Version 2, assume Milan for now.
        Ok(&ProcType::Milan)
    }
}

/// TcbVersion represents the version of the firmware.
///
/// (Chapter 2.2; Table 3)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
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
    /// Creates a new instance of a TcbVersion
    pub fn new(bootloader: u8, tee: u8, snp: u8, microcode: u8) -> Self {
        Self {
            bootloader,
            tee,
            snp,
            microcode,
            _reserved: Default::default(),
        }
    }
}

bitfield! {
    /// The firmware associates each guest with a guest policy that the guest owner provides. The
    /// firmware restricts what actions the hypervisor can take on this guest according to the guest policy.
    /// The policy also indicates the minimum firmware version to for the guest.
    ///
    /// The guest owner provides the guest policy to the firmware during launch. The firmware then binds
    /// the policy to the guest. The policy cannot be changed throughout the lifetime of the guest. The
    /// policy is also migrated with the guest and enforced by the destination platform firmware.
    ///
    /// | Bit(s) | Name              | Description                                                                                                        >
    /// |--------|-------------------|-------------------------------------------------------------------------------------------------------------------->
    /// | 7:0    | ABI_MINOR         | The minimum ABI minor version required for this guest to run.                                                      >
    /// | 15:8   | ABI_MAJOR         | The minimum ABI major version required for this guest to run.                                                      >
    /// | 16     | SMT               | 0: Host SMT usage is disallowed.<br>1: Host SMT usage is allowed.                                                  >
    /// | 17     | -                 | Reserved. Must be one.                                                                                             >
    /// | 18     | MIGRATE_MA        | 0: Association with a migration agent is disallowed.<br>1: Association with a migration agent is allowed           >
    /// | 19     | DEBUG             | 0: Debugging is disallowed.<br>1: Debugging is allowed.                                                            >
    /// | 20     | SINGLE_SOCKET     | 0: Guest can be activated on multiple sockets.<br>1: Guest can only be activated on one socket.                    >
    /// | 21     | CXL_ALLOW         | 0: CXL cannot be populated with devices or memory.<br>1: CXL can be populated with devices or memory.              >
    /// | 22     | MEM_AES_256_XTS   | 0: Allow either AES 128 XEX or AES 256 XTS for memory encryption.<br>1: Require AES 256 XTS for memory encryption. >
    /// | 23     | RAPL_DIS          | 0: Allow Running Average Power Limit (RAPL).<br>1: RAPL must be disabled.                                          >
    /// | 24     | CIPHERTEXT_HIDING | 0: Ciphertext hiding may be enabled or disabled.<br>1: Ciphertext hiding must be enabled.                          >
    /// | 63:25  | -                 | Reserved. MBZ.                                                                                                     >
    ///
    #[repr(C)]
    #[derive(Default, Deserialize, Clone, Copy, Eq, PartialEq, Serialize)]
    pub struct GuestPolicy(u64);
    impl Debug;
    /// ABI_MINOR field: Indicates the minor API version.
    pub abi_minor, set_abi_minor: 7, 0;
    /// ABI_MAJOR field: Indicates the minor API version.
    pub abi_major, set_abi_major: 15, 8;
    /// SMT_ALLOWED field: Indicates the if SMT should be permitted.
    pub smt_allowed, set_smt_allowed: 16, 16;
    /// MIGRATE_MA_ALLOWED field: Indicates the if migration is permitted with
    /// the migration agent.
    pub migrate_ma_allowed, set_migrate_ma_allowed: 18, 18;
    /// DEBUG_ALLOWED field: Indicates the if debugging should is permitted.
    pub debug_allowed, set_debug_allowed: 19, 19;
    /// SINGLE_SOCKET_REQUIRED field: Indicates the if a single socket is required.
    pub single_socket_required, set_single_socket_required: 20, 20;
    /// CXL_ALLOW field: (1) can populate CXL devices/memory, (0) cannot populate CXL devices/memory
    pub cxl_allowed, set_cxl_allowed: 21, 21;
    /// MEM_AES_256_XTS field: (1) require AES 256 XTS encryption, (0) allows either AES 128 XEX or AES 256 XTS encryption
    pub mem_aes_256_xts, set_mem_aes_256_xts: 22, 22;
    /// RAPL_DIS field: (1) RAPL must be disabled, (0) allow RAPL
    pub rapl_dis, set_rapl_dis: 23, 23;
    /// CIPHERTEXT_HIDING field: (1) ciphertext hiding must be enabled, (0) ciphertext hiding may be enabled/disabled
    pub ciphertext_hiding, set_ciphertext_hiding: 24, 24;
}

impl From<GuestPolicy> for u64 {
    fn from(value: GuestPolicy) -> Self {
        // Bit 17 of the guest policy is reserved and must always be set to 1.
        let reserved: u64 = 1 << 17;

        value.0 | reserved
    }
}

bitfield! {
    /// A structure with a bit-field unsigned 64 bit integer:
    /// Bit 0 representing the status of SMT enablement.
    /// Bit 1 representing the status of TSME enablement.
    /// Bit 2 indicates if ECC memory is used.
    /// Bit 3 indicates if RAPL is disabled.
    /// Bit 4 indicates if ciphertext hiding is enabled
    /// Bits 5-63 are reserved.
    #[repr(C)]
    #[derive(Default, Deserialize, Clone, Copy, Serialize)]
    pub struct PlatformInfo(u64);
    impl Debug;
    /// Returns the bit state of SMT
    pub smt_enabled, _: 0, 0;
    /// Returns the bit state of TSME.
    pub tsme_enabled, _: 1, 1;
    /// Indicates that the platform is currently using ECC memory
    pub ecc_enabled, _: 2, 2;
    /// Indicates that the RAPL feature is disabled
    pub rapl_disabled, _: 3, 3;
    /// Indicates that ciphertext hiding is enabled
    pub ciphertext_hiding_enabled, _: 4, 4;
    /// reserved
    reserved, _: 63, 5;
}

const SIG_PIECE_SIZE: usize = std::mem::size_of::<[u8; 72]>();
const R_S_SIZE: usize = SIG_PIECE_SIZE * 2usize;

#[repr(C)]
#[derive(Copy, Clone, Deserialize, Serialize)]
/// ECDSA signature.
pub struct Signature {
    #[serde(with = "BigArray")]
    r: [u8; 72],
    #[serde(with = "BigArray")]
    s: [u8; 72],
    #[serde(with = "BigArray")]
    _reserved: [u8; 512 - R_S_SIZE],
}

impl Signature {
    /// Returns the signatures `r` component
    pub fn r(&self) -> &[u8; 72] {
        &self.r
    }

    /// Returns the signatures `s` component
    pub fn s(&self) -> &[u8; 72] {
        &self.s
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Signature {{ r: {:?}, s: {:?} }}",
            self.r.iter(),
            self.s.iter()
        )
    }
}

impl Eq for Signature {}
impl PartialEq for Signature {
    fn eq(&self, other: &Signature) -> bool {
        self.r[..] == other.r[..] && self.s[..] == other.s[..]
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature {
            r: [0u8; 72],
            s: [0u8; 72],
            _reserved: [0u8; (512 - (SIG_PIECE_SIZE * 2))],
        }
    }
}

impl From<ecdsa::EcdsaSig> for Signature {
    #[inline]
    fn from(value: ecdsa::EcdsaSig) -> Self {
        Signature {
            r: value.r().as_le_bytes(),
            s: value.s().as_le_bytes(),
            _reserved: [0; 512 - (SIG_PIECE_SIZE * 2)],
        }
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self> {
        Ok(ecdsa::EcdsaSig::from_der(value)?.into())
    }
}

impl TryFrom<&Signature> for ecdsa::EcdsaSig {
    type Error = Error;

    #[inline]
    fn try_from(value: &Signature) -> Result<Self> {
        let r = bn::BigNum::from_le(&value.r)?;
        let s = bn::BigNum::from_le(&value.s)?;
        Ok(ecdsa::EcdsaSig::from_private_components(r, s)?)
    }
}

impl TryFrom<&Signature> for Vec<u8> {
    type Error = Error;

    #[inline]
    fn try_from(value: &Signature) -> Result<Self> {
        Ok(ecdsa::EcdsaSig::try_from(value)?.to_der()?)
    }
}

pub(crate) trait FromLe: Sized {
    fn from_le(value: &[u8]) -> Result<Self>;
}

pub(crate) trait AsLeBytes<T> {
    fn as_le_bytes(&self) -> T;
}

impl FromLe for openssl::bn::BigNum {
    #[inline]
    fn from_le(value: &[u8]) -> Result<Self> {
        Ok(Self::from_slice(
            &value.iter().rev().cloned().collect::<Vec<_>>(),
        )?)
    }
}

impl AsLeBytes<[u8; 72]> for openssl::bn::BigNumRef {
    fn as_le_bytes(&self) -> [u8; 72] {
        let mut buf = [0u8; 72];

        for (i, b) in self.to_vec().into_iter().rev().enumerate() {
            buf[i] = b;
        }

        buf
    }
}

impl AsLeBytes<[u8; 512]> for openssl::bn::BigNumRef {
    fn as_le_bytes(&self) -> [u8; 512] {
        let mut buf = [0u8; 512];

        for (i, b) in self.to_vec().into_iter().rev().enumerate() {
            buf[i] = b;
        }

        buf
    }
}
