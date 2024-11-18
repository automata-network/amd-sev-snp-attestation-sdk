use crate::error::Result;
use rand::RngCore;
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::CertType;
use std::arch::x86_64::__cpuid;
use std::{fs::File, fs::OpenOptions, io::Write, path::PathBuf};

// https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
const CPUID_GET_HIGHEST_FUNCTION: u32 = 0x80000000;
const CPUID_PROCESSOR_INFO_AND_FEATURE_BITS: u32 = 0x1;

const CPUID_FEATURE_HYPERVISOR: u32 = 1 << 31;

const CPUID_HYPERV_SIG: &str = "Microsoft Hv";
const CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS: u32 = 0x40000000;
const CPUID_HYPERV_FEATURES: u32 = 0x40000003;
const CPUID_HYPERV_MIN: u32 = 0x40000005;
const CPUID_HYPERV_MAX: u32 = 0x4000ffff;
const CPUID_HYPERV_ISOLATION: u32 = 1 << 22;
const CPUID_HYPERV_CPU_MANAGEMENT: u32 = 1 << 12;
const CPUID_HYPERV_ISOLATION_CONFIG: u32 = 0x4000000C;
const CPUID_HYPERV_ISOLATION_TYPE_MASK: u32 = 0xf;
const CPUID_HYPERV_ISOLATION_TYPE_SNP: u32 = 2;

/// Struct to hold utilities related to HyperV
pub struct HyperV;

impl HyperV {
    /// Checks whether the VM is running on top of HyperV hypervisor
    ///
    /// Returns:
    /// - true if VM is running on top of HyperV, false otherwise.
    pub fn present() -> bool {
        let mut cpuid = unsafe { __cpuid(CPUID_PROCESSOR_INFO_AND_FEATURE_BITS) };
        if (cpuid.ecx & CPUID_FEATURE_HYPERVISOR) == 0 {
            return false;
        }

        cpuid = unsafe { __cpuid(CPUID_GET_HIGHEST_FUNCTION) };
        if cpuid.eax < CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS {
            return false;
        }

        cpuid = unsafe { __cpuid(CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS) };
        if cpuid.eax < CPUID_HYPERV_MIN || cpuid.eax > CPUID_HYPERV_MAX {
            return false;
        }

        let mut sig: Vec<u8> = vec![];
        sig.append(&mut cpuid.ebx.to_le_bytes().to_vec());
        sig.append(&mut cpuid.ecx.to_le_bytes().to_vec());
        sig.append(&mut cpuid.edx.to_le_bytes().to_vec());

        if sig != CPUID_HYPERV_SIG.as_bytes() {
            return false;
        }

        cpuid = unsafe { __cpuid(CPUID_HYPERV_FEATURES) };

        let isolated: bool = (cpuid.ebx & CPUID_HYPERV_ISOLATION) != 0;
        let managed: bool = (cpuid.ebx & CPUID_HYPERV_CPU_MANAGEMENT) != 0;

        if !isolated || managed {
            return false;
        }

        cpuid = unsafe { __cpuid(CPUID_HYPERV_ISOLATION_CONFIG) };
        let mask = cpuid.ebx & CPUID_HYPERV_ISOLATION_TYPE_MASK;
        let snp = CPUID_HYPERV_ISOLATION_TYPE_SNP;

        if mask != snp {
            return false;
        }

        true
    }
}

/// Generates 64 bytes of random data
/// Always guaranted to return something (ie, unwrap() can be safely called)
pub fn generate_random_data() -> Option<[u8; 64]> {
    let mut data = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut data);
    Some(data)
}

pub trait CertTypeExt {
    fn string(&self) -> String;
}

impl CertTypeExt for CertType {
    fn string(&self) -> String {
        match self {
            CertType::VCEK => "VCEK",
            CertType::VLEK => "VLEK",
            CertType::ARK => "ARK",
            CertType::ASK => "ASK",
            CertType::Empty => "Empty",
            CertType::CRL => "CRL",
            CertType::OTHER(_) => "OTHER",
        }
        .to_string()
    }
}

pub trait AttestationReportExt {
    fn get_signer_type(&self) -> Result<CertType>;
}

impl AttestationReportExt for AttestationReport {
    fn get_signer_type(&self) -> Result<CertType> {
        let encoded: Vec<u8> = bincode::serialize(&self)?;
        let bits = encoded[0x48];
        let signer_type = bits & 0b11100;
        if signer_type == 0b000 {
            return Ok(CertType::VCEK);
        } else if signer_type == 0b100 {
            return Ok(CertType::VLEK);
        }
        Err(crate::error::SevSnpError::Bincode(
            "Unknown Signer for attestation report!".to_string(),
        ))
    }
}

/// Write the Derived Key to a location on disk.
pub fn write_key_to_disk(key: &[u8], key_filepath: &PathBuf) -> Result<()> {
    let mut key_file = if key_filepath.exists() {
        // Try to overwrite keyfile contents
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(key_filepath)?
    } else {
        // Try to create a new file
        File::create(key_filepath)?
    };

    bincode::serialize_into(&mut key_file, key)?;
    Ok(())
}

/// Serialize and write the attestation report and request data to a location on disk.
pub fn write_attestation_report_to_disk(
    report: &AttestationReport,
    report_filepath: &PathBuf,
    reqdata_filepath: &PathBuf,
) -> Result<()> {
    write_report(report_filepath, &report)?;
    write_request_data(reqdata_filepath, &report.report_data)?;
    Ok(())
}

/// Deserialize and read an existing attestation report from disk.
pub fn read_attestation_report_from_disk(report_filepath: &PathBuf) -> Result<AttestationReport> {
    let attestation_file = File::open(report_filepath)?;
    let attestation_report = bincode::deserialize_from(attestation_file)?;
    Ok(attestation_report)
}

fn write_report(filepath: &PathBuf, report: &AttestationReport) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(filepath)?;

    bincode::serialize_into(&mut file, report)?;
    Ok(())
}

fn write_request_data(filepath: &PathBuf, request_data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(filepath)?;

    write_hex(&mut file, &request_data)
}

fn write_hex(file: &mut File, data: &[u8]) -> Result<()> {
    let mut line_counter = 0;
    for val in data {
        // Make it blocks for easier read
        if line_counter.eq(&16) {
            writeln!(file)?;
            line_counter = 0;
        }

        write!(file, "{:02x}", val)?;
        line_counter += 1;
    }
    Ok(())
}
