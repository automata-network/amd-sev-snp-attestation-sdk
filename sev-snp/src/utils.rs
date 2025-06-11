use crate::{cpu::ProcType, error::Result};
use rand::RngCore;
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::CertType;
use std::{fs::File, fs::OpenOptions, io::Write, path::PathBuf};

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

/// TODO: update this trait once SEV crate updates with the new fields.
/// From preliminary preview, it looks like there are major changes to accomodate
/// report V2 and V3 formats.
pub trait AttestationReportExt {
    /// Returns the Signing Key type used for this report.
    /// 0: VCEK
    /// 1: VLEK
    /// 2-6: RESERVED
    /// 7: None
    fn get_signer_type(&self) -> Result<&CertType>;
    /// Returns the cpu codename of the CPU used in the report.
    fn get_cpu_codename(&self) -> Result<&ProcType>;
}

impl AttestationReportExt for AttestationReport {
    fn get_signer_type(&self) -> Result<&CertType> {
        let encoded: Vec<u8> = bincode::serialize(&self)?;
        let bits = encoded[0x48];
        let signer_type = bits & 0b11100;
        if signer_type == 0b000 {
            return Ok(&CertType::VCEK);
        } else if signer_type == 0b100 {
            return Ok(&CertType::VLEK);
        }
        Err(crate::error::SevSnpError::Bincode(
            "Unknown Signer for attestation report!".to_string(),
        ))
    }

    fn get_cpu_codename(&self) -> Result<&ProcType> {
        // Notes: Report version must be 3 or above to have these previously reserved fields populated.
        // Offsets:
        // 0x188: CPUID_FAM_ID : Family ID (Combined Extended Family ID and Family ID)
        // 0x189: CPUID_MOD_ID : Model (combined Extended Model and Model fields)
        // 0x18A: CPUID_STEP : Stepping
        let encoded: Vec<u8> = bincode::serialize(&self)?;
        if self.version >= 3 {
            let fam_id = encoded[0x188];
            let mod_id = encoded[0x189];
            let stepping = encoded[0x18A];
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
