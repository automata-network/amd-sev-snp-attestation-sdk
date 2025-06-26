use crate::error::Result;
use crate::report::AttestationReport;
use coco_provider::coco::snp::types::CertType;
use rand::RngCore;
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
