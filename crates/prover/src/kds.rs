use alloy_primitives::Bytes;
use amd_sev_snp_attestation_verifier::{stub::ProcessorType, AttestationReport};
use reqwest::blocking::get;
use x509_verifier_rust_crypto::pem_to_der;

const KDS_BASE_URL: &str = "https://kdsintf.amd.com/";

// https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/57230.pdf
pub struct KDS {}

impl KDS {
    pub fn new() -> Self {
        Self {}
    }

    fn fetch(&self, path: &str) -> anyhow::Result<Bytes> {
        let kds_url = format!("{}/vcek/v1/{}", KDS_BASE_URL, path);
        let ret_data = get(&kds_url)?.bytes()?.to_vec().into();
        Ok(ret_data)
    }

    pub fn fetch_model_cert_chain(&self, model: ProcessorType) -> anyhow::Result<Vec<Bytes>> {
        let result = self.fetch(&format!("{}/cert_chain", model.to_str()?))?;
        let ders = pem_to_der(&result)?;
        Ok(ders)
    }

    pub fn fetch_crl(&self, model: ProcessorType) -> anyhow::Result<Bytes> {
        let result = self.fetch(&format!("{}/crl", model.to_str()?))?;
        Ok(result.into())
    }

    pub fn fetch_vcek(&self, report: &AttestationReport) -> anyhow::Result<Bytes> {
        let path = format!(
            "{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            report.get_cpu_codename()?.to_str()?,
            alloy_primitives::hex::encode(&report.chip_id),
            &report.reported_tcb.bootloader,
            &report.reported_tcb.tee,
            &report.reported_tcb.snp,
            &report.reported_tcb.microcode
        );
        let cert = self.fetch(&path)?;
        Ok(cert)
    }

    pub fn fetch_report_cert_chain(
        &self,
        report: &AttestationReport,
    ) -> anyhow::Result<Vec<Bytes>> {
        let processor_type = report.get_cpu_codename()?;
        let vek_cert = self.fetch_vcek(report)?;
        let mut ders = self.fetch_model_cert_chain(processor_type)?;
        ders.insert(0, vek_cert);
        Ok(ders)
    }
}
