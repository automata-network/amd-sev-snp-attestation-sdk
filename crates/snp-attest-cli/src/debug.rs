use amd_sev_snp_attestation_prover::utils::AttestationReportWithVekCertChain;
use amd_sev_snp_attestation_verifier::AttestationReport;
use clap::{Args, Subcommand};
use std::path::PathBuf;
use x509_verifier_rust_crypto::CertChain;

#[derive(Subcommand)]
pub enum DebugCli {
    Doc(DebugDocCli),
}

impl DebugCli {
    pub fn run(&self) -> anyhow::Result<()> {
        match self {
            DebugCli::Doc(cli) => cli.run(),
        }
    }
}

#[derive(Args)]
pub struct DebugDocCli {
    #[clap(long)]
    report: PathBuf,
}

impl DebugDocCli {
    pub fn run(&self) -> anyhow::Result<()> {
        let data = AttestationReportWithVekCertChain::decode(&std::fs::read(&self.report)?)?;
        let report = AttestationReport::from_bytes(&data.report)?;

        println!("Report content:\n{}", report);
        if let Some(certs) = data.vek_certs {
            let cert_chain = CertChain::parse_rev(&certs)?;
            println!("Cert Chain:");
            let digest = cert_chain.digest();
            for (idx, cert) in cert_chain.certs.iter().enumerate() {
                println!("\t[{idx}] Digest: {:?}", digest[idx]);
                let (start, end) = cert.validity();
                println!(
                    "\t    Valid: {start}({}) - {end}({})",
                    start.timestamp(),
                    end.timestamp()
                );
            }
        }

        Ok(())
    }
}
