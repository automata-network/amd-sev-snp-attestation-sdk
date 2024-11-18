use sev::certs::snp::Certificate;

pub struct CertificateChain {
    /// AMD Root Key Certificate
    pub ark_cert: Certificate,
    /// AMD SEV Key Certificate
    pub ask_cert: Certificate,
    /// VEK: Either a VCEK or VLEK.
    /// VLEK: Versioned Loaded Endorsement Key (VLEK), which is issued by AMD to a cloud provider
    /// VCEK: VM Chip Endorsement Key). VCEK is unique per CPU.
    pub vek_cert: Certificate,
}

impl CertificateChain {
    pub fn new(ark_cert: Certificate, ask_cert: Certificate, vek_cert: Certificate) -> Self {
        CertificateChain {
            ark_cert,
            ask_cert,
            vek_cert,
        }
    }
}
