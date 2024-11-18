use crate::error::{Result, SevSnpError};
use sysinfo::{CpuRefreshKind, RefreshKind, System};

#[derive(Debug, Clone)]
pub enum ProcType {
    /// 7003 series AMD EPYC Processor
    Milan,
    /// 9004 series AMD EPYC Processor
    Genoa,
    /// 97x4 series AMD EPYC Processor
    Bergamo,
    /// 8004 series AMD EPYC Processor
    Siena,
    // Turin,
    // Venice,
}

impl ProcType {
    pub fn to_kds_url(&self) -> String {
        match self {
            ProcType::Genoa | ProcType::Siena | ProcType::Bergamo => &ProcType::Genoa,
            _ => self,
        }
        .to_string()
    }
}

impl std::fmt::Display for ProcType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ProcType::Milan => write!(f, "Milan"),
            ProcType::Genoa => write!(f, "Genoa"),
            ProcType::Bergamo => write!(f, "Bergamo"),
            ProcType::Siena => write!(f, "Siena"),
        }
    }
}

/// Retrieve the codename for an AMD processor.
pub fn get_processor_codename() -> Result<&'static ProcType> {
    let s = System::new_with_specifics(RefreshKind::new().with_cpu(CpuRefreshKind::everything()));
    // Every PC will have at least one CPU.
    let cpu_brand = s.cpus()[0].brand();
    if cpu_brand.contains("7R13") || cpu_brand.contains("7B13") || cpu_brand.contains("19/01") {
        return Ok(&ProcType::Milan);
    }
    // TODO: Support more processor models once they are available.

    Err(SevSnpError::Cpu(format!("Unhandled CPU: {}", cpu_brand)))
}
