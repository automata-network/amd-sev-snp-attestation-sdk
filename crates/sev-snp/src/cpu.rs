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
