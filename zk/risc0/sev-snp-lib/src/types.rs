#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CertType {
    /// Empty or closing entry for the CertTable
    Empty,

    /// AMD Root Signing Key (ARK) certificate
    ARK,

    /// AMD SEV Signing Key (ASK) certificate
    ASK,

    /// Versioned Chip Endorsement Key (VCEK) certificate
    VCEK,

    /// Versioned Loaded Endorsement Key (VLEK) certificate
    VLEK,

    /// Certificate Revocation List (CRLs) certificate(s)
    CRL
}

impl CertType {
    pub fn to_uuid(&self) -> String {
        match self {
            CertType::Empty => "00000000-0000-0000-0000-000000000000".to_string(),
            CertType::ARK => "c0b406a4-a803-4952-9743-3fb6014cd0ae".to_string(),
            CertType::ASK => "4ab7b379-bbac-4fe4-a02f-05aef327c782".to_string(),
            CertType::VCEK => "63da758d-e664-4564-adc5-f4b93be8accd".to_string(),
            CertType::VLEK => "a8074bc2-a25a-483e-aae6-39c045a0b8a1".to_string(),
            CertType::CRL => "92f81bc3-5811-4d3d-97ff-d19f88dc67ea".to_string()
        }
    }

    pub fn to_str(&self) -> &str {
        match self {
            CertType::Empty => "",
            CertType::ARK => "ark",
            CertType::ASK => "ask",
            CertType::VCEK => "vcek",
            CertType::VLEK => "vlek",
            CertType::CRL => "crl"
        }
    }
}

#[derive(Debug)]
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
    pub fn from_str(str: &str) -> Self {
        match str {
            "Milan" => ProcType::Milan,
            "Genoa" => ProcType::Genoa,
            "Bergamo" => ProcType::Bergamo,
            "Siena" => ProcType::Siena,
            _ => panic!("Unknown Processor Model")
        }
    }

    pub fn to_str(&self) -> &str {
        match self {
            ProcType::Milan => "Milan",
            ProcType::Genoa => "Genoa",
            ProcType::Bergamo => "Bergamo",
            ProcType::Siena => "Siena"
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            ProcType::Milan => 0,
            ProcType::Genoa => 1,
            ProcType::Bergamo => 2,
            ProcType::Siena => 3
        }
    }

    pub fn from_u8(byte: &u8) -> Self {
        match byte {
            0 => ProcType::Milan,
            1 => ProcType::Genoa,
            2 => ProcType::Bergamo,
            3 => ProcType::Siena,
            _ => panic!("Unknown Processor Model")
        }
    }
}

// impl std::fmt::Display for ProcType {
//     fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
//         match self {
//             ProcType::Milan => write!(f, "Milan"),
//             ProcType::Genoa => write!(f, "Genoa"),
//             ProcType::Bergamo => write!(f, "Bergamo"),
//             ProcType::Siena => write!(f, "Siena"),
//         }
//     }
// }
