use crate::error::{Result, SevSnpError};
use serde::{Deserialize, Serialize};
use sev::firmware::guest::AttestationReport;
use tss_esapi::{
    abstraction::nv,
    handles::NvIndexTpmHandle,
    interface_types::{resource_handles::NvAuth, session_handles::AuthSession},
    tcti_ldr::{DeviceConfig, TctiNameConf},
};

#[repr(C)]
#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
struct Hcl {
    rsv1: [u32; 8],
    report: AttestationReport,
    rsv2: [u32; 5],
}

const VTPM_HCL_REPORT_NV_INDEX: u32 = 0x01400001;

/// On HyperV, AttestationReport is retrieved via the TPM device instead of /dev/sev-guest device.
pub fn get_attestation_report(
    _data: Option<[u8; 64]>,
    vmpl: Option<u32>,
) -> Result<AttestationReport> {
    if vmpl.unwrap() > 0 {
        return Err(SevSnpError::Tpm(
            "Azure vTPM attestation report requires VMPL 0!".to_string(),
        ));
    }
    let bytes = tpm2_read()?;
    hcl_report(&bytes)
}

fn tpm2_read() -> Result<Vec<u8>> {
    let handle = NvIndexTpmHandle::new(VTPM_HCL_REPORT_NV_INDEX)?;
    let mut ctx = tss_esapi::Context::new(TctiNameConf::Device(DeviceConfig::default()))?;
    ctx.set_sessions((Some(AuthSession::Password), None, None));

    Ok(nv::read_full(&mut ctx, NvAuth::Owner, handle)?)
}

fn hcl_report(bytes: &[u8]) -> Result<AttestationReport> {
    let hcl: Hcl = bincode::deserialize(bytes)?;

    Ok(hcl.report)
}
