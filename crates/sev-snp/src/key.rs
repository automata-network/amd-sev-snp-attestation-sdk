use crate::error::{Result, SevSnpError};
use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};

pub enum RootKeyType {
    VCEK,
    VMRK,
}

pub struct DerivedKeyOptions {
    /// Pick a root key from which to derive the derived key.
    /// Defaults to VECK
    pub root_key_type: Option<RootKeyType>,
    /// Specify which Guest Field Select bits to enable. It is a 6 digit binary string. For each bit, 0 denotes off and 1 denotes on.
    /// The least significant (rightmost) bit is Guest Policy followed by Image ID, Family ID, Measurement, SVN, TCB Version which is the most significant (leftmost) bit.
    /// Example: "000000" means all bits are off.
    /// Example: "100001" means only the Guest Policy and TCB Version bits are on.
    /// Defaults to None (or 0)
    pub guest_field_sel: Option<String>,
    /// Specify the guest SVN to mix into the key. Must not exceed the guest SVN provided at launch in the ID block.
    /// Defaults to None (or 0)
    pub guest_svn: Option<u32>,
    /// Specify the TCB version to mix into the derived key. Must not exceed CommittedTcb.
    /// Defaults to None (or 0)
    pub tcb_version: Option<u64>,
    /// VMPL level that the Guest is running on. It is a number between 0 to 3.
    /// Defaults to 1.
    pub vmpl: Option<u32>,
}

pub struct DerivedKeyGenerator {
    options: DerivedKeyOptions,
    is_hyperv: bool,
}

impl DerivedKeyGenerator {
    /// Initialise DerivedKeyGenerator with default options
    pub fn default(is_hyperv: bool) -> Self {
        let options = DerivedKeyOptions {
            root_key_type: Some(RootKeyType::VCEK),
            guest_field_sel: None,
            guest_svn: None,
            tcb_version: None,
            vmpl: Some(1),
        };
        DerivedKeyGenerator { options, is_hyperv }
    }

    /// Initialise DerivedKeyGenerator with custom options
    pub fn new(options: DerivedKeyOptions, is_hyperv: bool) -> Self {
        DerivedKeyGenerator { options, is_hyperv }
    }

    /// Generate the Derived Key
    pub fn get(&self) -> Result<[u8; 32]> {
        // Derived Key generation is not supported for HyperV
        if self.is_hyperv {
            return Err(SevSnpError::DerivedKey(
                "Derived Key generation is not supported for HyperV".to_string(),
            ));
        }

        let root_key_sel = match self
            .options
            .root_key_type
            .as_ref()
            .unwrap_or(&RootKeyType::VCEK)
        {
            RootKeyType::VCEK => false,
            RootKeyType::VMRK => true,
        };
        let vmpl = self.options.vmpl.unwrap_or(1);
        let guest_field_sel: u64 = match self.options.guest_field_sel.as_ref() {
            Some(val) => u64::from_str_radix(&val, 2).unwrap(),
            None => 0,
        };
        let guest_svn = self.options.guest_svn.unwrap_or(0);
        let tcb_version = self.options.tcb_version.unwrap_or(0);

        self.verify_options(vmpl, guest_field_sel)?;

        let request = DerivedKey::new(
            root_key_sel,
            GuestFieldSelect(guest_field_sel),
            vmpl,
            guest_svn,
            tcb_version,
        );
        // Try to open device
        let mut sev_fw = Firmware::open()?;
        // Try to get derived key
        Ok(sev_fw.get_derived_key(None, request)?)
    }

    fn verify_options(&self, vmpl: u32, guest_field_sel: u64) -> Result<()> {
        if vmpl > 3 {
            return Err(SevSnpError::ConfigOptions(format!(
                "Invalid VMPL {}: Should be a number between 0 - 3",
                vmpl
            )));
        }
        if guest_field_sel > 63 {
            return Err(SevSnpError::ConfigOptions(format!(
                "Invalid guest_field_sel {}: Should be a number less than 64",
                guest_field_sel
            )));
        }
        Ok(())
    }
}
