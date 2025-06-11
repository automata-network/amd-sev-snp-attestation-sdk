## Table of Contents
- [About AMD SEV-SNP](#about-amd-sev-snp)
- [Getting Started](#getting-started)

## About AMD SEV-SNP
AMD Secure Encrypted Virtualization-Secure Nested Paging (SEV-SNP) enhances memory integrity protection to prevent hypervisor-based attacks like data replay and memory re-mapping. It creates an isolated execution environment and introduces optional security enhancements for various VM use cases. SEV-SNP also strengthens protection against interrupt behavior and side-channel attacks. Refer to [whitepaper](https://www.amd.com/content/dam/amd/en/documents/epyc-business-docs/white-papers/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf) to get more details.

## Getting Started

### Hardware Requirements
The following cloud service providers (CSP) have support for AMD SEV-SNP:

#### AWS
- Instance Type: m6a, c6a, or r6a families
- Operating System: Amazon Linux 2023, RHEL 9.3, SLES 15 SP4, Ubuntu 23.04 or newer
- Region: us-east-2 (US East- Ohio), eu-west-1 (Europe- Ireland)
#### Azure
- Instance Type: DCasv5-series, DCadsv5-series, ECasv5-series, ECadsv5-series
- Operating System: Ubuntu 24.04(Confidential VM)- x64 Gen 2 image
- Region: any region that supports the above confidential instances.
#### GCP
- Instance Type: General-purpose n2d
- Operating System: Ubuntu 20.04+, RHEL 8+, SLES 15+, Fedora CoreOS 40+ 
- Supported zones: asia-southeast1-{a,b,c}, europe-west3-{a,b,c}, europe-west4-{a,b,c}, us-central1-{a,b,c}
- For more information on supported operating systems, please check out the following article on GCP: [supported configurations](https://cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations#amd-sev-snp)
- Currently, SEV-SNP enabled VMs can only be created via gcloud or Rest API, please check out this article on how to do so: [create an instance](https://cloud.google.com/confidential-computing/confidential-vm/docs/create-a-confidential-vm-instance#gcloud)
#### Others
- If you wish to use a CSP that is not listed above or run your own host, please ensure that the CSP or host is running the KVM hypervisor with the required patches for AMD SEV-SNP support and that your virtual machine has access to the device `/dev/sev-guest`.

### Download Dependencies
```bash
sudo apt install build-essential pkg-config libtss2-dev
```
### Getting Started with Rust
First, install Rust:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

To get a quick introduction on how to generate and verify an attestation report, we have an example at `examples/attestation.rs`. To run the example:
```bash
cargo build --example attestation
sudo ./target/debug/examples/attestation
```
The example should successfully generate and verify an attestation report on any SEV-SNP enabled virtual machine and display the result on stdout.

## Rust API Usage
### Initialise SevSnp object

In order to run the next few steps, first initialise an SevSnp object:
```rust
use sev_snp::SevSnp;

...

let sev_snp = SevSnp::new();
```

### Generate Attestation
To generate an attestation with default options, you can do so like this:
```rust
let (report, _) = sev_snp.get_attestation_report()?;
```

If you wish to customise options for the attestation report, you can do something like this:

```rust
use sev_snp::device::ReportOptions;

...

sev_snp.get_attestation_report_with_options(
    ReportOptions {
        report_data: Some([0; 64]),
        vmpl: Some(1),
    }
)?;
```

For details on the struct options, please check out the comments in the struct.

### Verify Attestation
#### Verify Attestation on-chain

To verify your attestation repot on chain, you can use either [RISC0](../zk/risc0/) or [SP1](../zk/sp1/) zkVM to perform the validation offchain and generate a ZK proof, then verify this proof on chain. Here are the steps to generate the proof:

1. Perform the attestation generation with the VEK cert, and store the results in Base64 format. Check how it does at [attestation example](./examples/attestation.rs).

2. Follow the instructions at [RISC0](../zk/risc0/) or [SP1](../zk/sp1/) folder, to see how to generate a proof and validate it offchain.

3. Send the proof with necessary output to the [Automata AMD SEV-SNP Attestation contract](https://explorer-testnet.ata.network/address/0xDe510E1F9258c94c5520B717210a301Cc8297F1F).

#### Verify Attestation off-chain

To verify your attestation report, you can use the following function:

```rust
sev_snp.verify_attestation_report(&report, None)?;
```

If you wish to choose how the attestation report is verified, you can use the following function:

```rust
sev_snp.verify_attestation_report_with_options(&report, &sev_snp::AttestationFlow::Extended, None)?;
```
There are 2 ways to verify the attestation report.
You can choose to use the `&sev_snp::AttestationFlow::Regular` or `&sev_snp::AttestationFlow::Extended` option.
   - In the extended verification method, the report is verified by using CA certs retrieved from the AMD SEV device. This means that this verification method can only be performed on the SEV-SNP VM where the report is generated.
   - In the regular verification method, the report is verified by using CA certs retrieved from the AMD Key Distribution Service (KDS). 

Note the following CSP specific details:
- GCP: Either Extended or Regular can be used for attestation report verification
- Azure: Only Regular can be used for attestation report verification
- AWS: Either Extended or Regular can be used, but note that:
    - In Regular verification method: the VLEK cert must be provided instead of `None`. Only ARK and ASK can be retrieved from the KDS.
    - In Extended verification method: Only the VLEK cert can be retrieved from the SEV-SNP device. ARK and ASK will be retrieved from the KDS.

### Generate Derived Key
> Note: This option is not available on Azure Confidential VMs.

To generate a derived key, you can do so by calling the following function:

```rust
let derived_key = sev_snp.get_derived_key()?;
```


If you wish to specify additional options when generating the key, you can call the following function:

```rust
use sev_snp::key::{DerivedKeyOptions, RootKeyType};

...


let derived_key = sev_snp.get_derived_key_with_options(
    DerivedKeyOptions {
        root_key_type: Some(RootKeyType::VMRK),
        guest_field_sel: Some("000000".to_string()),
        guest_svn: Some(1),
        tcb_version: Some(1),
        vmpl: Some(1),
    }
)?;

```
For details on the struct options, please check out the comments in the struct.

### Get Golden Measurement
This allows developers to get the measurements of the system and hardware.

TBD.

## Getting Started with Go
same structure with `Getting Started with Rust`.

TBD.
