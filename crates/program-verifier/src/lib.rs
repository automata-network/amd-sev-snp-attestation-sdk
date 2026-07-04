pub use amd_sev_snp_attestation_verifier::stub::{VerifierInput, VerifierJournal};
use atakit_zk_guest::{Codec, CodecValue, GuestProgram};

pub struct Guest;

pub struct CustomCodec;

impl Codec for CustomCodec {}

impl CodecValue<CustomCodec> for VerifierInput {
    fn encode_codec(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.encode())
    }

    fn decode_codec(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(VerifierInput::decode(bytes)?)
    }
}

impl CodecValue<CustomCodec> for VerifierJournal {
    fn encode_codec(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.encode())
    }

    fn decode_codec(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(VerifierJournal::decode(bytes)?)
    }
}

impl GuestProgram<CustomCodec> for Guest {
    type Input = VerifierInput;
    type Output = VerifierJournal;

    fn run(input: VerifierInput) -> anyhow::Result<VerifierJournal> {
        amd_sev_snp_attestation_verifier::verify_attestation(input)
    }
}

atakit_zk_guest::guest_program!(Guest, codec = CustomCodec);
