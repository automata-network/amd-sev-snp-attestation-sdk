use alloy_primitives::hex;
use anyhow::{anyhow, Context};
use boundless_market::{
    alloy::{
        providers::{Provider, ProviderBuilder},
        signers::local::PrivateKeySigner,
        transports::http::reqwest::Url,
    },
    client::Client as BoundlessClient,
    contracts::FulfillmentData,
    price_oracle::{Amount, Asset},
    request_builder::{OfferParams, RequestParams},
    storage::{StorageUploader, StorageUploaderType},
    Deployment, StandardUploader, StorageUploaderConfig,
};
use risc0_zkvm::Digest;

use crate::{utils::block_on, RawProof, RawProofType};

use super::{BoundlessProofType, ProgramRisc0};

pub(crate) use boundless_market::alloy::primitives::{utils::parse_units, U256};

pub(crate) async fn submit_boundless_request(
    stdin: &[u8],
    elf: &[u8],
    cfg: &super::RiscZeroProverConfig,
    program_url: Option<&str>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let rpc_url = cfg
        .rpc_url
        .as_ref()
        .ok_or_else(|| anyhow!("missing BOUNDLESS_RPC_URL"))?;
    let private_key_hex = cfg
        .private_key
        .as_ref()
        .ok_or_else(|| anyhow!("missing BOUNDLESS_PRIVATE_KEY"))?;

    let rpc_url_parsed: Url = rpc_url
        .parse()
        .context("Failed to parse Boundless RPC URL")?;

    let provider = ProviderBuilder::new().connect_http(rpc_url_parsed.clone());
    let chain_id = provider
        .get_chain_id()
        .await
        .context("Failed to get chain ID from RPC")?;

    let deployment = Deployment::from_chain_id(chain_id)
        .with_context(|| format!("No Boundless deployment for chain {}", chain_id))?;

    let private_key_bytes = hex::decode(private_key_hex.trim_start_matches("0x"))
        .context("Failed to decode private key (must be hex-encoded)")?;
    let private_key =
        PrivateKeySigner::from_slice(&private_key_bytes).context("Failed to parse private key")?;

    let storage_config = storage_uploader_config_from_env().context(
        "Failed to get storage uploader config (check PINATA_JWT or S3_BUCKET env vars)",
    )?;

    let client = BoundlessClient::builder()
        .with_rpc_url(rpc_url_parsed)
        .with_deployment(deployment)
        .with_uploader_config(&storage_config)
        .await
        .context("Failed to configure Boundless storage uploader")?
        .with_private_key(private_key)
        .config_offer_layer(|config| {
            config
                .max_price_per_cycle(Amount::new(cfg.effective_max_price(), Asset::ETH))
                .min_price_per_cycle(Amount::new(cfg.effective_min_price(), Asset::ETH))
        })
        .build()
        .await
        .context("Failed to build Boundless client")?;

    // Build request.
    let mut request_builder = RequestParams::new().with_stdin(stdin);

    // Set program (URL if provided, otherwise upload ELF).
    if let Some(url) = program_url {
        request_builder = request_builder
            .with_program_url(url)
            .context("Failed to set program URL")?;
    } else {
        request_builder = request_builder.with_program(elf.to_vec());
    }

    // Set proof type.
    if matches!(cfg.proof_type, BoundlessProofType::Groth16) {
        request_builder = request_builder.with_groth16_proof();
    }

    // Configure offer params.
    let mut offer_builder = OfferParams::builder();
    if let Some(min_price) = cfg.min_price {
        offer_builder.min_price(Amount::new(U256::from(min_price), Asset::ETH));
    }
    if let Some(max_price) = cfg.max_price {
        offer_builder.max_price(Amount::new(U256::from(max_price), Asset::ETH));
    }
    if let Some((lock_timeout, timeout)) = cfg.effective_timeout() {
        offer_builder.lock_timeout(lock_timeout);
        offer_builder.timeout(timeout + 600);
    }
    if let Some(ramp_up_period) = cfg.ramp_up_period {
        offer_builder.ramp_up_period(ramp_up_period);
    }
    offer_builder.lock_collateral(Amount::new(cfg.effective_collateral(), Asset::ZKC));
    request_builder = request_builder.with_offer(offer_builder);

    tracing::debug!("Boundless request: {:?}", &request_builder);

    // Submit and wait for fulfillment.
    let (request_id, expires_at) = client
        .submit_onchain(request_builder)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to submit proof request: {:?}", e))?;

    tracing::info!("Boundless request submitted: {:x}", request_id);

    let fulfillment = client
        .wait_for_request_fulfillment(request_id, cfg.poll_interval(), expires_at)
        .await
        .context("Failed waiting for proof fulfillment")?;

    // Decode fulfillment data to extract the journal bytes.
    let fulfillment_data = fulfillment
        .data()
        .context("Failed to decode fulfillment data")?;
    let journal = match fulfillment_data {
        FulfillmentData::ImageIdAndJournal(_, journal) => journal.to_vec(),
        FulfillmentData::None => {
            return Err(anyhow!("Fulfillment has no journal data"));
        }
        _ => {
            return Err(anyhow!("Unexpected fulfillment data type"));
        }
    };

    Ok((fulfillment.seal.to_vec(), journal))
}

pub(crate) fn gen_proof<Input, Output>(
    program: &ProgramRisc0<Input, Output>,
    input_bytes: &[u8],
    _raw_proof_type: RawProofType,
    _encoded_composite_proofs: Option<&[&alloy_primitives::Bytes]>,
) -> anyhow::Result<RawProof> {
    gen_proof_boundless_single(program, input_bytes)
}

fn gen_proof_boundless_single<Input, Output>(
    program: &ProgramRisc0<Input, Output>,
    input_bytes: &[u8],
) -> anyhow::Result<RawProof> {
    let image_id = Digest::new(program.image_id());
    let program_url = program.config().verifier_program_url.as_deref();

    block_on(async {
        let (seal_bytes, journal_bytes) =
            submit_boundless_request(input_bytes, program.elf(), program.config(), program_url)
                .await?;

        let receipt = ProgramRisc0::<Vec<u8>, Vec<u8>>::construct_receipt(
            seal_bytes,
            journal_bytes.clone(),
            image_id,
        )?;

        Ok(RawProof::from_proof(&receipt, journal_bytes.into())?)
    })
}

pub(crate) fn upload_image<Input, Output>(
    program: &ProgramRisc0<Input, Output>,
) -> anyhow::Result<()> {
    block_on(async {
        let storage_config = storage_uploader_config_from_env().context(
            "Failed to get storage uploader config (check PINATA_JWT or S3_BUCKET env vars)",
        )?;
        let storage_uploader = StandardUploader::from_config(&storage_config)
            .await
            .context("Failed to configure Boundless storage uploader")?;

        let elf_url = storage_uploader
            .upload_program(program.elf())
            .await
            .context("Failed to upload ELF to Boundless storage")?;

        tracing::info!(
            "Uploaded image {} to storage: {}",
            Digest::new(program.image_id()),
            elf_url
        );

        Ok(())
    })
}

fn storage_uploader_config_from_env() -> anyhow::Result<StorageUploaderConfig> {
    if is_risc0_dev_mode() {
        return Ok(StorageUploaderConfig::dev_mode());
    }

    if let Ok(pinata_jwt) = std::env::var("PINATA_JWT") {
        let mut builder = StorageUploaderConfig::builder();
        builder
            .storage_uploader(StorageUploaderType::Pinata)
            .pinata_jwt(pinata_jwt);
        if let Some(url) = optional_url_env("PINATA_API_URL")? {
            builder.pinata_api_url(url);
        }
        if let Some(url) = optional_url_env("IPFS_GATEWAY_URL")? {
            builder.ipfs_gateway_url(url);
        }
        return Ok(builder.build()?);
    }

    if let Ok(s3_bucket) = std::env::var("S3_BUCKET") {
        let mut builder = StorageUploaderConfig::builder();
        builder
            .storage_uploader(StorageUploaderType::S3)
            .s3_bucket(s3_bucket);
        if let Ok(value) = std::env::var("S3_URL") {
            builder.s3_url(value);
        }
        if let Ok(value) =
            std::env::var("S3_ACCESS").or_else(|_| std::env::var("AWS_ACCESS_KEY_ID"))
        {
            builder.aws_access_key_id(value);
        }
        if let Ok(value) =
            std::env::var("S3_SECRET").or_else(|_| std::env::var("AWS_SECRET_ACCESS_KEY"))
        {
            builder.aws_secret_access_key(value);
        }
        if let Ok(value) = std::env::var("AWS_REGION") {
            builder.aws_region(value);
        }
        if let Some(value) = optional_bool_env("S3_USE_PRESIGNED")? {
            builder.s3_presigned(value);
        }
        if let Some(value) = optional_bool_env("S3_PUBLIC_URL")? {
            builder.s3_public_url(value);
        }
        return Ok(builder.build()?);
    }

    Err(anyhow!(
        "No Boundless storage uploader configured. Set PINATA_JWT, S3_BUCKET, or RISC0_DEV_MODE."
    ))
}

fn is_risc0_dev_mode() -> bool {
    std::env::var("RISC0_DEV_MODE")
        .ok()
        .map(|value| value.to_lowercase())
        .is_some_and(|value| value == "1" || value == "true" || value == "yes")
}

fn optional_url_env(name: &str) -> anyhow::Result<Option<Url>> {
    std::env::var(name)
        .ok()
        .map(|value| {
            value
                .parse()
                .with_context(|| format!("Failed to parse {name} as URL"))
        })
        .transpose()
}

fn optional_bool_env(name: &str) -> anyhow::Result<Option<bool>> {
    std::env::var(name)
        .ok()
        .map(|value| {
            value
                .parse()
                .with_context(|| format!("Failed to parse {name} as bool"))
        })
        .transpose()
}
