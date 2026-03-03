use std::{
    env::VarError,
    panic::{self, AssertUnwindSafe},
    sync::{mpsc, Arc},
};

use alloy_primitives::Bytes;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::runtime::{Handle, Runtime};

pub const DEFAULT_MARKETPLACE_POLL_BLOCK_INTERVAL: u64 = 10;

pub fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
    use tokio::task::block_in_place;

    if let Ok(handle) = Handle::try_current() {
        block_in_place(|| handle.block_on(fut))
    } else {
        let rt = Runtime::new().expect("Failed to create a new runtime");
        rt.block_on(fut)
    }
}

pub fn parallels_blocking<'a, T, F, E>(
    max_concurrency: usize,
    tasks: &'a [T],
    handler: F,
) -> Result<Vec<E>>
where
    T: Sync + Send,
    F: Fn(&T) -> Result<E> + Send + Sync + 'a,
    E: Send,
{
    crossbeam::thread::scope(|s| {
        let handler = Arc::new(handler);
        let max_concurrency = max_concurrency.min(tasks.len());
        let mut result: Vec<Option<Result<E>>> = Vec::with_capacity(tasks.len());
        result.resize_with(tasks.len(), || None);

        let (worker_request_tx, worker_request_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();

        for _ in 0..max_concurrency {
            let handler = Arc::clone(&handler);
            let worker_request_tx = worker_request_tx.clone();
            let result_tx = result_tx.clone();

            s.spawn(move |_| {
                let (task_tx, task_rx) = mpsc::channel();

                loop {
                    if worker_request_tx.send(task_tx.clone()).is_err() {
                        break;
                    }

                    let Ok((idx, task)) = task_rx.recv() else {
                        break;
                    };

                    let result = panic::catch_unwind(AssertUnwindSafe(|| {
                        handler(task).with_context(|| format!("handler failed at index {}", idx))
                    }))
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("panic at index {}", idx)));

                    let _ = result_tx.send((idx, result));
                }
            });
        }
        drop(result_tx);

        for (idx, task) in tasks.iter().enumerate() {
            loop {
                match worker_request_rx.recv() {
                    Ok(tx) => {
                        if tx.send((idx, task)).is_ok() {
                            break;
                        }
                    }
                    Err(_) => return Err(anyhow!("All workers have exited unexpectedly")),
                }
            }
        }
        drop(worker_request_rx);

        for _ in 0..result.len() {
            match result_rx.recv() {
                Ok((idx, res)) => {
                    result[idx] = Some(res);
                }
                Err(_) => {
                    return Err(anyhow!("Failed to receive result from worker"));
                }
            }
        }

        result
            .into_iter()
            .map(|r| r.expect("result slot missing"))
            .collect()
    })
    .unwrap()
}

fn parse_marketplace_poll_block_interval(raw: &str) -> Option<u64> {
    match raw.parse::<i64>() {
        Ok(parsed) if parsed >= 0 => Some(parsed as u64),
        _ => None,
    }
}

#[cfg(test)]
fn resolve_marketplace_poll_block_interval_from_str(raw: Option<&str>) -> u64 {
    raw.and_then(parse_marketplace_poll_block_interval)
        .unwrap_or(DEFAULT_MARKETPLACE_POLL_BLOCK_INTERVAL)
}

/// Resolve block interval for marketplace log polling.
///
/// `MARKETPLACE_POLL_BLOCK_INTERVAL` controls max blocks per eth_getLogs query:
/// - unset => 10
/// - >0 => chunk size
/// - 0 => unbounded (single query from start block to latest)
pub fn resolve_marketplace_poll_block_interval() -> u64 {
    match std::env::var("MARKETPLACE_POLL_BLOCK_INTERVAL") {
        Ok(raw) => match parse_marketplace_poll_block_interval(&raw) {
            Some(value) => value,
            None => {
                log::warn!(
                    "Invalid MARKETPLACE_POLL_BLOCK_INTERVAL={raw:?}; using default {}",
                    DEFAULT_MARKETPLACE_POLL_BLOCK_INTERVAL
                );
                DEFAULT_MARKETPLACE_POLL_BLOCK_INTERVAL
            }
        },
        Err(VarError::NotPresent) => DEFAULT_MARKETPLACE_POLL_BLOCK_INTERVAL,
        Err(VarError::NotUnicode(_)) => {
            log::warn!(
                "Invalid MARKETPLACE_POLL_BLOCK_INTERVAL (non-unicode); using default {}",
                DEFAULT_MARKETPLACE_POLL_BLOCK_INTERVAL
            );
            DEFAULT_MARKETPLACE_POLL_BLOCK_INTERVAL
        }
    }
}

/// Build inclusive block ranges `[start, end]` for bounded event queries.
///
/// If `interval` is 0, returns a single unbounded range `(block_start, latest_block)`.
pub fn block_query_ranges(block_start: u64, latest_block: u64, interval: u64) -> Vec<(u64, u64)> {
    let end = latest_block.max(block_start);
    if interval == 0 {
        return vec![(block_start, end)];
    }

    let mut ranges = Vec::new();
    let mut start = block_start;
    loop {
        let chunk_end = start.saturating_add(interval.saturating_sub(1)).min(end);
        ranges.push((start, chunk_end));
        if chunk_end >= end {
            break;
        }
        start = chunk_end.saturating_add(1);
    }

    ranges
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReportWithVekCertChain {
    pub report: Bytes,
    pub vek_certs: Option<Vec<Bytes>>,
}

impl AttestationReportWithVekCertChain {
    pub fn decode(input: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(input).map_err(|e| anyhow::anyhow!("Failed to decode: {}", e))
    }

    pub fn encode_json(&self) -> anyhow::Result<String> {
        serde_json::to_string(self).map_err(|e| anyhow::anyhow!("Failed to encode: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        block_query_ranges, resolve_marketplace_poll_block_interval_from_str,
        DEFAULT_MARKETPLACE_POLL_BLOCK_INTERVAL,
    };

    #[test]
    fn parse_marketplace_poll_block_interval_unset_uses_default() {
        let value = resolve_marketplace_poll_block_interval_from_str(None);
        assert_eq!(value, DEFAULT_MARKETPLACE_POLL_BLOCK_INTERVAL);
    }

    #[test]
    fn parse_marketplace_poll_block_interval_valid_values() {
        assert_eq!(
            resolve_marketplace_poll_block_interval_from_str(Some("10")),
            10
        );
        assert_eq!(
            resolve_marketplace_poll_block_interval_from_str(Some("1")),
            1
        );
        assert_eq!(
            resolve_marketplace_poll_block_interval_from_str(Some("0")),
            0
        );
    }

    #[test]
    fn parse_marketplace_poll_block_interval_invalid_uses_default() {
        assert_eq!(
            resolve_marketplace_poll_block_interval_from_str(Some("abc")),
            DEFAULT_MARKETPLACE_POLL_BLOCK_INTERVAL
        );
        assert_eq!(
            resolve_marketplace_poll_block_interval_from_str(Some("-5")),
            DEFAULT_MARKETPLACE_POLL_BLOCK_INTERVAL
        );
    }

    #[test]
    fn block_query_ranges_with_interval_10_exact_and_non_exact() {
        assert_eq!(
            block_query_ranges(100, 119, 10),
            vec![(100, 109), (110, 119)]
        );
        assert_eq!(
            block_query_ranges(100, 123, 10),
            vec![(100, 109), (110, 119), (120, 123)]
        );
    }

    #[test]
    fn block_query_ranges_with_interval_1() {
        assert_eq!(block_query_ranges(7, 9, 1), vec![(7, 7), (8, 8), (9, 9)]);
    }

    #[test]
    fn block_query_ranges_with_zero_interval_is_unbounded() {
        assert_eq!(block_query_ranges(50, 64, 0), vec![(50, 64)]);
    }
}
