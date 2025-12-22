use std::{
    panic::{self, AssertUnwindSafe},
    sync::{mpsc, Arc},
};

use alloy_primitives::Bytes;
use anyhow::{anyhow, Context, Result};
use tokio::runtime::{Handle, Runtime};
use serde::{Deserialize, Serialize};

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
