use std::path::Path;
use std::sync::Arc;

use tonic::{transport::Server, Request, Response, Status};
use tracing::info;

use crate::event_handler::EventHandler;

// Include generated protobuf/tonic types from build.rs
pub mod proto {
    tonic::include_proto!("ebpfence");
}

use proto::ebp_fence_server::{EbpFence, EbpFenceServer};
use proto::{
    BlockedPid, ListBlockedPiDsRequest, ListBlockedPiDsResponse, UnblockPidRequest,
    UnblockPidResponse,
};

struct EbpFenceService {
    handler: Arc<EventHandler>,
}

#[tonic::async_trait]
impl EbpFence for EbpFenceService {
    async fn list_blocked_pi_ds(
        &self,
        _request: Request<ListBlockedPiDsRequest>,
    ) -> Result<Response<ListBlockedPiDsResponse>, Status> {
        let pids = self.handler.get_blocked_pids();
        let blocked_pids = pids
            .into_iter()
            .map(|pid| BlockedPid {
                pid,
                violation_count: self.handler.get_violation_count_for_pid(pid),
            })
            .collect();
        Ok(Response::new(ListBlockedPiDsResponse { blocked_pids }))
    }

    async fn unblock_pid(
        &self,
        request: Request<UnblockPidRequest>,
    ) -> Result<Response<UnblockPidResponse>, Status> {
        let pid = request.into_inner().pid;
        if pid == 0 {
            return Err(Status::invalid_argument("pid must be greater than 0"));
        }
        self.handler.unblock_pid(pid).map_err(|e| {
            Status::not_found(format!("failed to unblock PID {}: {}", pid, e))
        })?;
        Ok(Response::new(UnblockPidResponse {}))
    }
}

pub async fn serve(handler: Arc<EventHandler>, socket_path: &Path) -> anyhow::Result<()> {
    // Remove a stale socket from a previous run
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }

    info!("gRPC server listening on {}", socket_path.display());

    let socket_path = socket_path.to_path_buf();
    let uds = tokio::net::UnixListener::bind(&socket_path)?;
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(uds);

    let service = EbpFenceServer::new(EbpFenceService { handler });

    Server::builder()
        .add_service(service)
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}
