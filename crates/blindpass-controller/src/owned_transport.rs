// SPDX-License-Identifier: AGPL-3.0-only
//! Local transport lifetimes retain active ownership beyond HTTP handler return.
//! Fencing closes local IO; bytes already written and server-side SQL completion
//! need separate accounting before any complete quiescence/source-stop claim.

use crate::recovery_authority::{OwnershipOperation, ProcessOwnership};
use axum::serve::Listener;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use tokio::time::Sleep;

/// Accepted HTTP connections must reconnect within this lifetime. Existing
/// 35-second node polls keep their handler bound; a slow peer cannot hold an
/// issuing transport indefinitely. This is not a grant expiry or SQL deadline.
const HTTP_CONNECTION_LIFETIME: Duration = Duration::from_secs(60);

/// Stop all accepted transports, including diagnostic connections that were
/// created after an ownership latch. This does not reactivate ownership.
#[derive(Default)]
pub struct TransportShutdown {
    stopped: AtomicBool,
    notification: Notify,
}

impl TransportShutdown {
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.notification.notify_waiters();
    }

    async fn wait(&self) {
        loop {
            let notified = self.notification.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.stopped.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

pub struct OwnedListener<L> {
    listener: L,
    owner: Option<Arc<ProcessOwnership>>,
    shutdown: Arc<TransportShutdown>,
}

impl<L> OwnedListener<L> {
    pub fn new(listener: L, owner: Option<Arc<ProcessOwnership>>) -> Self {
        Self::with_shutdown(listener, owner, Arc::new(TransportShutdown::default()))
    }

    pub fn with_shutdown(
        listener: L,
        owner: Option<Arc<ProcessOwnership>>,
        shutdown: Arc<TransportShutdown>,
    ) -> Self {
        Self {
            listener,
            owner,
            shutdown,
        }
    }

    pub fn shutdown_handle(&self) -> Arc<TransportShutdown> {
        self.shutdown.clone()
    }
}

impl<L: Listener> Listener for OwnedListener<L> {
    type Io = OwnedIo<L::Io>;
    type Addr = L::Addr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (io, address) = self.listener.accept().await;
            if let Ok(io) = OwnedIo::new(
                io,
                self.owner.clone(),
                HTTP_CONNECTION_LIFETIME,
                self.shutdown.clone(),
            ) {
                return (io, address);
            }
            // Only an admission/fence race is refused here. New nonactive
            // connections still reach diagnostic/ordinary route admission.
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

pub struct OwnedIo<I> {
    io: Option<I>,
    operation: Option<OwnershipOperation>,
    fenced: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    deadline: Pin<Box<Sleep>>,
    stopped: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl<I> OwnedIo<I> {
    pub(crate) fn new(
        io: I,
        owner: Option<Arc<ProcessOwnership>>,
        lifetime: Duration,
        shutdown: Arc<TransportShutdown>,
    ) -> io::Result<Self> {
        let mut operation = None;
        let mut fenced: Option<Pin<Box<dyn Future<Output = ()> + Send>>> = None;
        if let Some(owner) = owner {
            if owner.is_active() {
                operation = Some(owner.begin_operation().map_err(|_| closed_error())?);
            } else if owner.is_recovering() {
                operation = Some(
                    owner
                        .begin_recovery_operation()
                        .map_err(|_| closed_error())?,
                );
            }
            // Admission may win the mutex immediately before fencing. An
            // admitted socket must still arm the already-fired notification.
            if operation.is_some() || !owner.is_fenced() {
                fenced = Some(Box::pin(async move { owner.wait_fenced().await }));
            }
        }
        Ok(Self {
            io: Some(io),
            operation,
            fenced,
            deadline: Box::pin(tokio::time::sleep(lifetime)),
            stopped: Box::pin(async move { shutdown.wait().await }),
        })
    }

    fn close(&mut self) {
        // Close local IO before dropping its permit; never detach a live
        // socket from the operation counter. Remote/kernel-written bytes
        // are not recalled by this local close.
        self.io.take();
        self.operation.take();
        self.fenced.take();
    }

    fn poll_closed(&mut self, context: &mut Context<'_>) -> bool {
        if self.io.is_none() {
            return true;
        }
        if self
            .fenced
            .as_mut()
            .is_some_and(|future| future.as_mut().poll(context).is_ready())
            || self.stopped.as_mut().poll(context).is_ready()
            || self.deadline.as_mut().poll(context).is_ready()
        {
            self.close();
            return true;
        }
        false
    }
}

impl<I> Drop for OwnedIo<I> {
    fn drop(&mut self) {
        self.close();
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for OwnedIo<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.poll_closed(context) {
            return Poll::Ready(Err(closed_error()));
        }
        Pin::new(this.io.as_mut().expect("open transport")).poll_read(context, buffer)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for OwnedIo<I> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.poll_closed(context) {
            return Poll::Ready(Err(closed_error()));
        }
        Pin::new(this.io.as_mut().expect("open transport")).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.poll_closed(context) {
            return Poll::Ready(Err(closed_error()));
        }
        Pin::new(this.io.as_mut().expect("open transport")).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.poll_closed(context) {
            return Poll::Ready(Err(closed_error()));
        }
        Pin::new(this.io.as_mut().expect("open transport")).poll_shutdown(context)
    }
}

fn closed_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "controller transport closed",
    )
}
