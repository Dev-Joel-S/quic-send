use thiserror::Error;

pub mod common;
pub mod crypto;
pub mod destination;
pub mod direct;
pub mod limits;
pub mod packets;
pub mod pairing;
pub mod peers;
pub mod receive;
pub mod send;

pub const BUF_SIZE: usize = 8192;
// TODO: bump the protocol version and the ALPN below whenever the handshake or the
//       packets change, the pairing work will do that.
pub const QS_PROTO_VERSION: &str = "0.5.0";
pub const QS_ALPN: &[u8] = b"quic-send/0.5.0";

#[derive(Error, Debug)]
pub enum QuicSendError {
    #[error("send error: {0}")]
    Send(#[from] send::SendError),
    #[error("receive error: {0}")]
    Receive(#[from] receive::ReceiveError),
    #[error("bind error: {0}")]
    Bind(String),
}
