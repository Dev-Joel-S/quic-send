use thiserror::Error;

pub mod common;
pub mod crypto;
pub mod destination;
pub mod direct;
pub mod limits;
pub mod packets;
pub mod pairing;
pub mod password;
pub mod peers;
pub mod private_file;
pub mod receive;
pub mod send;

pub const BUF_SIZE: usize = 8192;
// 0.5.0 was never released, so every change to the handshake and the packets so far is
// part of it.
// TODO: from the first release on, bump the protocol version and the ALPN below whenever
//       the handshake or the packets change.
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
