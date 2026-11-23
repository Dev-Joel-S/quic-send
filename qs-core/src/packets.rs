use crate::common::{FilesAvailable, FilesToSkip};
use iroh::EndpointAddr;
use serde::{Deserialize, Serialize};

/// All packets send from the sender to the receiver
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SenderToReceiver {
    /// Initial connection request
    ConnRequest {
        version_num: String,
        /// The receiver has to prove that it knows the password before anything is offered
        password: bool,
        /// Where the sender can be found again, only told when it uses its stable
        /// identity, see `crate::peers`
        identity: Option<EndpointAddr>,
    },
    /// The sender's message of the password exchange, see `crate::password`
    Password { message: Vec<u8> },
    /// The receiver knew the password, and here is the proof that the sender knows it too
    PasswordAccepted { proof: Vec<u8> },
    /// The receiver did not know the password
    PasswordRejected,
    /// Send the files the sender wants to send
    FileInfo { files: Vec<FilesAvailable> },
}

/// All packets send from the receiver to the sender
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReceiverToSender {
    /// Reject the connection request, because the version number is wrong
    WrongVersion { expected: String },
    /// Accept the connection request
    Ok {
        /// Where the receiver can be found again, only told when it uses its stable
        /// identity
        identity: Option<EndpointAddr>,
    },
    /// The receiver's message of the password exchange and its proof
    Password { message: Vec<u8>, proof: Vec<u8> },
    /// The receiver was told to use a password, but the sender did not set one
    PasswordExpected,
    /// Reject the files the sender wants to send
    RejectFiles,
    /// Accept the files, and send the files that are supposed to be fully or partially skipped
    AcceptFilesSkip { files: Vec<Option<FilesToSkip>> },
}
