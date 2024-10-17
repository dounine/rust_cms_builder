// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Remote signing support.

pub mod session_negotiation;

use {
    base64::{engine::general_purpose::STANDARD as STANDARD_ENGINE, Engine},
    bcder::{
        encode::{PrimitiveContent, Values},
        Mode, Oid,
    },
    serde::{de::DeserializeOwned, Deserialize, Serialize},
    std::{
        cell::{RefCell, RefMut},
        net::TcpStream,
    },
    thiserror::Error,
    x509_certificate::{
        CapturedX509Certificate, KeyAlgorithm, KeyInfoSigner, Sign, Signature, SignatureAlgorithm,
        X509CertificateError,
    },
};

/// URL of default server to use.
pub const DEFAULT_SERVER_URL: &str = "wss://ws.codesign.gregoryszorc.com/";

/// An error specific to remote signing.
#[derive(Debug, Error)]
pub enum RemoteSignError {
    #[error("unexpected message received from relay server: {0}")]
    ServerUnexpectedMessage(String),

    #[error("error reported from relay server: {0}")]
    ServerError(String),

    #[error("not compatible with relay server; try upgrading to a new release?")]
    ServerIncompatible,

    #[error("cryptography error: {0}")]
    Crypto(String),

    #[error("bad client state: {0}")]
    ClientState(&'static str),

    #[error("joining state not wanted for this session type: {0}")]
    SessionJoinUnwantedState(String),

    #[error("session join string error: {0}")]
    SessionJoinString(String),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PEM encoding error: {0}")]
    Pem(#[from] pem::PemError),

    #[error("JSON serialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("SPAKE error: {0}")]
    Spake(spake2::Error),

    #[error("SPKI error: {0}")]
    Spki(#[from] spki::Error),

    #[error("X.509 certificate handler error: {0}")]
    X509(#[from] X509CertificateError),
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ApiMethod {
    Hello,
    CreateSession,
    JoinSession,
    SendMessage,
    Goodbye,
}

/// A websocket message sent from the client to the server.
#[derive(Clone, Debug, Serialize)]
struct ClientMessage {
    /// Unique ID for this request.
    request_id: String,
    /// API method being called.
    api: ApiMethod,
    /// Payload for this method.
    payload: Option<ClientPayload>,
}

/// Payload for a [ClientMessage].
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
enum ClientPayload {
    CreateSession {
        session_id: String,
        ttl: u64,
        context: Option<String>,
    },
    JoinSession {
        session_id: String,
        context: Option<String>,
    },
    SendMessage {
        session_id: String,
        message: String,
    },
    Goodbye {
        session_id: String,
        reason: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum ServerMessageType {
    Error,
    Greeting,
    SessionCreated,
    SessionJoined,
    MessageSent,
    PeerMessage,
    SessionClosed,
}

/// Websocket message sent from server to client.
#[derive(Clone, Debug, Deserialize)]
struct ServerMessage {
    /// ID of request responsible for this message.
    request_id: Option<String>,
    /// The type of message.
    #[serde(rename = "type")]
    typ: ServerMessageType,
    ttl: Option<u64>,
    payload: Option<serde_json::Value>,
}

impl ServerMessage {
    fn into_result(self) -> Result<Self, RemoteSignError> {
        if self.typ == ServerMessageType::Error {
            let error = self.as_error()?;
            Err(RemoteSignError::ServerError(format!(
                "{}: {}",
                error.code, error.message
            )))
        } else {
            Ok(self)
        }
    }

    fn as_type<T: DeserializeOwned>(
        &self,
        message_type: ServerMessageType,
    ) -> Result<T, RemoteSignError> {
        if self.typ == message_type {
            if let Some(value) = &self.payload {
                Ok(serde_json::from_value(value.clone())?)
            } else {
                Err(RemoteSignError::ClientState(
                    "no payload for requested type",
                ))
            }
        } else {
            Err(RemoteSignError::ClientState(
                "requested payload for wrong message type",
            ))
        }
    }

    fn as_error(&self) -> Result<ServerError, RemoteSignError> {
        self.as_type::<ServerError>(ServerMessageType::Error)
    }

    fn as_greeting(&self) -> Result<ServerGreeting, RemoteSignError> {
        self.as_type::<ServerGreeting>(ServerMessageType::Greeting)
    }

    fn as_session_joined(&self) -> Result<ServerJoined, RemoteSignError> {
        self.as_type::<ServerJoined>(ServerMessageType::SessionJoined)
    }

    fn as_peer_message(&self) -> Result<ServerPeerMessage, RemoteSignError> {
        self.as_type::<ServerPeerMessage>(ServerMessageType::PeerMessage)
    }

    fn as_session_closed(&self) -> Result<ServerSessionClosed, RemoteSignError> {
        self.as_type::<ServerSessionClosed>(ServerMessageType::SessionClosed)
    }
}

/// Response messages seen from server.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum ServerPayload {
    Error(ServerError),
    Greeting(ServerGreeting),
    SessionJoined(ServerJoined),
    PeerMessage(ServerPeerMessage),
    SessionClosed(ServerSessionClosed),
}

#[derive(Clone, Debug, Deserialize)]
struct ServerError {
    code: String,
    message: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ServerGreeting {
    apis: Vec<String>,
    motd: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct ServerJoined {
    context: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct ServerPeerMessage {
    message: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ServerSessionClosed {
    reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PeerMessageType {
    Ping,
    Pong,
    RequestSigningCertificate,
    SigningCertificate,
    SignRequest,
    Signature,
}

/// A peer-to-peer message.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct PeerMessage {
    #[serde(rename = "type")]
    typ: PeerMessageType,
    payload: Option<serde_json::Value>,
}

impl PeerMessage {
    fn require_type(self, typ: PeerMessageType) -> Result<Self, RemoteSignError> {
        if self.typ == typ {
            Ok(self)
        } else {
            Err(RemoteSignError::ServerUnexpectedMessage(format!(
                "{:?}",
                self.typ
            )))
        }
    }

    fn as_type<T: DeserializeOwned>(
        &self,
        message_type: PeerMessageType,
    ) -> Result<T, RemoteSignError> {
        if self.typ == message_type {
            if let Some(value) = &self.payload {
                Ok(serde_json::from_value(value.clone())?)
            } else {
                Err(RemoteSignError::ClientState(
                    "no payload for requested type",
                ))
            }
        } else {
            Err(RemoteSignError::ClientState(
                "requested payload for wrong message type",
            ))
        }
    }

    fn as_signing_certificate(&self) -> Result<PeerSigningCertificate, RemoteSignError> {
        self.as_type::<PeerSigningCertificate>(PeerMessageType::SigningCertificate)
    }

    fn as_sign_request(&self) -> Result<PeerSignRequest, RemoteSignError> {
        self.as_type::<PeerSignRequest>(PeerMessageType::SignRequest)
    }

    fn as_signature(&self) -> Result<PeerSignature, RemoteSignError> {
        self.as_type::<PeerSignature>(PeerMessageType::Signature)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PeerCertificate {
    certificate: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    chain: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum PeerPayload {
    SigningCertificate(PeerSigningCertificate),
    SignRequest(PeerSignRequest),
    Signature(PeerSignature),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PeerSigningCertificate {
    certificates: Vec<PeerCertificate>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PeerSignRequest {
    message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PeerSignature {
    message: String,
    signature: String,
    algorithm_oid: String,
}

const REQUIRED_ACTIONS: [&str; 4] = ["create-session", "join-session", "send-message", "goodbye"];

/// Represents the response from the server.
enum ServerResponse {
    /// Server closed the connection.
    Closed,

    /// A parsed protocol message.
    Message(ServerMessage),
}

/// A function that receives session information.
pub type SessionInfoCallback = fn(sjs_base64: &str, sjs_pem: &str) -> Result<(), RemoteSignError>;

