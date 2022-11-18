use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    time::Duration,
};

use async_trait::async_trait;
use http_types::{Body, Method, Request, Response, StatusCode, Url};
use nanorpc::{RpcTransport, JrpcRequest, JrpcResponse};
use smol::net::TcpStream;
use themelio_stf::{melvm::Covenant, HexBytes, PoolKey};
use themelio_structs::{
    CoinData, CoinID, Denom, Header, PoolState, StakeDoc, Transaction, TxHash, TxKind,
};
use anyhow::anyhow;


/// A client to a particular wallet daemon.
#[derive(Clone, Debug)]
pub struct DaemonClient {
    endpoint: SocketAddr,
}

#[async_trait]
impl RpcTransport for DaemonClient {
    type Error = anyhow::Error;

    async fn call_raw(&self, req: JrpcRequest) -> Result<JrpcResponse, Self::Error> {
        let to_send = serde_json::to_string((&req)).unwrap();
        let mut res = http_post(self.endpoint, "", &to_send)
        .await
        .map_err(|_| anyhow!("failed to POST to melwalletd"))?;
        let result: JrpcResponse = res.body_json()
        .await
        .map_err(|_| anyhow!("Unable to deserialize response"))?;
        return Ok(result)
    }
}
impl DaemonClient {
    /// Creates a new client.
    pub fn new(endpoint: SocketAddr) -> Self {
        Self { endpoint }
    }
}

async fn http_get(endpoint: SocketAddr, path: &str) -> http_types::Result<Response> {
    let conn = TcpStream::connect(endpoint).await?;
    let mut req = Request::new(
        Method::Get,
        Url::parse(&format!("http://{}/{}", endpoint, path))?,
    );
    async_h1::connect(conn, req).await
}
async fn http_post(endpoint: SocketAddr, path: &str, body: &str) -> http_types::Result<Response> {
    let conn = TcpStream::connect(endpoint).await?;
    let mut req = Request::new(
        Method::Post,
        Url::parse(&format!("http://{}/", endpoint))?,
    );
    req.set_body(body);
    async_h1::connect(conn, req).await
}
#[allow(dead_code)]
async fn http_put(endpoint: SocketAddr, path: &str) -> http_types::Result<Response> {
    let conn = TcpStream::connect(endpoint).await?;
    let mut req = Request::new(
        Method::Put,
        Url::parse(&format!("http://{}/{}", endpoint, path))?,
    );
    async_h1::connect(conn, req).await
}

async fn http_with_body(
    endpoint: SocketAddr,
    path: &str,
    method: Method,
    body: impl Into<Body>,
) -> http_types::Result<Response> {
    let mut req = Request::new(
        method,
        Url::parse(&format!("http://{}/{}", endpoint, path))?,
    );
    req.set_body(body);
   
    let conn = TcpStream::connect(endpoint).await?;
    async_h1::connect(conn, req).await
}
