use std::{
    net::SocketAddr,
};

use async_trait::async_trait;
use http_types::{Method, Request, Response, Url};
use nanorpc::{RpcTransport, JrpcRequest, JrpcResponse};
use smol::net::TcpStream;


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
        let to_send = serde_json::to_string(&req).unwrap();
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


async fn http_post(endpoint: SocketAddr, _path: &str, body: &str) -> http_types::Result<Response> {
    let conn = TcpStream::connect(endpoint).await?;
    let mut req = Request::new(
        Method::Post,
        Url::parse(&format!("http://{}/", endpoint))?,
    );
    req.set_body(body);
    async_h1::connect(conn, req).await
}
