//! A basic OAuth 1.0 server implementation used for testing the client.

#[macro_use]
extern crate log;

mod authorization;
mod handler;

use std::convert::Infallible;
use std::net::SocketAddr;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Response, Server, StatusCode};

#[tokio::main]
async fn main() {
    env_logger::init();

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));

    let service = service_fn(|req| async {
        info!("{:?}", req);

        let res = match (req.method(), req.uri().path()) {
            (&http::Method::GET, "/echo") | (&http::Method::POST, "/echo") => {
                handler::echo(req).await
            }
            (&http::Method::POST, "/request_temp_credentials") => {
                handler::post_request_temp_credentials(req).await
            }
            (&http::Method::POST, "/request_token") => handler::post_request_token(req).await,
            _ => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::default())
                .unwrap(),
        };
        info!("{:?}", res);

        Ok::<_, Infallible>(res)
    });
    let make_service = make_service_fn(|_| async move { Ok::<_, Infallible>(service) });

    Server::bind(&addr).serve(make_service).await.unwrap();
}
