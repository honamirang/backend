#![deny(unused_mut)]
#![deny(unused_imports)]

mod fetch;

use axum::{response::Html, routing::get, Json, Router, http::Method, routing::any};
use tower_http::cors::{Any, CorsLayer};
use tokio::net::TcpListener;
use crate::fetch::fetch_timetable;

#[tokio::main]
async fn main() {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([]);
    // build our application with a route
    let app = Router::new()
        .route("/", any(handler))
        .route("/sans", get(sans_handler))
        .route("/fetch", get(fetch_handler))
        .layer(cors);

    // run it
    let listener = TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await;
}

async fn handler(method: Method) -> Json<&'static str> {
    Json("{ hello_world: \"Hello, world\" }")
}

async fn sans_handler() -> Html<&'static str> {
    Html("<h1>Sans</h1>")
}

async fn fetch_handler() {
    fetch_timetable("", "");
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_fetch() {
        let data = fetch_timetable("", "").unwrap();
        println!("{:?}", data);
    }
}