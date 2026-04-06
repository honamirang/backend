//! Run with
//!
//! ```not_rust
//! cargo run -p example-hello-world
//! ```

use axum::{response::Html, routing::get, Json, Router, http::Method, routing::any};
use tower_http::cors::{Any, CorsLayer};
use tokio::net::TcpListener;

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