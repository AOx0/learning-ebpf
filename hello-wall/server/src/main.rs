use axum::{routing::get, Router};

async fn hello() -> String {
    println!("Nuevo request");
    format!(
        "Hola desde el server {}",
        std::env::var("SERVER").unwrap_or_default()
    )
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let router = Router::new().route("/", get(hello));

    let tcp_listener = tokio::net::TcpListener::bind("[::]:5000").await?;

    axum::serve(tcp_listener, router.into_make_service()).await
}
