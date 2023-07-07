use axum::{
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
    routing::{get, post},
    Router, Server,
};
use axum_sessions::{
    async_session::MemoryStore,
    extractors::{ReadableSession, WritableSession},
    SessionLayer,
};
use rand::Rng;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cookies = {
        let store = MemoryStore::new();
        let secret = rand::thread_rng().gen::<[u8; 128]>();
        SessionLayer::new(store, &secret)
    };

    let app = Router::new()
        .route("/logout", get(logout))
        .route_layer(axum::middleware::from_fn(extract))
        .route("/login", post(login))
        .layer(cookies);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8001));
    tracing::info!(addr = ?addr, "now listening");

    Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn extract<B>(
    session: ReadableSession,
    mut req: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    tracing::error!("entering extractor");

    let secret = session
        .get::<String>("secret")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if secret != "asdf" {
        return Err(StatusCode::UNAUTHORIZED);
    }

    req.extensions_mut().insert(secret);

    tracing::error!("leaving extractor");

    Ok(next.run(req).await)
}

async fn login(mut session: WritableSession) -> Result<(), StatusCode> {
    tracing::error!("entering login");
    session.insert("secret", "asdf").unwrap();
    Ok(())
}

async fn logout(mut session: WritableSession) -> StatusCode {
    tracing::error!("entering logout");
    session.destroy();
    StatusCode::OK
}
