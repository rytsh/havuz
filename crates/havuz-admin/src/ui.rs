//! Dashboard serving.
//!
//! Two ways to get the UI in front of an operator:
//!
//! * `--features embed-ui` bakes `ui/dist` into the binary, keeping the
//!   single-file deployment story intact.
//! * Without that feature, `HAVUZ_UI_DIR` serves the same files from disk. This
//!   is what a `pnpm dev` loop uses, and it means a Rust-only contributor never
//!   needs a Node toolchain to build the project.

use axum::extract::State;
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

use crate::state::AdminState;

pub const UI_DIR_ENV: &str = "HAVUZ_UI_DIR";

#[cfg(feature = "embed-ui")]
#[derive(rust_embed::Embed)]
#[folder = "$CARGO_MANIFEST_DIR/../../ui/dist"]
struct Assets;

pub async fn serve(State(state): State<AdminState>, uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    // Never let an unmatched API path fall through to the SPA; a 404 that
    // returns HTML is very hard to debug from the client side.
    if path.starts_with("api/") {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "error": { "code": "not_found", "message": format!("no route for /{path}") }
            })),
        )
            .into_response();
    }

    if !state.serve_ui {
        return (StatusCode::NOT_FOUND, "dashboard is disabled").into_response();
    }

    let requested = if path.is_empty() { "index.html" } else { path };

    if let Some(response) = from_disk(requested) {
        return response;
    }
    if let Some(response) = from_embed(requested) {
        return response;
    }

    // Single-page app: unknown paths fall back to the entry point so client
    // side routing works on a hard refresh.
    if let Some(response) = from_disk("index.html").or_else(|| from_embed("index.html")) {
        return response;
    }

    (StatusCode::NOT_FOUND, PLACEHOLDER).into_response()
}

fn from_disk(path: &str) -> Option<Response> {
    let dir = std::env::var(UI_DIR_ENV).ok()?;
    let root = std::path::Path::new(&dir).canonicalize().ok()?;
    let candidate = root.join(path).canonicalize().ok()?;

    // Reject anything that escapes the asset root. Without this check a
    // request for `../../etc/passwd` would be served happily.
    if !candidate.starts_with(&root) {
        return None;
    }

    let bytes = std::fs::read(&candidate).ok()?;
    Some(with_content_type(path, bytes))
}

#[cfg(feature = "embed-ui")]
fn from_embed(path: &str) -> Option<Response> {
    let file = Assets::get(path)?;
    Some(with_content_type(path, file.data.into_owned()))
}

#[cfg(not(feature = "embed-ui"))]
fn from_embed(_path: &str) -> Option<Response> {
    None
}

fn with_content_type(path: &str, bytes: Vec<u8>) -> Response {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    ([(header::CONTENT_TYPE, mime.as_ref())], bytes).into_response()
}

const PLACEHOLDER: &str = "\
havuz is running, but no dashboard assets were found.

Build the UI:      cd ui && pnpm install && pnpm build
Serve from disk:   HAVUZ_UI_DIR=ui/dist havuz
Bake into binary:  cargo build --release -p havuz-server --features havuz-admin/embed-ui

The API is available at /api/v1/ regardless.
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_type_follows_the_extension() {
        let response = with_content_type("app.js", b"//".to_vec());
        assert!(response.headers()[header::CONTENT_TYPE].to_str().unwrap().contains("javascript"));

        let response = with_content_type("index.html", b"<!doctype html>".to_vec());
        assert!(response.headers()[header::CONTENT_TYPE].to_str().unwrap().contains("html"));

        let response = with_content_type("logo.svg", b"<svg/>".to_vec());
        assert!(response.headers()[header::CONTENT_TYPE].to_str().unwrap().contains("svg"));
    }

    #[test]
    fn traversal_outside_the_asset_root_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), b"<html/>").unwrap();
        std::env::set_var(UI_DIR_ENV, dir.path());

        assert!(from_disk("index.html").is_some(), "a normal asset is served");
        assert!(from_disk("../../../etc/passwd").is_none(), "traversal must not escape the root");
        assert!(from_disk("nope.js").is_none());

        std::env::remove_var(UI_DIR_ENV);
    }

    #[test]
    fn the_placeholder_tells_the_operator_what_to_do() {
        assert!(PLACEHOLDER.contains("pnpm build"));
        assert!(PLACEHOLDER.contains(UI_DIR_ENV));
        assert!(PLACEHOLDER.contains("/api/v1/"));
    }
}
