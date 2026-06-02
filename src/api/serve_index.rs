use argon2::password_hash::rand_core::{OsRng, RngCore};
use axum::response::{IntoResponse, Response};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use http::{HeaderValue, StatusCode, header};

/// Read the bundled `index.html` from the embedded static dir.
#[cfg(feature = "embed-resource")]
fn read_index_html() -> Option<&'static str> {
    use include_dir::{Dir, include_dir};
    static INCLUDE_STATIC: Dir = include_dir!("$CARGO_MANIFEST_DIR/static");
    INCLUDE_STATIC
        .get_file("index.html")
        .and_then(|f| f.contents_utf8())
}

/// Read `index.html` from disk for the external-resource build.
#[cfg(feature = "external-resource")]
fn read_index_html() -> Option<String> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/static/index.html");
    std::fs::read_to_string(path).ok()
}

fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    B64.encode(bytes)
}

/// Inject a CSP nonce into Trunk's `<script type="module">` bootloader so the
/// browser accepts it under a strict `script-src 'nonce-...'` policy.
///
/// Handles both Trunk's recent placeholder form (`<script type="module" nonce>`)
/// and the plain form (`<script type="module">`).
fn inject_nonce(html: &str, nonce: &str) -> String {
    let target = format!(r#"<script type="module" nonce="{}">"#, nonce);
    html.replace(r#"<script type="module" nonce>"#, &target)
        .replace(r#"<script type="module">"#, &target)
}

fn build_csp(nonce: &str) -> String {
    format!(
        "default-src 'self'; \
         script-src 'self' 'wasm-unsafe-eval' 'nonce-{}'; \
         style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
         font-src 'self' https://fonts.gstatic.com data:; \
         img-src 'self' data:; \
         connect-src 'self'; \
         frame-ancestors 'none'; \
         form-action 'self'",
        nonce
    )
}

/// Serve the SPA's `index.html` with a fresh per-request CSP nonce.
pub async fn serve_index() -> Response {
    let Some(html) = read_index_html() else {
        return (StatusCode::NOT_FOUND, "index.html not found").into_response();
    };
    let html_ref: &str = &html;

    let nonce = generate_nonce();
    let body = inject_nonce(html_ref, &nonce);
    let csp = build_csp(&nonce);

    let mut response = (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response();

    if let Ok(value) = HeaderValue::from_str(&csp) {
        response
            .headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, value);
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_replaces_plain_script() {
        let html = r#"<head><script type="module">init()</script></head>"#;
        let out = inject_nonce(html, "abc123");
        assert!(out.contains(r#"<script type="module" nonce="abc123">init()</script>"#));
    }

    #[test]
    fn inject_replaces_empty_nonce_attribute() {
        let html = r#"<script type="module" nonce>init()</script>"#;
        let out = inject_nonce(html, "abc123");
        assert!(out.contains(r#"<script type="module" nonce="abc123">init()</script>"#));
    }

    #[test]
    fn csp_includes_font_sources() {
        let csp = build_csp("x");
        assert!(csp.contains("https://fonts.googleapis.com"));
        assert!(csp.contains("font-src 'self' https://fonts.gstatic.com"));
        assert!(csp.contains("'nonce-x'"));
        assert!(csp.contains("'wasm-unsafe-eval'"));
    }

    #[test]
    fn nonce_is_unique() {
        let a = generate_nonce();
        let b = generate_nonce();
        assert_ne!(a, b);
        assert!(!a.is_empty());
    }
}
