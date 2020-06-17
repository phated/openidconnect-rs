use oauth2::AccessToken;
use std::str::FromStr;

use crate::http_types::headers::{HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use crate::http_types::Response;

pub const MIME_TYPE_JSON: &str = "application/json";
pub const MIME_TYPE_JWKS: &str = "application/jwk-set+json";
pub const MIME_TYPE_JWT: &str = "application/jwt";

pub const BEARER: &str = "Bearer";

// The [essence](https://mimesniff.spec.whatwg.org/#mime-type-essence) is the <type>/<subtype>
// representation.
pub fn content_type_has_essence(content_type: &HeaderValue, expected_essence: &str) -> bool {
    let ct = content_type.as_str();

    ct[..ct.find(';').unwrap_or_else(|| ct.len())].to_lowercase() == expected_essence.to_lowercase()
}

pub fn check_content_type(response: &Response, expected_content_type: &str) -> Result<(), String> {
    response.header(CONTENT_TYPE)
        .map_or(Ok(()), |content_type|
            // Section 3.1.1.1 of RFC 7231 indicates that media types are case insensitive and
            // may be followed by optional whitespace and/or a parameter (e.g., charset).
            // See https://tools.ietf.org/html/rfc7231#section-3.1.1.1.
            if !content_type.iter().any(|hv| content_type_has_essence(&hv, expected_content_type)) {
                Err(
                    format!(
                        "Unexpected response Content-Type: {:?}, should be `{}`",
                        content_type,
                        expected_content_type
                    )
                )
            } else {
                Ok(())
            }
        )
}

pub fn auth_bearer(access_token: &AccessToken) -> (HeaderName, HeaderValue) {
    (
        AUTHORIZATION,
        HeaderValue::from_str(&format!("{} {}", BEARER, access_token.secret()))
            .expect("invalid access token"),
    )
}
