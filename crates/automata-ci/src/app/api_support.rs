//! Shared wire contracts for authenticated JSON application APIs.

use axum::{
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ApiError {
    Unauthorized,
    Forbidden,
    NotFound,
    InvalidRequest,
    UnsupportedMediaType,
    TooLarge,
    Conflict,
    Unavailable,
    Internal,
}

impl ApiError {
    const fn status(self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::InvalidRequest => "invalid_request",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::TooLarge => "request_too_large",
            Self::Conflict => "conflict",
            Self::Unavailable => "dependency_unavailable",
            Self::Internal => "internal_error",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = json_response(self.status(), &ErrorDocument { error: self.code() });
        if self == Self::Unauthorized {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"automata\""),
            );
        }
        if self == Self::Unavailable {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        response
    }
}

#[derive(Debug, Serialize)]
struct ErrorDocument {
    error: &'static str,
}

pub(super) fn canonical_uuid(value: &str) -> Result<Uuid, ApiError> {
    let parsed = Uuid::parse_str(value).map_err(|_| ApiError::InvalidRequest)?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        return Err(ApiError::InvalidRequest);
    }
    Ok(parsed)
}

pub(super) fn is_json_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    value.to_str().is_ok_and(|value| {
        let mut parts = value.split(';');
        if !parts
            .next()
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
        {
            return false;
        }
        let Some(parameter) = parts.next() else {
            return true;
        };
        parts.next().is_none()
            && parameter
                .trim()
                .split_once('=')
                .is_some_and(|(name, value)| {
                    name.trim().eq_ignore_ascii_case("charset")
                        && value.trim().eq_ignore_ascii_case("utf-8")
                })
    })
}

pub(super) fn json_response<T: Serialize>(status: StatusCode, document: &T) -> Response {
    match serde_json::to_vec(document) {
        Ok(body) => (
            status,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            br#"{"error":"internal_error"}"#.as_slice(),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;

    use super::*;

    #[test]
    fn json_content_type_accepts_only_one_exact_json_media_type() {
        for valid in [
            "application/json",
            "APPLICATION/JSON",
            "application/json; charset=utf-8",
            "application/json ; CHARSET = UTF-8",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_str(valid).unwrap());
            assert!(is_json_content_type(&headers), "rejected {valid}");
        }

        assert!(!is_json_content_type(&HeaderMap::new()));
        for invalid in [
            "text/json",
            "application/json; charset=iso-8859-1",
            "application/json; profile=x",
            "application/json; charset=utf-8; charset=utf-8",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(invalid).unwrap(),
            );
            assert!(!is_json_content_type(&headers), "accepted {invalid}");
        }

        let mut duplicate = HeaderMap::new();
        duplicate.append(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        duplicate.append(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        assert!(!is_json_content_type(&duplicate));

        let mut opaque = HeaderMap::new();
        opaque.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        assert!(!is_json_content_type(&opaque));
    }

    #[test]
    fn canonical_uuid_accepts_only_lowercase_hyphenated_non_nil_text() {
        const VALUE: &str = "aaaaaaaa-1111-4111-8111-111111111111";

        assert_eq!(
            canonical_uuid(VALUE).unwrap().hyphenated().to_string(),
            VALUE
        );
        for invalid in [
            "not-a-uuid",
            "00000000-0000-0000-0000-000000000000",
            "AAAAAAAA-1111-4111-8111-111111111111",
            "aaaaaaaa111141118111111111111111",
            "{aaaaaaaa-1111-4111-8111-111111111111}",
        ] {
            assert_eq!(canonical_uuid(invalid), Err(ApiError::InvalidRequest));
        }
    }

    #[tokio::test]
    async fn every_api_error_has_the_exact_closed_wire_contract() {
        for (error, status, code) in [
            (
                ApiError::Unauthorized,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            ),
            (ApiError::Forbidden, StatusCode::FORBIDDEN, "forbidden"),
            (ApiError::NotFound, StatusCode::NOT_FOUND, "not_found"),
            (
                ApiError::InvalidRequest,
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
            (
                ApiError::UnsupportedMediaType,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
            ),
            (
                ApiError::TooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
            ),
            (ApiError::Conflict, StatusCode::CONFLICT, "conflict"),
            (
                ApiError::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "dependency_unavailable",
            ),
            (
                ApiError::Internal,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
        ] {
            assert_eq!(error.status(), status);
            assert_eq!(error.code(), code);

            let response = error.into_response();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            if error == ApiError::Unauthorized {
                assert_eq!(
                    response.headers()[header::WWW_AUTHENTICATE],
                    "Bearer realm=\"automata\""
                );
            } else {
                assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
            }
            if error == ApiError::Unavailable {
                assert_eq!(response.headers()[header::RETRY_AFTER], "1");
            } else {
                assert!(!response.headers().contains_key(header::RETRY_AFTER));
            }

            let body = to_bytes(response.into_body(), 1_024)
                .await
                .expect("error response body");
            assert_eq!(body.as_ref(), format!(r#"{{"error":"{code}"}}"#).as_bytes());
        }
    }

    #[derive(Debug, Serialize)]
    struct SuccessDocument {
        result: &'static str,
    }

    #[tokio::test]
    async fn json_response_is_compact_non_cacheable_json() {
        let response = json_response(StatusCode::CREATED, &SuccessDocument { result: "created" });
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body = to_bytes(response.into_body(), 1_024)
            .await
            .expect("success response body");
        assert_eq!(body.as_ref(), br#"{"result":"created"}"#);
    }

    #[derive(Debug)]
    struct SerializationFailure;

    impl Serialize for SerializationFailure {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(<S::Error as serde::ser::Error>::custom(
                "intentional serialization failure",
            ))
        }
    }

    #[tokio::test]
    async fn serialization_failure_uses_the_exact_internal_error_fallback() {
        let response = json_response(StatusCode::CREATED, &SerializationFailure);
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body = to_bytes(response.into_body(), 1_024)
            .await
            .expect("fallback response body");
        assert_eq!(body.as_ref(), br#"{"error":"internal_error"}"#);
    }
}
