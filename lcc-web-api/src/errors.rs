use axum::{http::StatusCode, response::Response};

pub struct WebAppError {
    id: String,
    error: Option<anyhow::Error>,
    public_message: Option<String>,
    private_message: Option<String>,
    status_code: StatusCode,
}

#[derive(serde::Serialize, schemars::JsonSchema)]
struct WebAppPublicError {
    /// Error ID. Can be used by server admin to lookup exact error / backtrace
    id: String,

    /// Message shown to API user
    message: Option<String>,
}

impl WebAppError {
    pub fn new(status_code: StatusCode) -> Self {
        Self {
            id: lcc_lib::util::get_error_id(),
            status_code,
            public_message: None,
            private_message: None,
            error: None,
        }
    }

    /// Sets a message, which is shown to the API user
    pub fn public_message(mut self, public_message: &str) -> Self {
        self.public_message = Some(public_message.to_string());
        self
    }

    /// Sets a message, which is only logged on server-side
    pub fn private_message(mut self, private_message: &str) -> Self {
        self.private_message = Some(private_message.to_string());
        self
    }

    /// Sets the causing error.
    pub fn error(mut self, error: anyhow::Error) -> Self {
        self.error = Some(error);
        self
    }
}

// Tell axum how to convert `AppError` into a response.
impl axum::response::IntoResponse for WebAppError {
    fn into_response(self) -> Response {
        log::warn!(
            "[error_id={}] Error during handling request, causing code {}: private_message={:?} public_message={:?}, error={:?}",
            self.id,
            self.status_code,
            self.private_message,
            self.public_message,
            self.error
        );
        (
            self.status_code,
            axum::Json(WebAppPublicError {
                id: self.id,
                message: self.public_message,
            }),
        )
            .into_response()
    }
}

impl aide::OperationOutput for WebAppError {
    type Inner = String;

    fn inferred_responses(
        ctx: &mut aide::gen::GenContext,
        _operation: &mut aide::openapi::Operation,
    ) -> std::vec::Vec<(std::option::Option<u16>, aide::openapi::Response)> {
        let web_app_error_internal_response = aide::openapi::Response {
            description: "Internal Server Error".to_owned(),
            headers: indexmap::indexmap! {},
            content: indexmap::indexmap! {
                "application/json".to_owned() => aide::openapi::MediaType {
                    schema: Some(aide::openapi::SchemaObject {
                        json_schema: ctx.schema.subschema_for::<WebAppPublicError>(),
                        example: None,
                        external_docs: None,
                    }),
                    example: Some(serde_json::json!(WebAppPublicError{ id: lcc_lib::util::get_error_id(), message: Some("Example error message. Contact server admin to get more information.".to_owned()) })),
                    ..Default::default()
                }
            },
            links: indexmap::indexmap! {},
            extensions: indexmap::indexmap! {},
        };

        let web_app_error_bad_request_response = aide::openapi::Response {
            description: "Bad Request".to_owned(),
            headers: indexmap::indexmap! {},
            content: indexmap::indexmap! {
                "application/json".to_owned() => aide::openapi::MediaType {
                    schema: Some(aide::openapi::SchemaObject {
                        json_schema: ctx.schema.subschema_for::<WebAppPublicError>(),
                        example: None,
                        external_docs: None,
                    }),
                    example: Some(serde_json::json!(WebAppPublicError{ id: lcc_lib::util::get_error_id(), message: Some("Example error message about which validation failed. Contact server admin to get more information.".to_owned()) })),
                    ..Default::default()
                }
            },
            links: indexmap::indexmap! {},
            extensions: indexmap::indexmap! {},
        };

        vec![
            (Some(StatusCode::INTERNAL_SERVER_ERROR.into()), web_app_error_internal_response),
            (Some(StatusCode::BAD_REQUEST.into()), web_app_error_bad_request_response),
        ]
    }
}

// Anyhow Error -> WebAppError, so we can just use anyhow for the most part
impl<E> From<E> for WebAppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        let err_conv = err.into();
        Self {
            id: lcc_lib::util::get_error_id(),
            private_message: Some(err_conv.to_string()),
            error: Some(err_conv),
            public_message: None,
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
