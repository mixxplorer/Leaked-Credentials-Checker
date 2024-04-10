use axum::{http::StatusCode, response::Response};

pub struct WebAppError {
    id: String,
    error: Option<anyhow::Error>,
    public_message: Option<String>,
    private_message: Option<String>,
    status_code: StatusCode,
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

    pub fn public_message(mut self, public_message: &str) -> Self {
        self.public_message = Some(public_message.to_string());
        self
    }

    pub fn private_message(mut self, private_message: &str) -> Self {
        self.private_message = Some(private_message.to_string());
        self
    }

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
            axum::Json(serde_json::json!({
                "message": self.public_message,
                "id": self.id,
            })),
        )
            .into_response()
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
