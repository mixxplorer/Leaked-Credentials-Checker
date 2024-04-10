use axum::{extract::State, http::StatusCode, Json};

use crate::errors;
use crate::AppState;

#[derive(serde::Deserialize)]
pub struct HashCheckRequest {
    hash: String,
}

pub async fn check_hash(State(state): State<AppState>, Json(payload): Json<HashCheckRequest>) -> Result<Json<serde_json::Value>, errors::WebAppError> {
    let check_items = lcc_lib::password_filter::hash_string_to_filter_items(&payload.hash);
    if let Err(err) = check_items {
        return Err(errors::WebAppError::new(StatusCode::BAD_REQUEST)
            .public_message("Invalid Hash passed.")
            .private_message(&format!("Hash = {}", payload.hash))
            .error(err));
    }
    let leaked = check_items?.iter().all(|item| state.hash_filter.contains(item));
    Ok(Json(serde_json::json!({ "leaked": leaked, "licenses": state.hash_filter.licenses })))
}
