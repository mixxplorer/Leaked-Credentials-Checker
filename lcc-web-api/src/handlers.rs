#[derive(serde::Deserialize, schemars::JsonSchema, aide::OperationIo)]
pub struct HashCheckRequest {
    hash: String,
}

#[derive(serde::Serialize, schemars::JsonSchema, aide::OperationIo)]
#[aide(output)]
pub struct HashCheckResponse {
    leaked: bool,
    licenses: Vec<lcc_lib::util::License>,
}

#[derive(serde::Serialize, schemars::JsonSchema, aide::OperationIo)]
#[aide(output)]
pub struct HealthResponse {
    operational: bool,
    licenses: Vec<lcc_lib::util::License>,
}

pub fn health_desc(op: aide::transform::TransformOperation) -> aide::transform::TransformOperation {
    op.description("Returns whether the API is healthy").id("health")
}

pub fn check_hash_desc(op: aide::transform::TransformOperation) -> aide::transform::TransformOperation {
    op.description("Checks whether a hash appeared in a known credential leak.").id("checkHash")
}

pub async fn health(axum::extract::State(state): axum::extract::State<crate::AppState>) -> Result<axum::Json<HealthResponse>, crate::errors::WebAppError> {
    Ok(axum::Json(HealthResponse {
        operational: true, // as soon as the API is reachable, it is also operational
        licenses: state.hash_filter.licenses.clone(),
    }))
}

pub async fn check_hash(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
    axum::Json(payload): axum::Json<HashCheckRequest>,
) -> Result<axum::Json<HashCheckResponse>, crate::errors::WebAppError> {
    let check_items = lcc_lib::password_filter::hash_string_to_filter_items(&payload.hash);
    if let Err(err) = check_items {
        return Err(crate::errors::WebAppError::new(axum::http::StatusCode::BAD_REQUEST)
            .public_message("Invalid Hash passed.")
            .private_message(&format!("Hash = {}", payload.hash))
            .error(err));
    }
    let leaked = check_items?.iter().all(|item| state.hash_filter.contains(item));
    Ok(axum::Json(HashCheckResponse {
        leaked,
        licenses: state.hash_filter.licenses.clone(),
    }))
}
