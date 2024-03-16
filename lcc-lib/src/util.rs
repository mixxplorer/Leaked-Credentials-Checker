/// License struct to denote license of the data
#[derive(bincode::Encode, bincode::Decode, serde::Serialize, schemars::JsonSchema, Clone)]
pub struct License {
    /// Which part of the software/data this license is for
    pub part: String,
    /// Who is the author
    pub author: String,
    /// Link to owner
    pub owner_url: String,
    /// Link to project
    pub project_url: String,
    /// Which license type is being used
    pub license: String,
}

pub fn get_error_id() -> String {
    use rand::distributions::{Alphanumeric, DistString};
    Alphanumeric.sample_string(&mut rand::thread_rng(), 10)
}
