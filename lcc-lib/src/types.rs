mod private {
    /// Private trait, see https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
    pub trait AttributeSealedState {}
}

/// [Typestate](https://cliffle.com/blog/rust-typestate/) base trait indicating whether an attribute is set or not
pub trait AttributeState: private::AttributeSealedState + Clone + serde::de::DeserializeOwned {}

/// [Typestate](https://cliffle.com/blog/rust-typestate/) indicating an attribute is not set
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct AttributeNotSet;
impl AttributeState for AttributeNotSet {}
impl private::AttributeSealedState for AttributeNotSet {}

/// [Typestate](https://cliffle.com/blog/rust-typestate/) indicating an attribute is set
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct AttributeSet;
impl AttributeState for AttributeSet {}
impl private::AttributeSealedState for AttributeSet {}
