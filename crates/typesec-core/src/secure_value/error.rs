//! Errors for reading, declassifying, and combining protected values.

/// Error returned when a capability does not authorize access to a protected value.
#[derive(Debug, thiserror::Error)]
pub enum SecureAccessError {
    /// The capability lease has expired.
    #[error(transparent)]
    Capability(#[from] crate::CapabilityUseError),
    /// The capability covers a different resource instance than the protected value.
    #[error(
        "capability for resource '{capability_resource}' does not cover protected value from '{value_resource}'"
    )]
    ResourceMismatch {
        /// Resource id the capability was minted for.
        capability_resource: String,
        /// Resource id the protected value is tied to.
        value_resource: String,
    },
}

/// Error returned when protected values cannot be safely combined.
#[derive(Debug, thiserror::Error)]
pub enum SecureValueError {
    /// The two values came from different resource instances.
    #[error(
        "cannot combine protected values from resources '{left_resource}' and '{right_resource}'"
    )]
    ResourceIdMismatch {
        /// Resource id of the left value.
        left_resource: String,
        /// Resource id of the right value.
        right_resource: String,
    },
}
