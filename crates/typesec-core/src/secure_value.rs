//! Opaque labeled values for information-flow style data handling.
//!
//! This module adapts the central idea of SecLib's `Sec s a` container to the
//! `typesec` capability model. Sensitive data can be transformed while it stays
//! inside [`SecureValue`], but extracting or declassifying it requires an
//! explicit typed capability.

use std::marker::PhantomData;

use crate::{
    Capability, Resource, ResourceId,
    permissions::{CanDeclassify, CanReadInternal, CanReadSensitive},
};

mod error;
mod label;

pub use error::{SecureAccessError, SecureValueError};
pub use label::{Internal, Join, PrivacyLevel, Public, Secret, Sensitive};

/// Resulting value type when two protected values are zipped.
pub type ZippedSecureValue<L, M, T, U, R> = SecureValue<<L as Join<M>>::Output, (T, U), R>;

/// Data protected by a type-level privacy label and resource type.
///
/// The inner value is private. Callers can transform it with [`map`][Self::map]
/// and [`zip`][Self::zip], but cannot observe it unless it is public or they hold
/// an appropriate capability for resource `R` *with a matching resource id*.
///
/// `SecureValue` deliberately does **not** implement `PartialEq` or derive
/// `Debug` over the inner value: equality would act as an oracle for guessing
/// protected contents, and `Debug` would print them into logs. The manual
/// `Debug` impl below redacts the payload.
#[derive(Clone)]
pub struct SecureValue<L: PrivacyLevel, T, R: Resource> {
    value: T,
    resource_id: ResourceId,
    _label: PhantomData<fn() -> L>,
    _resource: PhantomData<fn() -> R>,
}

impl<L: PrivacyLevel, T, R: Resource> SecureValue<L, T, R> {
    /// Label `value` as protected data associated with `resource`.
    pub fn protect(value: T, resource: &R) -> Self {
        Self {
            value,
            resource_id: ResourceId::from(resource.resource_id()),
            _label: PhantomData,
            _resource: PhantomData,
        }
    }

    /// Runtime identifier of the resource this value came from.
    pub fn resource_id(&self) -> &str {
        self.resource_id.as_str()
    }

    /// The type-level privacy label name.
    pub fn label_name() -> &'static str {
        L::name()
    }

    /// Transform the contained value without changing its label.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> SecureValue<L, U, R> {
        SecureValue {
            value: f(self.value),
            resource_id: self.resource_id,
            _label: PhantomData,
            _resource: PhantomData,
        }
    }

    /// Combine two protected values and keep the more restrictive label.
    ///
    /// Both values must be tied to the same resource type and the same runtime
    /// resource id. Callers that combine multiple records should use a domain
    /// resource type whose id represents that aggregate.
    #[must_use = "zipping protected values can fail when resource ids differ"]
    pub fn zip<M: PrivacyLevel, U>(
        self,
        other: SecureValue<M, U, R>,
    ) -> Result<ZippedSecureValue<L, M, T, U, R>, SecureValueError>
    where
        L: Join<M>,
    {
        if self.resource_id != other.resource_id {
            return Err(SecureValueError::ResourceIdMismatch {
                left_resource: self.resource_id.to_string(),
                right_resource: other.resource_id.to_string(),
            });
        }

        Ok(SecureValue {
            value: (self.value, other.value),
            resource_id: self.resource_id,
            _label: PhantomData,
            _resource: PhantomData,
        })
    }

    /// Reveal protected data with sensitive-read authority.
    ///
    /// The capability must have been minted for the *same resource instance*
    /// this value is tied to — a capability for `customer/2` cannot reveal
    /// data protected under `customer/1`, even though both share the resource
    /// type `R`.
    #[must_use = "revealing protected data can fail and returns the protected value"]
    pub fn reveal(
        self,
        capability: &Capability<CanReadSensitive, R>,
    ) -> Result<T, SecureAccessError> {
        capability.ensure_active()?;
        self.check_capability_resource(capability.resource_id())?;
        Ok(self.value)
    }

    /// Lower the label to public with explicit declassification authority.
    ///
    /// Like [`reveal`][Self::reveal], the capability's resource id must match
    /// the protected value's resource id.
    #[must_use = "declassification can fail and returns a relabeled value"]
    pub fn declassify(
        self,
        capability: &Capability<CanDeclassify, R>,
    ) -> Result<SecureValue<Public, T, R>, SecureAccessError> {
        capability.ensure_active()?;
        self.check_capability_resource(capability.resource_id())?;
        Ok(SecureValue {
            value: self.value,
            resource_id: self.resource_id,
            _label: PhantomData,
            _resource: PhantomData,
        })
    }

    fn check_capability_resource(
        &self,
        capability_resource: &ResourceId,
    ) -> Result<(), SecureAccessError> {
        if capability_resource == &self.resource_id {
            Ok(())
        } else {
            Err(SecureAccessError::ResourceMismatch {
                capability_resource: capability_resource.to_string(),
                value_resource: self.resource_id.to_string(),
            })
        }
    }
}

impl<L: PrivacyLevel, T, R: Resource> std::fmt::Debug for SecureValue<L, T, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureValue")
            .field("label", &L::name())
            .field("resource_id", &self.resource_id)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl<T, R: Resource> SecureValue<Public, T, R> {
    /// Extract public data without a capability.
    pub fn into_public(self) -> T {
        self.value
    }
}

impl<T, R: Resource> SecureValue<Internal, T, R> {
    /// Reveal internal data with internal-read authority.
    ///
    /// This is intentionally weaker than [`reveal`][SecureValue::reveal]:
    /// internal data does not require `CanReadSensitive`, while sensitive and
    /// secret data still do. The capability must cover the same resource id.
    #[must_use = "revealing internal data can fail and returns the protected value"]
    pub fn reveal_internal(
        self,
        capability: &Capability<CanReadInternal, R>,
    ) -> Result<T, SecureAccessError> {
        capability.ensure_active()?;
        self.check_capability_resource(capability.resource_id())?;
        Ok(self.value)
    }
}

#[cfg(test)]
mod tests;
