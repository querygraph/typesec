//! Opaque labeled values for information-flow style data handling.
//!
//! This module adapts the central idea of SecLib's `Sec s a` container to the
//! `typesec` capability model. Sensitive data can be transformed while it stays
//! inside [`SecureValue`], but extracting or declassifying it requires an
//! explicit typed capability.

use std::marker::PhantomData;

use crate::{
    Capability, Resource,
    permissions::{CanDeclassify, CanReadSensitive},
};

/// Private sealing for built-in privacy labels.
pub(crate) mod sealed {
    /// Sealing trait for [`PrivacyLevel`][super::PrivacyLevel].
    pub trait Sealed {}
}

/// A type-level privacy label.
pub trait PrivacyLevel: sealed::Sealed + Send + Sync + 'static {
    /// Stable label name for logs, diagnostics, and generated code.
    fn name() -> &'static str;
}

/// Public data: safe to reveal without a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Public;

/// Internal data: not public, but below sensitive and secret data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Internal;

/// Sensitive data such as PII or confidential business records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sensitive;

/// Secret data such as credentials or highly restricted model inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Secret;

macro_rules! impl_privacy_level {
    ($($ty:ty => $name:literal),* $(,)?) => {
        $(
            impl sealed::Sealed for $ty {}
            impl PrivacyLevel for $ty {
                fn name() -> &'static str { $name }
            }
        )*
    };
}

impl_privacy_level! {
    Public => "public",
    Internal => "internal",
    Sensitive => "sensitive",
    Secret => "secret",
}

/// Type-level least upper bound for two privacy labels.
///
/// Combining values should keep the more restrictive label. For example,
/// `Join<Sensitive> for Public` yields `Sensitive`.
pub trait Join<Rhs: PrivacyLevel>: PrivacyLevel {
    /// The resulting label after both inputs influence the value.
    type Output: PrivacyLevel;
}

/// Resulting value type when two protected values are zipped.
pub type ZippedSecureValue<L, M, T, U, R> = SecureValue<<L as Join<M>>::Output, (T, U), R>;

macro_rules! impl_join {
    ($left:ty, $right:ty => $out:ty) => {
        impl Join<$right> for $left {
            type Output = $out;
        }
    };
}

impl_join!(Public, Public => Public);
impl_join!(Public, Internal => Internal);
impl_join!(Public, Sensitive => Sensitive);
impl_join!(Public, Secret => Secret);

impl_join!(Internal, Public => Internal);
impl_join!(Internal, Internal => Internal);
impl_join!(Internal, Sensitive => Sensitive);
impl_join!(Internal, Secret => Secret);

impl_join!(Sensitive, Public => Sensitive);
impl_join!(Sensitive, Internal => Sensitive);
impl_join!(Sensitive, Sensitive => Sensitive);
impl_join!(Sensitive, Secret => Secret);

impl_join!(Secret, Public => Secret);
impl_join!(Secret, Internal => Secret);
impl_join!(Secret, Sensitive => Secret);
impl_join!(Secret, Secret => Secret);

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
    resource_id: String,
    _label: PhantomData<fn() -> L>,
    _resource: PhantomData<fn() -> R>,
}

impl<L: PrivacyLevel, T, R: Resource> SecureValue<L, T, R> {
    /// Label `value` as protected data associated with `resource`.
    pub fn protect(value: T, resource: &R) -> Self {
        Self {
            value,
            resource_id: resource.resource_id().to_owned(),
            _label: PhantomData,
            _resource: PhantomData,
        }
    }

    /// Runtime identifier of the resource this value came from.
    pub fn resource_id(&self) -> &str {
        &self.resource_id
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
                left_resource: self.resource_id,
                right_resource: other.resource_id,
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
        capability_resource: &str,
    ) -> Result<(), SecureAccessError> {
        if capability_resource == self.resource_id {
            Ok(())
        } else {
            Err(SecureAccessError::ResourceMismatch {
                capability_resource: capability_resource.to_owned(),
                value_resource: self.resource_id.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        capability::{Capability, DEFAULT_CAPABILITY_TTL},
        permissions::{CanDeclassify, CanReadSensitive},
        resource::GenericResource,
    };
    use std::time::{Duration, SystemTime};

    #[test]
    fn map_preserves_label_and_resource() {
        let resource = GenericResource::new("customer/1", "customer");
        let value: SecureValue<Sensitive, String, GenericResource> =
            SecureValue::protect("alice@example.com".to_owned(), &resource);

        let len = value.map(|email| email.len());

        assert_eq!(
            SecureValue::<Sensitive, usize, GenericResource>::label_name(),
            "sensitive"
        );
        assert_eq!(len.resource_id(), "customer/1");
    }

    #[test]
    fn zip_uses_more_restrictive_label() {
        let resource = GenericResource::new("customer/1", "customer");
        let public: SecureValue<Public, u32, GenericResource> = SecureValue::protect(7, &resource);
        let secret: SecureValue<Secret, &str, GenericResource> =
            SecureValue::protect("token", &resource);

        let combined: SecureValue<Secret, (u32, &str), GenericResource> =
            public.zip(secret).expect("same resource id");

        assert_eq!(combined.resource_id(), "customer/1");
    }

    #[test]
    fn zip_rejects_different_resource_ids() {
        let left_resource = GenericResource::new("customer/1", "customer");
        let right_resource = GenericResource::new("customer/2", "customer");
        let public: SecureValue<Public, u32, GenericResource> =
            SecureValue::protect(7, &left_resource);
        let secret: SecureValue<Secret, &str, GenericResource> =
            SecureValue::protect("token", &right_resource);

        assert!(matches!(
            public.zip(secret),
            Err(SecureValueError::ResourceIdMismatch {
                left_resource,
                right_resource
            }) if left_resource == "customer/1" && right_resource == "customer/2"
        ));
    }

    #[test]
    fn public_values_can_be_unwrapped_without_capability() {
        let resource = GenericResource::new("report/1", "report");
        let public: SecureValue<Public, &str, GenericResource> =
            SecureValue::protect("ok", &resource);

        assert_eq!(public.into_public(), "ok");
    }

    #[test]
    fn sensitive_values_require_capability_to_reveal() {
        let resource = GenericResource::new("customer/1", "customer");
        let secret: SecureValue<Secret, &str, GenericResource> =
            SecureValue::protect("ssn", &resource);
        let cap: Capability<CanReadSensitive, GenericResource> =
            Capability::new_unchecked("agent:test", "customer/1");

        assert_eq!(secret.reveal(&cap).expect("matching resource"), "ssn");
    }

    #[test]
    fn declassify_makes_public_value() {
        let resource = GenericResource::new("metric/1", "metric");
        let sensitive: SecureValue<Sensitive, usize, GenericResource> =
            SecureValue::protect(42, &resource);
        let cap: Capability<CanDeclassify, GenericResource> =
            Capability::new_unchecked("agent:test", "metric/1");

        let public = sensitive.declassify(&cap).expect("matching resource");

        assert_eq!(public.into_public(), 42);
    }

    #[test]
    fn reveal_rejects_capability_for_other_resource_instance() {
        let resource = GenericResource::new("customer/1", "customer");
        let secret: SecureValue<Secret, &str, GenericResource> =
            SecureValue::protect("ssn", &resource);
        // Same resource *type*, different *instance*:
        let cap: Capability<CanReadSensitive, GenericResource> =
            Capability::new_unchecked("agent:test", "customer/2");

        assert!(matches!(
            secret.reveal(&cap),
            Err(SecureAccessError::ResourceMismatch { .. })
        ));
    }

    #[test]
    fn declassify_rejects_capability_for_other_resource_instance() {
        let resource = GenericResource::new("metric/1", "metric");
        let sensitive: SecureValue<Sensitive, usize, GenericResource> =
            SecureValue::protect(42, &resource);
        let cap: Capability<CanDeclassify, GenericResource> =
            Capability::new_unchecked("agent:test", "metric/other");

        assert!(matches!(
            sensitive.declassify(&cap),
            Err(SecureAccessError::ResourceMismatch { .. })
        ));
    }

    #[test]
    fn debug_redacts_protected_value() {
        let resource = GenericResource::new("customer/1", "customer");
        let secret: SecureValue<Secret, &str, GenericResource> =
            SecureValue::protect("ssn-123-45-6789", &resource);

        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("ssn-123-45-6789"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn reveal_rejects_expired_capability() {
        let resource = GenericResource::new("customer/1", "customer");
        let secret: SecureValue<Secret, &str, GenericResource> =
            SecureValue::protect("ssn", &resource);
        let issued_at = SystemTime::now()
            .checked_sub(DEFAULT_CAPABILITY_TTL + Duration::from_secs(1))
            .expect("time subtraction");
        let cap: Capability<CanReadSensitive, GenericResource> =
            Capability::new_with_issued_at("agent:test", "customer/1", issued_at);

        assert!(matches!(
            secret.reveal(&cap),
            Err(SecureAccessError::Capability(_))
        ));
    }
}
