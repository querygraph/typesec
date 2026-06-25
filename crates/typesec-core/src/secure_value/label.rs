//! Privacy labels and their type-level least-upper-bound lattice.
//!
//! The four built-in labels ([`Public`], [`Internal`], [`Sensitive`], [`Secret`])
//! are sealed zero-sized markers. [`Join`] encodes, at the type level, which label
//! results when two protected values are combined: always the more restrictive of
//! the two. These types parameterise [`SecureValue`][super::SecureValue].

/// Private sealing for built-in privacy labels.
pub(crate) mod sealed {
    /// Sealing trait for [`PrivacyLevel`][super::super::PrivacyLevel].
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
