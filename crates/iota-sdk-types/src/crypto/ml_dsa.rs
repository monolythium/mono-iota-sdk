// Copyright (c) 2026 Mono Labs
// SPDX-License-Identifier: Apache-2.0

//! ML-DSA-65 user-authenticator wire types.

use base64ct::{Base64, Encoding};

use super::{PublicKeyExt, SignatureScheme};

/// Domain prefix for version-one ML-DSA-65 signing intents.
pub const ML_DSA_65_INTENT_V1_DOMAIN: &[u8] = b"MONO_ML_DSA_65_INTENT_V1";
/// Canonical byte length of a version-one ML-DSA-65 signing intent.
pub const ML_DSA_65_INTENT_V1_LEN: usize = ML_DSA_65_INTENT_V1_DOMAIN.len() + 155;
/// Canonical FIPS-204 ML-DSA-65 public-key length.
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1_952;
/// Canonical FIPS-204 ML-DSA-65 signature length.
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3_309;
/// Canonical byte length of a version-one ML-DSA-65 user authenticator.
pub const ML_DSA_65_AUTHENTICATOR_V1_LEN: usize =
    1 + ML_DSA_65_INTENT_V1_LEN + ML_DSA_65_SIGNATURE_LEN + ML_DSA_65_PUBLIC_KEY_LEN;
/// BCS byte length of a version-one authenticator, including its two-byte
/// ULEB128 prefix.
pub const ML_DSA_65_AUTHENTICATOR_V1_BCS_LEN: usize = 2 + ML_DSA_65_AUTHENTICATOR_V1_LEN;

const USER_ROLE: u8 = 0;
const USER_TRANSACTION_PURPOSE: u8 = 0;
const NON_CLUSTER_ID: [u8; 32] = [0; 32];

/// Error decoding an ML-DSA-65 authenticator or one of its components.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MlDsa65AuthenticatorError {
    #[error("invalid {field} length: expected {expected}, got {actual}")]
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("invalid ML-DSA-65 authenticator scheme flag: {0:#04x}")]
    InvalidAuthenticatorScheme(u8),
    #[error("invalid ML-DSA-65 signing intent domain")]
    InvalidIntentDomain,
    #[error("invalid ML-DSA-65 signing intent scheme flag: {0:#04x}")]
    InvalidIntentScheme(u8),
    #[error("invalid ML-DSA-65 user signing intent field: {0}")]
    InvalidUserIntent(&'static str),
    #[error("invalid base64: {0}")]
    Base64(#[from] base64ct::Error),
}

/// A fixed-width FIPS-204 ML-DSA-65 public key.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MlDsa65PublicKey(Box<[u8]>);

impl MlDsa65PublicKey {
    /// The fixed public-key length.
    pub const LENGTH: usize = ML_DSA_65_PUBLIC_KEY_LEN;

    /// Constructs a public key from its fixed-width encoding.
    #[must_use]
    pub fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(Box::from(bytes))
    }

    /// Parses a fixed-width public key.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, MlDsa65AuthenticatorError> {
        fixed_bytes("ML-DSA-65 public key", Self::LENGTH, bytes.as_ref()).map(Self)
    }

    /// Returns the fixed-width public-key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for MlDsa65PublicKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("MlDsa65PublicKey")
            .field("length", &self.0.len())
            .finish()
    }
}

impl PublicKeyExt for MlDsa65PublicKey {
    type FromBytesErr = MlDsa65AuthenticatorError;

    fn as_bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Self::FromBytesErr> {
        Self::from_bytes(bytes)
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::MlDsa65
    }
}

impl AsRef<[u8]> for MlDsa65PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl core::fmt::Display for MlDsa65PublicKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&Base64::encode_string(self.as_bytes()))
    }
}

impl core::str::FromStr for MlDsa65PublicKey {
    type Err = MlDsa65AuthenticatorError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(Base64::decode_vec(value)?)
    }
}

/// A fixed-width FIPS-204 ML-DSA-65 signature.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MlDsa65Signature(Box<[u8]>);

impl MlDsa65Signature {
    /// The fixed signature length.
    pub const LENGTH: usize = ML_DSA_65_SIGNATURE_LEN;

    /// Constructs a signature from its fixed-width encoding.
    #[must_use]
    pub fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(Box::from(bytes))
    }

    /// Parses a fixed-width signature.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, MlDsa65AuthenticatorError> {
        fixed_bytes("ML-DSA-65 signature", Self::LENGTH, bytes.as_ref()).map(Self)
    }

    /// Returns the fixed-width signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for MlDsa65Signature {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("MlDsa65Signature")
            .field("length", &self.0.len())
            .finish()
    }
}

impl AsRef<[u8]> for MlDsa65Signature {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl core::fmt::Display for MlDsa65Signature {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&Base64::encode_string(self.as_bytes()))
    }
}

impl core::str::FromStr for MlDsa65Signature {
    type Err = MlDsa65AuthenticatorError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(Base64::decode_vec(value)?)
    }
}

/// Context committed to by a version-one ML-DSA-65 user signature.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MlDsa65SigningIntentV1 {
    network_id: [u8; 32],
    genesis_digest: [u8; 32],
    protocol_version: u64,
    epoch: u64,
    message_digest: [u8; 32],
}

impl MlDsa65SigningIntentV1 {
    /// Constructs the canonical user-transaction signing intent.
    #[must_use]
    pub const fn new(
        network_id: [u8; 32],
        genesis_digest: [u8; 32],
        protocol_version: u64,
        epoch: u64,
        message_digest: [u8; 32],
    ) -> Self {
        Self {
            network_id,
            genesis_digest,
            protocol_version,
            epoch,
            message_digest,
        }
    }

    /// Parses and validates a canonical user-transaction signing intent.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, MlDsa65AuthenticatorError> {
        let bytes = bytes.as_ref();
        require_length("ML-DSA-65 signing intent", ML_DSA_65_INTENT_V1_LEN, bytes)?;

        let mut offset = 0;
        let domain = take::<{ ML_DSA_65_INTENT_V1_DOMAIN.len() }>(bytes, &mut offset);
        if domain.as_slice() != ML_DSA_65_INTENT_V1_DOMAIN {
            return Err(MlDsa65AuthenticatorError::InvalidIntentDomain);
        }

        let scheme = take::<1>(bytes, &mut offset)[0];
        if scheme != SignatureScheme::MlDsa65.to_u8() {
            return Err(MlDsa65AuthenticatorError::InvalidIntentScheme(scheme));
        }

        let network_id = take::<32>(bytes, &mut offset);
        let genesis_digest = take::<32>(bytes, &mut offset);
        let protocol_version = u64::from_be_bytes(take::<8>(bytes, &mut offset));
        let epoch = u64::from_be_bytes(take::<8>(bytes, &mut offset));
        let cluster_id = take::<32>(bytes, &mut offset);
        let role = take::<1>(bytes, &mut offset)[0];
        let purpose = take::<1>(bytes, &mut offset)[0];
        let sequence = u64::from_be_bytes(take::<8>(bytes, &mut offset));
        let message_digest = take::<32>(bytes, &mut offset);

        if cluster_id != NON_CLUSTER_ID {
            return Err(MlDsa65AuthenticatorError::InvalidUserIntent("cluster id"));
        }
        if role != USER_ROLE {
            return Err(MlDsa65AuthenticatorError::InvalidUserIntent("role"));
        }
        if purpose != USER_TRANSACTION_PURPOSE {
            return Err(MlDsa65AuthenticatorError::InvalidUserIntent("purpose"));
        }
        if sequence != 0 {
            return Err(MlDsa65AuthenticatorError::InvalidUserIntent("sequence"));
        }

        Ok(Self::new(
            network_id,
            genesis_digest,
            protocol_version,
            epoch,
            message_digest,
        ))
    }

    /// Encodes the intent as domain, scheme, context, role, purpose, and
    /// digest.
    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ML_DSA_65_INTENT_V1_LEN);
        bytes.extend_from_slice(ML_DSA_65_INTENT_V1_DOMAIN);
        bytes.push(SignatureScheme::MlDsa65.to_u8());
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.genesis_digest);
        bytes.extend_from_slice(&self.protocol_version.to_be_bytes());
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&NON_CLUSTER_ID);
        bytes.push(USER_ROLE);
        bytes.push(USER_TRANSACTION_PURPOSE);
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&self.message_digest);
        bytes
    }

    /// Returns the network identifier.
    #[must_use]
    pub const fn network_id(self) -> [u8; 32] {
        self.network_id
    }

    /// Returns the genesis digest.
    #[must_use]
    pub const fn genesis_digest(self) -> [u8; 32] {
        self.genesis_digest
    }

    /// Returns the active protocol version.
    #[must_use]
    pub const fn protocol_version(self) -> u64 {
        self.protocol_version
    }

    /// Returns the epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Returns the signed transaction-message digest.
    #[must_use]
    pub const fn message_digest(self) -> [u8; 32] {
        self.message_digest
    }
}

/// A fixed-width, self-describing ML-DSA-65 user authenticator.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MlDsa65AuthenticatorV1 {
    intent: MlDsa65SigningIntentV1,
    signature: MlDsa65Signature,
    public_key: MlDsa65PublicKey,
}

impl MlDsa65AuthenticatorV1 {
    /// Constructs an authenticator from fixed-width components.
    #[must_use]
    pub fn new(
        intent: MlDsa65SigningIntentV1,
        signature: MlDsa65Signature,
        public_key: MlDsa65PublicKey,
    ) -> Self {
        Self {
            intent,
            signature,
            public_key,
        }
    }

    /// Parses `scheme || intent || signature || public-key`.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, MlDsa65AuthenticatorError> {
        let bytes = bytes.as_ref();
        require_length(
            "ML-DSA-65 authenticator",
            ML_DSA_65_AUTHENTICATOR_V1_LEN,
            bytes,
        )?;

        if bytes[0] != SignatureScheme::MlDsa65.to_u8() {
            return Err(MlDsa65AuthenticatorError::InvalidAuthenticatorScheme(
                bytes[0],
            ));
        }

        let intent_end = 1 + ML_DSA_65_INTENT_V1_LEN;
        let signature_end = intent_end + ML_DSA_65_SIGNATURE_LEN;
        let intent = MlDsa65SigningIntentV1::from_bytes(&bytes[1..intent_end])?;
        let signature = MlDsa65Signature::from_bytes(&bytes[intent_end..signature_end])?;
        let public_key = MlDsa65PublicKey::from_bytes(&bytes[signature_end..])?;
        Ok(Self::new(intent, signature, public_key))
    }

    /// Encodes `scheme || intent || signature || public-key`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ML_DSA_65_AUTHENTICATOR_V1_LEN);
        bytes.push(SignatureScheme::MlDsa65.to_u8());
        bytes.extend_from_slice(&self.intent.to_bytes());
        bytes.extend_from_slice(self.signature.as_bytes());
        bytes.extend_from_slice(self.public_key.as_bytes());
        bytes
    }

    /// Base64-encodes the canonical authenticator bytes.
    #[must_use]
    pub fn to_base64(&self) -> String {
        Base64::encode_string(&self.to_bytes())
    }

    /// Decodes a base64-encoded canonical authenticator.
    pub fn from_base64(value: &str) -> Result<Self, MlDsa65AuthenticatorError> {
        Self::from_bytes(Base64::decode_vec(value)?)
    }

    /// Returns the signed intent.
    #[must_use]
    pub const fn intent(&self) -> MlDsa65SigningIntentV1 {
        self.intent
    }

    /// Returns the ML-DSA-65 signature.
    #[must_use]
    pub const fn signature(&self) -> &MlDsa65Signature {
        &self.signature
    }

    /// Returns the ML-DSA-65 public key.
    #[must_use]
    pub const fn public_key(&self) -> &MlDsa65PublicKey {
        &self.public_key
    }
}

fn require_length(
    field: &'static str,
    expected: usize,
    bytes: &[u8],
) -> Result<(), MlDsa65AuthenticatorError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(MlDsa65AuthenticatorError::InvalidLength {
            field,
            expected,
            actual: bytes.len(),
        })
    }
}

fn fixed_bytes(
    field: &'static str,
    expected: usize,
    bytes: &[u8],
) -> Result<Box<[u8]>, MlDsa65AuthenticatorError> {
    require_length(field, expected, bytes)?;
    Ok(bytes.into())
}

fn take<const N: usize>(bytes: &[u8], offset: &mut usize) -> [u8; N] {
    let end = *offset + N;
    let mut value = [0; N];
    value.copy_from_slice(&bytes[*offset..end]);
    *offset = end;
    value
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use std::borrow::Cow;

    use serde::{Deserialize, Serialize};
    use serde_with::{Bytes, DeserializeAs};

    use super::*;

    macro_rules! impl_fixed_bytes_serde {
        ($type:ty) => {
            impl serde::Serialize for $type {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: serde::Serializer,
                {
                    if serializer.is_human_readable() {
                        serializer.serialize_str(&Base64::encode_string(self.as_bytes()))
                    } else {
                        serializer.serialize_bytes(self.as_bytes())
                    }
                }
            }

            impl<'de> serde::Deserialize<'de> for $type {
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    if deserializer.is_human_readable() {
                        let value: Cow<'de, str> = Deserialize::deserialize(deserializer)?;
                        value.parse().map_err(serde::de::Error::custom)
                    } else {
                        let bytes: Cow<'de, [u8]> = Bytes::deserialize_as(deserializer)?;
                        Self::from_bytes(bytes).map_err(serde::de::Error::custom)
                    }
                }
            }
        };
    }

    impl_fixed_bytes_serde!(MlDsa65PublicKey);
    impl_fixed_bytes_serde!(MlDsa65Signature);

    impl serde::Serialize for MlDsa65SigningIntentV1 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            if serializer.is_human_readable() {
                serializer.serialize_str(&Base64::encode_string(&self.to_bytes()))
            } else {
                serializer.serialize_bytes(&self.to_bytes())
            }
        }
    }

    impl<'de> serde::Deserialize<'de> for MlDsa65SigningIntentV1 {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let bytes: Vec<u8> = if deserializer.is_human_readable() {
                let value: Cow<'de, str> = Deserialize::deserialize(deserializer)?;
                Base64::decode_vec(&value).map_err(serde::de::Error::custom)?
            } else {
                let bytes: Cow<'de, [u8]> = Bytes::deserialize_as(deserializer)?;
                bytes.into_owned()
            };
            Self::from_bytes(bytes).map_err(serde::de::Error::custom)
        }
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ReadableAuthenticatorRef<'a> {
        intent: &'a MlDsa65SigningIntentV1,
        signature: &'a MlDsa65Signature,
        public_key: &'a MlDsa65PublicKey,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ReadableAuthenticator {
        intent: MlDsa65SigningIntentV1,
        signature: MlDsa65Signature,
        public_key: MlDsa65PublicKey,
    }

    impl serde::Serialize for MlDsa65AuthenticatorV1 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            if serializer.is_human_readable() {
                ReadableAuthenticatorRef {
                    intent: &self.intent,
                    signature: &self.signature,
                    public_key: &self.public_key,
                }
                .serialize(serializer)
            } else {
                serializer.serialize_bytes(&self.to_bytes())
            }
        }
    }

    impl<'de> serde::Deserialize<'de> for MlDsa65AuthenticatorV1 {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let ReadableAuthenticator {
                    intent,
                    signature,
                    public_key,
                } = ReadableAuthenticator::deserialize(deserializer)?;
                Ok(Self::new(intent, signature, public_key))
            } else {
                let bytes: Cow<'de, [u8]> = Bytes::deserialize_as(deserializer)?;
                Self::from_bytes(bytes).map_err(serde::de::Error::custom)
            }
        }
    }
}

#[cfg(feature = "proptest")]
mod proptest_impls {
    use proptest::prelude::*;

    use super::*;

    impl Arbitrary for MlDsa65PublicKey {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
            proptest::collection::vec(any::<u8>(), Self::LENGTH..=Self::LENGTH)
                .prop_map(|bytes| Self(bytes.into_boxed_slice()))
                .boxed()
        }
    }

    impl Arbitrary for MlDsa65Signature {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
            proptest::collection::vec(any::<u8>(), Self::LENGTH..=Self::LENGTH)
                .prop_map(|bytes| Self(bytes.into_boxed_slice()))
                .boxed()
        }
    }

    impl Arbitrary for MlDsa65SigningIntentV1 {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
            (
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                any::<u64>(),
                any::<u64>(),
                any::<[u8; 32]>(),
            )
                .prop_map(|(network, genesis, version, epoch, message)| {
                    Self::new(network, genesis, version, epoch, message)
                })
                .boxed()
        }
    }

    impl Arbitrary for MlDsa65AuthenticatorV1 {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
            (
                any::<MlDsa65SigningIntentV1>(),
                any::<MlDsa65Signature>(),
                any::<MlDsa65PublicKey>(),
            )
                .prop_map(|(intent, signature, public_key)| {
                    Self::new(intent, signature, public_key)
                })
                .boxed()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> MlDsa65AuthenticatorV1 {
        MlDsa65AuthenticatorV1::new(
            MlDsa65SigningIntentV1::new([1; 32], [2; 32], 3, 4, [5; 32]),
            MlDsa65Signature::new([6; ML_DSA_65_SIGNATURE_LEN]),
            MlDsa65PublicKey::new([7; ML_DSA_65_PUBLIC_KEY_LEN]),
        )
    }

    #[test]
    fn authenticator_wire_round_trips() {
        let authenticator = fixture();
        let bytes = authenticator.to_bytes();

        assert_eq!(bytes.len(), ML_DSA_65_AUTHENTICATOR_V1_LEN);
        assert_eq!(bytes[0], 0x08);
        assert_eq!(
            &bytes[1..1 + ML_DSA_65_INTENT_V1_DOMAIN.len()],
            ML_DSA_65_INTENT_V1_DOMAIN
        );
        assert_eq!(
            bytes[1 + ML_DSA_65_INTENT_V1_DOMAIN.len()],
            SignatureScheme::MlDsa65.to_u8()
        );
        assert_eq!(
            MlDsa65AuthenticatorV1::from_bytes(&bytes).unwrap(),
            authenticator
        );
        assert_eq!(
            MlDsa65AuthenticatorV1::from_base64(&authenticator.to_base64()).unwrap(),
            authenticator
        );
    }

    #[test]
    fn malformed_authenticator_is_rejected() {
        let canonical = fixture().to_bytes();

        assert!(matches!(
            MlDsa65AuthenticatorV1::from_bytes(&canonical[..canonical.len() - 1]),
            Err(MlDsa65AuthenticatorError::InvalidLength { .. })
        ));

        let mut wrong = canonical.clone();
        wrong[0] = 0;
        assert!(matches!(
            MlDsa65AuthenticatorV1::from_bytes(&wrong),
            Err(MlDsa65AuthenticatorError::InvalidAuthenticatorScheme(0))
        ));

        let mut wrong = canonical.clone();
        wrong[1] ^= 1;
        assert!(matches!(
            MlDsa65AuthenticatorV1::from_bytes(&wrong),
            Err(MlDsa65AuthenticatorError::InvalidIntentDomain)
        ));

        let mut wrong = canonical.clone();
        wrong[1 + ML_DSA_65_INTENT_V1_DOMAIN.len()] = 0;
        assert!(matches!(
            MlDsa65AuthenticatorV1::from_bytes(&wrong),
            Err(MlDsa65AuthenticatorError::InvalidIntentScheme(0))
        ));

        let cluster_offset = 1 + ML_DSA_65_INTENT_V1_DOMAIN.len() + 1 + 32 + 32 + 8 + 8;
        let role_offset = cluster_offset + 32;
        let purpose_offset = role_offset + 1;
        let sequence_offset = purpose_offset + 1;

        for (offset, field) in [
            (cluster_offset, "cluster id"),
            (role_offset, "role"),
            (purpose_offset, "purpose"),
            (sequence_offset + 7, "sequence"),
        ] {
            let mut wrong = canonical.clone();
            wrong[offset] = 1;
            assert!(matches!(
                MlDsa65AuthenticatorV1::from_bytes(&wrong),
                Err(MlDsa65AuthenticatorError::InvalidUserIntent(actual)) if actual == field
            ));
        }
    }

    #[cfg(feature = "hash")]
    #[test]
    fn address_hashes_scheme_then_public_key() {
        let authenticator = fixture();
        let mut hasher = crate::hash::Hasher::new();
        hasher.update([0x08]);
        hasher.update(authenticator.public_key().as_bytes());

        assert_eq!(
            authenticator.derive_address().as_bytes(),
            hasher.finalize().as_bytes()
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trips_use_the_canonical_wire() {
        let authenticator = fixture();
        let bcs = bcs::to_bytes(&authenticator).unwrap();

        assert_eq!(bcs.len(), ML_DSA_65_AUTHENTICATOR_V1_BCS_LEN);
        assert_eq!(&bcs[..3], &[0xc1, 0x2a, 0x08]);
        assert_eq!(
            bcs::from_bytes::<MlDsa65AuthenticatorV1>(&bcs).unwrap(),
            authenticator
        );

        let json = serde_json::to_string(&authenticator).unwrap();
        assert_eq!(
            serde_json::from_str::<MlDsa65AuthenticatorV1>(&json).unwrap(),
            authenticator
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn human_readable_serde_rejects_malformed_intents() {
        let authenticator = fixture();
        let canonical_json = serde_json::to_value(&authenticator).unwrap();
        let canonical_intent = authenticator.intent().to_bytes();
        let role_offset = ML_DSA_65_INTENT_V1_DOMAIN.len() + 1 + 32 + 32 + 8 + 8 + 32;

        let mut malformed_intents = Vec::new();
        malformed_intents.push(canonical_intent[..canonical_intent.len() - 1].to_vec());

        let mut wrong_domain = canonical_intent.clone();
        wrong_domain[0] ^= 1;
        malformed_intents.push(wrong_domain);

        let mut wrong_role = canonical_intent;
        wrong_role[role_offset] = 1;
        malformed_intents.push(wrong_role);

        for intent in malformed_intents {
            let mut json = canonical_json.clone();
            json["intent"] = serde_json::Value::String(Base64::encode_string(&intent));
            assert!(serde_json::from_value::<MlDsa65AuthenticatorV1>(json).is_err());
        }
    }
}
