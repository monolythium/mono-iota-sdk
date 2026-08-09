// Copyright (c) 2026 IOTA Stiftung
// Modified by Mono Labs for the Monolythium IOTA Rust SDK, 2026.
// SPDX-License-Identifier: Apache-2.0

//! High-level API for gRPC client operations.
//!
//! This module provides wrappers around the raw gRPC service clients.
//! Proto types are exposed directly with lazy conversion methods, allowing
//! users to convert only what they need to SDK types.

mod common;
pub mod execution;
pub mod ledger;
mod metadata;
pub mod move_package;
pub mod state;

pub use common::{CheckpointStreamError, Error, Page, ProtocolError, ReadMask, Result, RpcStatus};
pub(crate) use common::{
    ProtoResult, TryFromProtoError, build_proto_transaction, collect_stream, define_list_query,
    field_mask_with_default, proto_object_id, saturating_usize_to_u32,
};
pub use iota_grpc_types::read_masks::*;
use iota_types::{
    AuthenticatedCheckpointData, AuthenticatedCheckpointSummary, CheckpointAuthentication,
    CheckpointSequenceNumber,
};
pub use metadata::MetadataEnvelope;

/// An item from a checkpoint data stream.
///
/// When `filter_checkpoints` is enabled, the server may skip checkpoints that
/// don't match the provided filters. In that case, `Progress` items are sent
/// periodically to indicate liveness and the current scan position. When
/// `filter_checkpoints` is disabled, only `Checkpoint` items are produced.
///
/// For liveness detection with `filter_checkpoints`, wrap `stream.next()` in
/// `tokio::time::timeout()` — if neither a `Checkpoint` nor a `Progress`
/// arrives within your chosen duration plus some buffer for connection latency,
/// the connection is likely dead.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum CheckpointStreamItem {
    /// A complete checkpoint with its transactions and events.
    Checkpoint(Box<CheckpointResponse>),
    /// A progress indicator sent during filtered scanning.
    /// Contains the sequence number of the latest scanned checkpoint.
    Progress {
        latest_scanned_sequence_number: CheckpointSequenceNumber,
    },
}

impl CheckpointStreamItem {
    /// Returns the contained checkpoint, or `None` if this is a progress
    /// message.
    pub fn into_checkpoint(self) -> Option<CheckpointResponse> {
        match self {
            Self::Checkpoint(c) => Some(*c),
            Self::Progress { .. } => None,
        }
    }

    /// Returns the progress sequence number, or `None` if this is a
    /// checkpoint.
    pub fn into_progress(self) -> Option<CheckpointSequenceNumber> {
        match self {
            Self::Checkpoint(_) => None,
            Self::Progress {
                latest_scanned_sequence_number,
            } => Some(latest_scanned_sequence_number),
        }
    }

    /// Returns `true` if this is a checkpoint item.
    pub fn is_checkpoint(&self) -> bool {
        matches!(self, Self::Checkpoint(_))
    }

    /// Returns `true` if this is a progress item.
    pub fn is_progress(&self) -> bool {
        matches!(self, Self::Progress { .. })
    }
}

/// Response for a checkpoint query.
///
/// Contains checkpoint summary, authentication, contents, transactions, and
/// events.
/// Fields are proto types that can be accessed directly or converted to SDK
/// types using their conversion methods (e.g.,
/// `response.summary()?.summary()?`, `response.contents()?.contents()?`).
#[derive(Clone, Debug)]
pub struct CheckpointResponse {
    /// The checkpoint sequence number.
    pub sequence_number: CheckpointSequenceNumber,
    /// Proto checkpoint summary. Use `response.summary()?.summary()` to convert
    /// to SDK type.
    pub summary: Option<iota_grpc_types::v1::checkpoint::CheckpointSummary>,
    /// Proto validator signature. Use `response.signature()?.signature()` to
    /// convert to SDK type.
    pub signature: Option<iota_grpc_types::v1::signatures::ValidatorAggregatedSignature>,
    /// Proto versioned checkpoint authentication. Use
    /// [`authentication`](Self::authentication) to convert it to the SDK type.
    pub authentication: Option<iota_grpc_types::v1::checkpoint::CheckpointAuthentication>,
    /// Proto checkpoint contents. Use `response.contents()?.contents()` to
    /// convert to SDK type.
    pub contents: Option<iota_grpc_types::v1::checkpoint::CheckpointContents>,
    /// Proto executed transactions. Use methods like `tx.effects()?`,
    /// `tx.transaction()?`, etc.
    pub executed_transactions: Vec<iota_grpc_types::v1::transaction::ExecutedTransaction>,
    /// Proto events. Use `event.try_into()` or `event.events()` to convert to
    /// SDK types.
    pub events: Vec<iota_grpc_types::v1::event::Event>,
}

impl CheckpointResponse {
    /// Get the checkpoint sequence number.
    ///
    /// Always available regardless of the read mask.
    pub fn sequence_number(&self) -> CheckpointSequenceNumber {
        self.sequence_number
    }

    /// Get the checkpoint summary.
    ///
    /// Returns the proto
    /// [`CheckpointSummary`](iota_grpc_types::v1::checkpoint::CheckpointSummary)
    /// which provides:
    /// - [`digest()`](iota_grpc_types::v1::checkpoint::CheckpointSummary::digest) — the summary digest
    /// - [`summary()`](iota_grpc_types::v1::checkpoint::CheckpointSummary::summary) — the deserialized SDK `CheckpointSummary`
    ///
    /// **Read mask:** `"checkpoint.summary"` (see
    /// [`CHECKPOINT_RESPONSE_SUMMARY`])
    pub fn summary(&self) -> Result<&iota_grpc_types::v1::checkpoint::CheckpointSummary> {
        self.summary
            .as_ref()
            .ok_or_else(|| TryFromProtoError::missing("summary").into())
    }

    /// Build a [`SignedCheckpointSummary`](iota_types::SignedCheckpointSummary)
    /// from the response.
    ///
    /// Requires the checkpoint summary and signature to be present.
    ///
    /// **Read mask:** see [`CHECKPOINT_RESPONSE_SIGNED_SUMMARY`]
    pub fn signed_summary(&self) -> Result<iota_types::SignedCheckpointSummary> {
        Ok(iota_types::SignedCheckpointSummary {
            checkpoint: self.summary()?.summary()?,
            signature: self.signature()?.signature()?,
        })
    }

    /// Build an [`AuthenticatedCheckpointSummary`] from the response.
    ///
    /// The versioned authentication field is preferred. A legacy validator
    /// signature is accepted as the IOTA authentication variant when the
    /// versioned field is absent. If a response includes both fields, they must
    /// encode the same legacy authentication.
    ///
    /// **Read mask:** see [`CHECKPOINT_RESPONSE_AUTHENTICATED_SUMMARY`]
    pub fn authenticated_summary(&self) -> Result<AuthenticatedCheckpointSummary> {
        Ok(AuthenticatedCheckpointSummary {
            checkpoint: self.summary()?.summary()?,
            authentication: self.authentication()?,
        })
    }

    /// Get the versioned authentication for the checkpoint.
    ///
    /// The versioned authentication field is preferred. A legacy validator
    /// signature is accepted as the IOTA authentication variant when the
    /// versioned field is absent. Supplying both fields with different values
    /// is invalid.
    ///
    /// **Read mask:** `"checkpoint.authentication"` for versioned responses,
    /// or `"checkpoint.signature"` for legacy responses. See
    /// [`CHECKPOINT_RESPONSE_AUTHENTICATION`].
    pub fn authentication(&self) -> Result<CheckpointAuthentication> {
        let authentication = match self.authentication.as_ref() {
            Some(authentication) => Some(authentication.authentication()?),
            None => None,
        };
        let legacy = match self.signature.as_ref() {
            Some(signature) => Some(CheckpointAuthentication::IotaValidatorAggregatedSignature(
                signature.signature()?,
            )),
            None => None,
        };

        match (authentication, legacy) {
            (Some(authentication), Some(legacy)) if authentication == legacy => Ok(authentication),
            (Some(_), Some(_)) => Err(TryFromProtoError::invalid(
                "checkpoint.authentication",
                "conflicts with checkpoint.signature",
            )
            .into()),
            (Some(authentication), None) | (None, Some(authentication)) => Ok(authentication),
            (None, None) => Err(TryFromProtoError::missing("checkpoint.authentication").into()),
        }
    }

    /// Get the validator aggregated signature for the checkpoint.
    ///
    /// **Read mask:** `"checkpoint.signature"` (see
    /// [`CHECKPOINT_RESPONSE_SIGNATURE`])
    pub fn signature(
        &self,
    ) -> Result<&iota_grpc_types::v1::signatures::ValidatorAggregatedSignature> {
        self.signature
            .as_ref()
            .ok_or_else(|| TryFromProtoError::missing("signature").into())
    }

    /// Get the checkpoint contents.
    ///
    /// Returns the proto
    /// [`CheckpointContents`](iota_grpc_types::v1::checkpoint::CheckpointContents)
    /// which provides:
    /// - [`digest()`](iota_grpc_types::v1::checkpoint::CheckpointContents::digest) — the contents digest
    /// - [`contents()`](iota_grpc_types::v1::checkpoint::CheckpointContents::contents) — the deserialized SDK `CheckpointContents`
    ///
    /// **Read mask:** `"checkpoint.contents"` (see
    /// [`CHECKPOINT_RESPONSE_CONTENTS`])
    pub fn contents(&self) -> Result<&iota_grpc_types::v1::checkpoint::CheckpointContents> {
        self.contents
            .as_ref()
            .ok_or_else(|| TryFromProtoError::missing("contents").into())
    }

    /// Get the executed transactions in this checkpoint.
    ///
    /// Returns proto
    /// [`ExecutedTransaction`](iota_grpc_types::v1::transaction::ExecutedTransaction)
    /// values. Which sub-fields are populated depends on the read mask; use
    /// paths like `"transactions.effects"` or `"transactions.transaction"`.
    ///
    /// **Read mask:** `"transactions"` for all sub-fields (see
    /// [`CHECKPOINT_RESPONSE_EXECUTED_TRANSACTIONS`])
    pub fn executed_transactions(
        &self,
    ) -> &Vec<iota_grpc_types::v1::transaction::ExecutedTransaction> {
        &self.executed_transactions
    }

    /// Get the top-level events for this checkpoint.
    ///
    /// Returns proto [`Event`](iota_grpc_types::v1::event::Event) values.
    /// Which sub-fields are populated depends on the read mask; use paths like
    /// `"events.bcs"` or `"events.event_type"`.
    ///
    /// **Read mask:** `"events"` for all sub-fields (see
    /// [`CHECKPOINT_RESPONSE_EVENTS`])
    pub fn events(&self) -> &Vec<iota_grpc_types::v1::event::Event> {
        &self.events
    }

    /// Build a full
    /// [`CheckpointData`](iota_types::checkpoint::CheckpointData)
    /// from the response.
    ///
    /// Requires the checkpoint summary, signature, contents, and all
    /// transaction data (transaction, signatures, effects, events,
    /// input_objects, output_objects) to be present in the response.
    ///
    /// **Read mask:** see [`CHECKPOINT_RESPONSE_CHECKPOINT_DATA`]
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use iota_sdk_grpc_client::CHECKPOINT_RESPONSE_CHECKPOINT_DATA;
    ///
    /// let client = Client::new("http://localhost:9000")?;
    /// let cp = client
    ///     .get_checkpoint_latest(Some(CHECKPOINT_RESPONSE_CHECKPOINT_DATA.into()), None, None)
    ///     .await?;
    /// let data = cp.body().checkpoint_data()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn checkpoint_data(&self) -> Result<iota_types::checkpoint::CheckpointData> {
        Ok(iota_types::checkpoint::CheckpointData {
            checkpoint_contents: self.contents()?.contents()?,
            checkpoint_summary: iota_types::SignedCheckpointSummary {
                checkpoint: self.summary()?.summary()?,
                signature: self.signature()?.signature()?,
            },
            transactions: self
                .executed_transactions()
                .iter()
                .map(TryInto::try_into)
                .collect::<std::result::Result<Vec<_>, _>>()?,
        })
    }

    /// Build full authenticated checkpoint data from the response.
    ///
    /// Requires the checkpoint summary, either supported authentication field,
    /// contents, and all transaction data to be present in the response.
    ///
    /// **Read mask:** see [`CHECKPOINT_RESPONSE_AUTHENTICATED_CHECKPOINT_DATA`]
    pub fn authenticated_checkpoint_data(&self) -> Result<AuthenticatedCheckpointData> {
        Ok(AuthenticatedCheckpointData {
            checkpoint_contents: self.contents()?.contents()?,
            checkpoint_summary: self.authenticated_summary()?,
            transactions: self
                .executed_transactions()
                .iter()
                .map(TryInto::try_into)
                .collect::<std::result::Result<Vec<_>, _>>()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use iota_grpc_types::v1::{
        bcs::BcsData, checkpoint::CheckpointAuthentication as ProtoCheckpointAuthentication,
        signatures::ValidatorAggregatedSignature as ProtoValidatorAggregatedSignature,
    };
    use iota_types::CheckpointAuthentication;

    use super::CheckpointResponse;

    const LEGACY_AUTHENTICATION_BCS_BASE64: &str = "AAoAAAAAAAAAmawXF4qmtLbc7X8KwcSs0EcyEZ2YW5rEFe7ajV8ImUK0QvnVQ23bmtRLcvbstqQlEjowAAABAAAAAAAAABAAAAAAAA==";
    const MONO_AUTHENTICATION_BCS_BASE64: &str = "AQMBAgM=";

    fn bcs_data(fixture: &str) -> BcsData {
        BcsData::from(STANDARD.decode(fixture).unwrap())
    }

    fn legacy_authentication() -> ProtoValidatorAggregatedSignature {
        ProtoValidatorAggregatedSignature::default()
            .with_bcs(bcs_data(LEGACY_AUTHENTICATION_BCS_BASE64))
    }

    fn versioned_authentication(fixture: &str) -> ProtoCheckpointAuthentication {
        ProtoCheckpointAuthentication::default().with_bcs(bcs_data(fixture))
    }

    fn response(
        signature: Option<ProtoValidatorAggregatedSignature>,
        authentication: Option<ProtoCheckpointAuthentication>,
    ) -> CheckpointResponse {
        CheckpointResponse {
            sequence_number: 0,
            summary: None,
            signature,
            authentication,
            contents: None,
            executed_transactions: Vec::new(),
            events: Vec::new(),
        }
    }

    #[test]
    fn legacy_signature_is_an_authentication_fallback() {
        let authentication = response(Some(legacy_authentication()), None)
            .authentication()
            .unwrap();
        assert!(matches!(
            authentication,
            CheckpointAuthentication::IotaValidatorAggregatedSignature(_)
        ));
    }

    #[test]
    fn versioned_mono_authentication_is_decoded() {
        let authentication = response(
            None,
            Some(versioned_authentication(MONO_AUTHENTICATION_BCS_BASE64)),
        )
        .authentication()
        .unwrap();
        match authentication {
            CheckpointAuthentication::MonoClusterAuthenticationV1(bytes) => {
                assert_eq!(bytes.as_bytes(), &[1, 2, 3]);
            }
            _ => panic!("expected Mono checkpoint authentication"),
        }
    }

    #[test]
    fn matching_legacy_and_versioned_fields_are_accepted() {
        let authentication = response(
            Some(legacy_authentication()),
            Some(versioned_authentication(LEGACY_AUTHENTICATION_BCS_BASE64)),
        )
        .authentication()
        .unwrap();
        assert!(matches!(
            authentication,
            CheckpointAuthentication::IotaValidatorAggregatedSignature(_)
        ));
    }

    #[test]
    fn malformed_versioned_authentication_does_not_fall_back() {
        let malformed = ProtoCheckpointAuthentication::default().with_bcs(vec![2]);
        assert!(
            response(Some(legacy_authentication()), Some(malformed))
                .authentication()
                .is_err()
        );
    }

    #[test]
    fn missing_authentication_fields_are_rejected() {
        assert!(response(None, None).authentication().is_err());
    }

    #[test]
    fn conflicting_authentication_fields_are_rejected() {
        let error = response(
            Some(legacy_authentication()),
            Some(versioned_authentication(MONO_AUTHENTICATION_BCS_BASE64)),
        )
        .authentication()
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("conflicts with checkpoint.signature")
        );
    }
}
