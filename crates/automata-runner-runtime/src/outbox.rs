use automata_protocol::{ProtocolLimits, RunnerToServer};

use crate::RunnerRuntimeError;

const LENGTH_PREFIX_BYTES: usize = 4;

pub(crate) fn append_record(existing: &[u8], record: &[u8]) -> Result<Vec<u8>, RunnerRuntimeError> {
    let record_len =
        u32::try_from(record.len()).map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?;
    let capacity = existing
        .len()
        .checked_add(LENGTH_PREFIX_BYTES)
        .and_then(|value| value.checked_add(record.len()))
        .ok_or(RunnerRuntimeError::InvalidDurablePayload)?;
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(existing);
    output.extend_from_slice(&record_len.to_be_bytes());
    output.extend_from_slice(record);
    Ok(output)
}

pub(crate) struct DecodedRecord {
    pub(crate) message: RunnerToServer,
    pub(crate) canonical_bytes: Vec<u8>,
}

pub(crate) fn decode_records(
    encoded: &[u8],
    limits: &ProtocolLimits,
) -> Result<Vec<DecodedRecord>, RunnerRuntimeError> {
    let mut messages = Vec::new();
    let mut remaining = encoded;
    while !remaining.is_empty() {
        let prefix = remaining
            .get(..LENGTH_PREFIX_BYTES)
            .ok_or(RunnerRuntimeError::InvalidDurablePayload)?;
        let length = usize::try_from(u32::from_be_bytes(
            prefix
                .try_into()
                .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?,
        ))
        .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?;
        if length == 0 || length > limits.max_frame_bytes() {
            return Err(RunnerRuntimeError::InvalidDurablePayload);
        }
        remaining = remaining
            .get(LENGTH_PREFIX_BYTES..)
            .ok_or(RunnerRuntimeError::InvalidDurablePayload)?;
        let record = remaining
            .get(..length)
            .ok_or(RunnerRuntimeError::InvalidDurablePayload)?;
        let decoded = automata_protocol_protobuf::decode_runner_frame(record, limits)
            .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?;
        messages.push(DecodedRecord {
            message: decoded.into_message(),
            canonical_bytes: record.to_vec(),
        });
        remaining = remaining
            .get(length..)
            .ok_or(RunnerRuntimeError::InvalidDurablePayload)?;
    }
    Ok(messages)
}
