//! Shared bounded guest-agent protocol used by the privileged HCS adapter.

use std::collections::BTreeMap;

use automata_ci_execution::{
    ExecutionCommand, ExecutionOutput, ExecutionOutputRecord, ExecutionOutputStream,
    ExecutionTermination,
};
use automata_ci_sandbox_guest::{
    GUEST_PROTOCOL_VERSION, GuestOutputStream, GuestRequest, GuestResponse, GuestTermination,
    decode_frame, encode_frame,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use thiserror::Error;

use crate::{BrokerCopyFromRequest, BrokerCopyToRequest, BrokerExecRequest};

/// Failure to construct or verify the fixed Windows guest-agent exchange.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BrokerGuestProtocolError {
    /// The broker request could not be represented by the bounded guest protocol.
    #[error("Windows broker guest request is invalid")]
    InvalidRequest,
    /// The guest returned a malformed, mismatched, or over-limit response.
    #[error("Windows broker guest response is invalid")]
    InvalidResponse,
}

/// Encodes one exact broker exec as a guest-agent protocol frame.
///
/// The frame carries the sandbox's hard process ceiling. On Windows the guest
/// agent creates the workload inside a nested Job Object and applies that
/// ceiling before it starts the literal argv.
///
/// # Errors
///
/// Rejects secret-marked environment, an invalid process ceiling, an
/// unrepresentable timeout, or an oversized protocol frame.
pub fn encode_broker_exec_guest_request(
    request: &BrokerExecRequest<'_>,
) -> Result<Vec<u8>, BrokerGuestProtocolError> {
    encode_frame(&exec_guest_request(
        request.command(),
        request.process_limit(),
    )?)
    .map_err(|_| BrokerGuestProtocolError::InvalidRequest)
}

/// Decodes and verifies one exact guest exec response.
///
/// # Errors
///
/// Rejects a malformed frame, another response kind or protocol version,
/// malformed record ordering, invalid base64, or output beyond the request's
/// aggregate limit.
pub fn decode_broker_exec_guest_response(
    frame: &[u8],
    output_limit: usize,
) -> Result<ExecutionOutput, BrokerGuestProtocolError> {
    let response = decode_frame::<GuestResponse>(frame)
        .map_err(|_| BrokerGuestProtocolError::InvalidResponse)?;
    let GuestResponse::Exec {
        protocol,
        termination,
        records,
        truncated,
    } = response
    else {
        return Err(BrokerGuestProtocolError::InvalidResponse);
    };
    if protocol != GUEST_PROTOCOL_VERSION {
        return Err(BrokerGuestProtocolError::InvalidResponse);
    }
    let mut captured = 0_usize;
    let records = records
        .into_iter()
        .map(|record| {
            let stream = output_stream(record.stream());
            if record.is_end_of_stream() {
                if !record
                    .data()
                    .map_err(|_| BrokerGuestProtocolError::InvalidResponse)?
                    .is_empty()
                {
                    return Err(BrokerGuestProtocolError::InvalidResponse);
                }
                return Ok(ExecutionOutputRecord::end_of_stream(stream));
            }
            let bytes = record
                .data()
                .map_err(|_| BrokerGuestProtocolError::InvalidResponse)?;
            captured = captured
                .checked_add(bytes.len())
                .ok_or(BrokerGuestProtocolError::InvalidResponse)?;
            if captured > output_limit {
                return Err(BrokerGuestProtocolError::InvalidResponse);
            }
            ExecutionOutputRecord::data(stream, bytes)
                .map_err(|_| BrokerGuestProtocolError::InvalidResponse)
        })
        .collect::<Result<Vec<_>, _>>()?;
    ExecutionOutput::new(execution_termination(termination), records, truncated)
        .map_err(|_| BrokerGuestProtocolError::InvalidResponse)
}

/// Encodes one exact copy-to request as a guest-agent file-write frame.
///
/// # Errors
///
/// Rejects an oversized protocol frame.
pub fn encode_broker_copy_to_guest_request(
    request: &BrokerCopyToRequest<'_>,
) -> Result<Vec<u8>, BrokerGuestProtocolError> {
    let request = request.request();
    encode_frame(&GuestRequest::WriteFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: request.operation_id().to_string(),
        path: request.target().as_str().to_owned(),
        content_base64: BASE64.encode(request.content()),
    })
    .map_err(|_| BrokerGuestProtocolError::InvalidRequest)
}

/// Verifies the exact acknowledgement for a guest-agent file write.
///
/// # Errors
///
/// Rejects a malformed frame, another response kind, or another protocol.
pub fn decode_broker_copy_to_guest_response(frame: &[u8]) -> Result<(), BrokerGuestProtocolError> {
    match decode_frame::<GuestResponse>(frame)
        .map_err(|_| BrokerGuestProtocolError::InvalidResponse)?
    {
        GuestResponse::WriteFile { protocol } if protocol == GUEST_PROTOCOL_VERSION => Ok(()),
        _ => Err(BrokerGuestProtocolError::InvalidResponse),
    }
}

/// Encodes one exact copy-from request as a guest-agent bounded file-read frame.
///
/// # Errors
///
/// Rejects an oversized protocol frame.
pub fn encode_broker_copy_from_guest_request(
    request: &BrokerCopyFromRequest<'_>,
) -> Result<Vec<u8>, BrokerGuestProtocolError> {
    let request = request.request();
    encode_frame(&GuestRequest::ReadFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: request.operation_id().to_string(),
        path: request.source().as_str().to_owned(),
        byte_limit: request.byte_limit(),
    })
    .map_err(|_| BrokerGuestProtocolError::InvalidRequest)
}

/// Decodes one exact bounded guest-agent file-read response.
///
/// # Errors
///
/// Rejects a malformed frame, another response kind or protocol, invalid
/// base64, or content larger than the caller's bound.
pub fn decode_broker_copy_from_guest_response(
    frame: &[u8],
    byte_limit: usize,
) -> Result<Vec<u8>, BrokerGuestProtocolError> {
    let response = decode_frame::<GuestResponse>(frame)
        .map_err(|_| BrokerGuestProtocolError::InvalidResponse)?;
    let GuestResponse::ReadFile {
        protocol,
        content_base64,
    } = response
    else {
        return Err(BrokerGuestProtocolError::InvalidResponse);
    };
    if protocol != GUEST_PROTOCOL_VERSION {
        return Err(BrokerGuestProtocolError::InvalidResponse);
    }
    let bytes = BASE64
        .decode(content_base64)
        .map_err(|_| BrokerGuestProtocolError::InvalidResponse)?;
    (bytes.len() <= byte_limit)
        .then_some(bytes)
        .ok_or(BrokerGuestProtocolError::InvalidResponse)
}

fn exec_guest_request(
    command: &ExecutionCommand,
    process_limit: u32,
) -> Result<GuestRequest, BrokerGuestProtocolError> {
    if process_limit == 0
        || command
            .environment()
            .values()
            .iter()
            .any(automata_ci_execution::EnvironmentVariable::is_secret)
    {
        return Err(BrokerGuestProtocolError::InvalidRequest);
    }
    let environment = command
        .environment()
        .values()
        .iter()
        .map(|variable| {
            (
                variable.name().as_str().to_owned(),
                variable.value().expose().to_owned(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let timeout_millis = u64::try_from(command.timeout().as_millis())
        .map_err(|_| BrokerGuestProtocolError::InvalidRequest)?;
    Ok(GuestRequest::Exec {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: command.operation_id().to_string(),
        program: command.argv().program().as_str().to_owned(),
        arguments: command.argv().arguments().to_vec(),
        environment,
        working_directory: command.working_directory().as_str().to_owned(),
        timeout_millis,
        output_limit: command.output_limit(),
        process_limit: Some(process_limit),
    })
}

const fn output_stream(stream: GuestOutputStream) -> ExecutionOutputStream {
    match stream {
        GuestOutputStream::Stdout => ExecutionOutputStream::Stdout,
        GuestOutputStream::Stderr => ExecutionOutputStream::Stderr,
    }
}

const fn execution_termination(termination: GuestTermination) -> ExecutionTermination {
    match termination {
        GuestTermination::Exited(code) => ExecutionTermination::Exited(code),
        GuestTermination::Signalled => ExecutionTermination::Signalled,
        GuestTermination::TimedOut => ExecutionTermination::TimedOut,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use automata_ci_core::OperationId;
    use automata_ci_execution::{
        ExecutionArgv, ExecutionEnvironment, ExecutionOutputRecord, ExecutionOutputStream,
        TargetPath,
    };

    use super::*;

    fn command(operation_id: OperationId) -> ExecutionCommand {
        ExecutionCommand::new(
            operation_id,
            ExecutionArgv::new(
                TargetPath::windows(r"C:\Windows\System32\cmd.exe").expect("program"),
                vec!["/d".into(), "/c".into(), "echo bounded".into()],
            )
            .expect("argv"),
            TargetPath::windows(r"C:\__w").expect("working directory"),
            ExecutionEnvironment::empty(),
            Duration::from_secs(30),
            1024,
        )
        .expect("command")
    }

    #[test]
    fn broker_exec_frame_requires_the_guest_job_object_process_ceiling() {
        let operation_id = OperationId::new();
        let request = exec_guest_request(&command(operation_id), 128).expect("guest request");
        let frame = encode_frame(&request).expect("frame");
        assert_eq!(
            decode_frame::<GuestRequest>(&frame).expect("decode"),
            GuestRequest::Exec {
                protocol: GUEST_PROTOCOL_VERSION,
                operation_id: operation_id.to_string(),
                program: r"C:\Windows\System32\cmd.exe".into(),
                arguments: vec!["/d".into(), "/c".into(), "echo bounded".into()],
                environment: BTreeMap::new(),
                working_directory: r"C:\__w".into(),
                timeout_millis: 30_000,
                output_limit: 1024,
                process_limit: Some(128),
            }
        );
        assert_eq!(
            exec_guest_request(&command(OperationId::new()), 0).expect_err("zero process limit"),
            BrokerGuestProtocolError::InvalidRequest
        );
    }

    #[test]
    fn guest_exec_response_preserves_ordered_output_and_termination() {
        let response = serde_json::json!({
            "result": "exec",
            "protocol": GUEST_PROTOCOL_VERSION,
            "termination": { "kind": "exited", "code": 17 },
            "records": [
                { "stream": "stdout", "data_base64": "b25l", "end_of_stream": false },
                { "stream": "stdout", "data_base64": "", "end_of_stream": true },
                { "stream": "stderr", "data_base64": "", "end_of_stream": true }
            ],
            "truncated": false
        });
        let output =
            decode_broker_exec_guest_response(&encode_frame(&response).expect("frame"), 1024)
                .expect("output");
        assert_eq!(output.termination(), ExecutionTermination::Exited(17));
        assert_eq!(
            output.records(),
            &[
                ExecutionOutputRecord::data(ExecutionOutputStream::Stdout, b"one".to_vec())
                    .expect("record"),
                ExecutionOutputRecord::end_of_stream(ExecutionOutputStream::Stdout),
                ExecutionOutputRecord::end_of_stream(ExecutionOutputStream::Stderr),
            ]
        );
    }
}
