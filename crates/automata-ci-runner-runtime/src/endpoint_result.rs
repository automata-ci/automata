use automata_ci_execution::{
    CopyFromRequest, ExecutionCommand, ExecutionError, ExecutionErrorKind, ExecutionOutput,
    ExecutionOutputRecord, ExecutionOutputStream, ExecutionStage, ExecutionTermination,
    MAX_EXECUTION_OUTPUT_RECORDS,
};

const MAGIC: &[u8; 8] = b"AERES001";
const STATUS_SUCCESS: u8 = 0;
const STATUS_ERROR: u8 = 1;
const EXEC_RECORD_OVERHEAD_BYTES: usize = 6;
const EXEC_FIXED_OVERHEAD_BYTES: usize = MAGIC.len() + 16;

pub(crate) fn exec_reservation(request: &ExecutionCommand) -> Option<u64> {
    request
        .output_limit()
        .checked_add(MAX_EXECUTION_OUTPUT_RECORDS.checked_mul(EXEC_RECORD_OVERHEAD_BYTES)?)
        .and_then(|value| value.checked_add(EXEC_FIXED_OVERHEAD_BYTES))
        .and_then(|value| u64::try_from(value).ok())
}

pub(crate) fn copy_from_reservation(request: &CopyFromRequest) -> Option<u64> {
    request
        .byte_limit()
        .checked_add(MAGIC.len() + 8)
        .and_then(|value| u64::try_from(value).ok())
}

pub(crate) const fn small_reservation() -> u64 {
    32
}

pub(crate) fn encode_exec(
    result: &Result<ExecutionOutput, ExecutionError>,
    request: &ExecutionCommand,
) -> Result<Vec<u8>, ()> {
    let mut encoded = header(0);
    match result {
        Ok(output) => {
            let output_bytes = output
                .stdout()
                .len()
                .checked_add(output.stderr().len())
                .ok_or(())?;
            if output_bytes > request.output_limit()
                || output.records().len() > MAX_EXECUTION_OUTPUT_RECORDS
            {
                return Err(());
            }
            encoded.push(STATUS_SUCCESS);
            encode_termination(&mut encoded, output.termination());
            encoded.push(u8::from(output.was_truncated()));
            put_u32(&mut encoded, output.records().len())?;
            for record in output.records() {
                encoded.push(match record.stream() {
                    ExecutionOutputStream::Stdout => 0,
                    ExecutionOutputStream::Stderr => 1,
                });
                encoded.push(u8::from(record.is_end_of_stream()));
                put_bytes(&mut encoded, record.bytes())?;
            }
        }
        Err(error) => encode_error(&mut encoded, *error, ExecutionStage::Exec)?,
    }
    Ok(encoded)
}

pub(crate) fn decode_exec(
    encoded: &[u8],
    request: &ExecutionCommand,
) -> Result<Result<ExecutionOutput, ExecutionError>, ()> {
    let mut reader = Reader::new(encoded, 0)?;
    match reader.byte()? {
        STATUS_SUCCESS => {
            let termination = decode_termination(&mut reader)?;
            let truncated = reader.boolean()?;
            let count = reader.length()?;
            if count > MAX_EXECUTION_OUTPUT_RECORDS {
                return Err(());
            }
            let mut records = Vec::with_capacity(count);
            let mut output_bytes = 0_usize;
            for _ in 0..count {
                let stream = match reader.byte()? {
                    0 => ExecutionOutputStream::Stdout,
                    1 => ExecutionOutputStream::Stderr,
                    _ => return Err(()),
                };
                let end_of_stream = reader.boolean()?;
                let bytes = reader.bytes()?;
                output_bytes = output_bytes.checked_add(bytes.len()).ok_or(())?;
                if output_bytes > request.output_limit() {
                    return Err(());
                }
                let record = if end_of_stream {
                    if !bytes.is_empty() {
                        return Err(());
                    }
                    ExecutionOutputRecord::end_of_stream(stream)
                } else {
                    ExecutionOutputRecord::data(stream, bytes.to_vec()).map_err(|_| ())?
                };
                records.push(record);
            }
            reader.finish()?;
            ExecutionOutput::new(termination, records, truncated)
                .map(Ok)
                .map_err(|_| ())
        }
        STATUS_ERROR => decode_error(&mut reader, ExecutionStage::Exec).map(Err),
        _ => Err(()),
    }
}

pub(crate) fn encode_unit(
    kind: u8,
    stage: ExecutionStage,
    result: Result<(), ExecutionError>,
) -> Result<Vec<u8>, ()> {
    let mut encoded = header(kind);
    match result {
        Ok(()) => encoded.push(STATUS_SUCCESS),
        Err(error) => encode_error(&mut encoded, error, stage)?,
    }
    Ok(encoded)
}

pub(crate) fn decode_unit(
    encoded: &[u8],
    kind: u8,
    stage: ExecutionStage,
) -> Result<Result<(), ExecutionError>, ()> {
    let mut reader = Reader::new(encoded, kind)?;
    match reader.byte()? {
        STATUS_SUCCESS => {
            reader.finish()?;
            Ok(Ok(()))
        }
        STATUS_ERROR => decode_error(&mut reader, stage).map(Err),
        _ => Err(()),
    }
}

pub(crate) fn encode_wait(result: Result<i32, ExecutionError>) -> Result<Vec<u8>, ()> {
    let mut encoded = header(2);
    match result {
        Ok(status) => {
            encoded.push(STATUS_SUCCESS);
            encoded.extend_from_slice(&status.to_be_bytes());
        }
        Err(error) => encode_error(&mut encoded, error, ExecutionStage::Wait)?,
    }
    Ok(encoded)
}

pub(crate) fn decode_wait(encoded: &[u8]) -> Result<Result<i32, ExecutionError>, ()> {
    let mut reader = Reader::new(encoded, 2)?;
    match reader.byte()? {
        STATUS_SUCCESS => {
            let status = i32::from_be_bytes(reader.array()?);
            reader.finish()?;
            Ok(Ok(status))
        }
        STATUS_ERROR => decode_error(&mut reader, ExecutionStage::Wait).map(Err),
        _ => Err(()),
    }
}

pub(crate) fn encode_bytes(
    result: &Result<Vec<u8>, ExecutionError>,
    request: &CopyFromRequest,
) -> Result<Vec<u8>, ()> {
    let mut encoded = header(4);
    match result {
        Ok(bytes) => {
            if bytes.len() > request.byte_limit() {
                return Err(());
            }
            encoded.push(STATUS_SUCCESS);
            put_bytes(&mut encoded, bytes)?;
        }
        Err(error) => encode_error(&mut encoded, *error, ExecutionStage::CopyFrom)?,
    }
    Ok(encoded)
}

pub(crate) fn decode_bytes(
    encoded: &[u8],
    request: &CopyFromRequest,
) -> Result<Result<Vec<u8>, ExecutionError>, ()> {
    let mut reader = Reader::new(encoded, 4)?;
    match reader.byte()? {
        STATUS_SUCCESS => {
            let bytes = reader.bytes()?;
            if bytes.len() > request.byte_limit() {
                return Err(());
            }
            let bytes = bytes.to_vec();
            reader.finish()?;
            Ok(Ok(bytes))
        }
        STATUS_ERROR => decode_error(&mut reader, ExecutionStage::CopyFrom).map(Err),
        _ => Err(()),
    }
}

fn header(kind: u8) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(MAGIC.len() + 16);
    encoded.extend_from_slice(MAGIC);
    encoded.push(kind);
    encoded
}

fn encode_error(
    encoded: &mut Vec<u8>,
    error: ExecutionError,
    expected_stage: ExecutionStage,
) -> Result<(), ()> {
    if error.stage() != expected_stage {
        return Err(());
    }
    encoded.push(STATUS_ERROR);
    encoded.push(error_kind_tag(error.kind()));
    encoded.push(stage_tag(error.stage()));
    Ok(())
}

fn decode_error(
    reader: &mut Reader<'_>,
    expected_stage: ExecutionStage,
) -> Result<ExecutionError, ()> {
    let kind = decode_error_kind(reader.byte()?)?;
    let stage = decode_stage(reader.byte()?)?;
    if stage != expected_stage {
        return Err(());
    }
    reader.finish()?;
    Ok(ExecutionError::new(kind, stage))
}

const fn error_kind_tag(kind: ExecutionErrorKind) -> u8 {
    match kind {
        ExecutionErrorKind::UnsupportedCapability => 0,
        ExecutionErrorKind::InvalidEnvironment => 1,
        ExecutionErrorKind::Cancelled => 2,
        ExecutionErrorKind::TimedOut => 3,
        ExecutionErrorKind::NotFound => 4,
        ExecutionErrorKind::OwnershipMismatch => 5,
        ExecutionErrorKind::InvalidState => 6,
        ExecutionErrorKind::OutputLimitExceeded => 7,
        ExecutionErrorKind::BackendRejected => 8,
        ExecutionErrorKind::LocalStorage => 9,
    }
}

const fn decode_error_kind(tag: u8) -> Result<ExecutionErrorKind, ()> {
    match tag {
        0 => Ok(ExecutionErrorKind::UnsupportedCapability),
        1 => Ok(ExecutionErrorKind::InvalidEnvironment),
        2 => Ok(ExecutionErrorKind::Cancelled),
        3 => Ok(ExecutionErrorKind::TimedOut),
        4 => Ok(ExecutionErrorKind::NotFound),
        5 => Ok(ExecutionErrorKind::OwnershipMismatch),
        6 => Ok(ExecutionErrorKind::InvalidState),
        7 => Ok(ExecutionErrorKind::OutputLimitExceeded),
        8 => Ok(ExecutionErrorKind::BackendRejected),
        9 => Ok(ExecutionErrorKind::LocalStorage),
        _ => Err(()),
    }
}

const fn stage_tag(stage: ExecutionStage) -> u8 {
    match stage {
        ExecutionStage::Exec => 0,
        ExecutionStage::Signal => 1,
        ExecutionStage::Wait => 2,
        ExecutionStage::CopyTo => 3,
        ExecutionStage::CopyFrom => 4,
    }
}

const fn decode_stage(tag: u8) -> Result<ExecutionStage, ()> {
    match tag {
        0 => Ok(ExecutionStage::Exec),
        1 => Ok(ExecutionStage::Signal),
        2 => Ok(ExecutionStage::Wait),
        3 => Ok(ExecutionStage::CopyTo),
        4 => Ok(ExecutionStage::CopyFrom),
        _ => Err(()),
    }
}

fn encode_termination(encoded: &mut Vec<u8>, termination: ExecutionTermination) {
    match termination {
        ExecutionTermination::Exited(status) => {
            encoded.push(0);
            encoded.extend_from_slice(&status.to_be_bytes());
        }
        ExecutionTermination::Signalled => encoded.push(1),
        ExecutionTermination::TimedOut => encoded.push(2),
        ExecutionTermination::Cancelled => encoded.push(3),
    }
}

fn decode_termination(reader: &mut Reader<'_>) -> Result<ExecutionTermination, ()> {
    match reader.byte()? {
        0 => Ok(ExecutionTermination::Exited(i32::from_be_bytes(
            reader.array()?,
        ))),
        1 => Ok(ExecutionTermination::Signalled),
        2 => Ok(ExecutionTermination::TimedOut),
        3 => Ok(ExecutionTermination::Cancelled),
        _ => Err(()),
    }
}

fn put_u32(encoded: &mut Vec<u8>, value: usize) -> Result<(), ()> {
    let value = u32::try_from(value).map_err(|_| ())?;
    encoded.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn put_bytes(encoded: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ()> {
    put_u32(encoded, bytes.len())?;
    encoded.extend_from_slice(bytes);
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], kind: u8) -> Result<Self, ()> {
        let mut reader = Self { bytes, offset: 0 };
        if reader.take(MAGIC.len())? != MAGIC || reader.byte()? != kind {
            return Err(());
        }
        Ok(reader)
    }

    fn byte(&mut self) -> Result<u8, ()> {
        Ok(*self.take(1)?.first().ok_or(())?)
    }

    fn boolean(&mut self) -> Result<bool, ()> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(()),
        }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ()> {
        self.take(N)?.try_into().map_err(|_| ())
    }

    fn length(&mut self) -> Result<usize, ()> {
        usize::try_from(u32::from_be_bytes(self.array()?)).map_err(|_| ())
    }

    fn bytes(&mut self) -> Result<&'a [u8], ()> {
        let length = self.length()?;
        self.take(length)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ()> {
        let end = self.offset.checked_add(length).ok_or(())?;
        let bytes = self.bytes.get(self.offset..end).ok_or(())?;
        self.offset = end;
        Ok(bytes)
    }

    fn finish(&self) -> Result<(), ()> {
        (self.offset == self.bytes.len()).then_some(()).ok_or(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use automata_ci_core::OperationId;
    use automata_ci_execution::{
        CopyFromRequest, ExecutionArgv, ExecutionEnvironment, ExecutionOutputRecord,
        ExecutionOutputStream, TargetPath,
    };

    use super::*;

    fn command(output_limit: usize) -> ExecutionCommand {
        ExecutionCommand::new(
            OperationId::new(),
            ExecutionArgv::new(
                TargetPath::posix("/bin/printf").expect("program"),
                vec!["value".to_owned()],
            )
            .expect("argv"),
            TargetPath::posix("/workspace").expect("working directory"),
            ExecutionEnvironment::empty(),
            Duration::from_secs(30),
            output_limit,
        )
        .expect("command")
    }

    fn output(termination: ExecutionTermination) -> ExecutionOutput {
        ExecutionOutput::new(
            termination,
            vec![
                ExecutionOutputRecord::data(ExecutionOutputStream::Stdout, b"out".to_vec())
                    .expect("stdout"),
                ExecutionOutputRecord::data(ExecutionOutputStream::Stderr, b"err".to_vec())
                    .expect("stderr"),
                ExecutionOutputRecord::end_of_stream(ExecutionOutputStream::Stdout),
                ExecutionOutputRecord::end_of_stream(ExecutionOutputStream::Stderr),
            ],
            false,
        )
        .expect("output")
    }

    #[test]
    fn exec_codec_round_trips_every_termination_without_plain_schema_fallbacks() {
        let request = command(1024);
        for termination in [
            ExecutionTermination::Exited(23),
            ExecutionTermination::Signalled,
            ExecutionTermination::TimedOut,
            ExecutionTermination::Cancelled,
        ] {
            let expected = output(termination);
            let encoded = encode_exec(&Ok(expected.clone()), &request).expect("encode");
            let decoded = decode_exec(&encoded, &request).expect("decode");
            assert_eq!(decoded, Ok(expected));
        }
    }

    #[test]
    fn error_codec_round_trips_the_closed_error_domain() {
        for kind in [
            ExecutionErrorKind::UnsupportedCapability,
            ExecutionErrorKind::InvalidEnvironment,
            ExecutionErrorKind::Cancelled,
            ExecutionErrorKind::TimedOut,
            ExecutionErrorKind::NotFound,
            ExecutionErrorKind::OwnershipMismatch,
            ExecutionErrorKind::InvalidState,
            ExecutionErrorKind::OutputLimitExceeded,
            ExecutionErrorKind::BackendRejected,
            ExecutionErrorKind::LocalStorage,
        ] {
            let expected = ExecutionError::new(kind, ExecutionStage::Signal);
            let encoded = encode_unit(1, ExecutionStage::Signal, Err(expected)).expect("encode");
            assert_eq!(
                decode_unit(&encoded, 1, ExecutionStage::Signal).expect("decode"),
                Err(expected)
            );
        }
    }

    #[test]
    fn wait_and_copy_from_codecs_round_trip_and_reapply_request_bounds() {
        let wait = encode_wait(Ok(-9)).expect("encode wait");
        assert_eq!(decode_wait(&wait).expect("decode wait"), Ok(-9));

        let request = CopyFromRequest::new(
            OperationId::new(),
            TargetPath::posix("/workspace/value").expect("source"),
            3,
        )
        .expect("copy request");
        let encoded = encode_bytes(&Ok(b"abc".to_vec()), &request).expect("encode bytes");
        assert_eq!(
            decode_bytes(&encoded, &request).expect("decode bytes"),
            Ok(b"abc".to_vec())
        );
        assert!(encode_bytes(&Ok(b"abcd".to_vec()), &request).is_err());
    }

    #[test]
    fn codec_rejects_wrong_kind_trailing_data_and_narrower_replay_limit() {
        let request = command(16);
        let mut encoded = encode_exec(&Ok(output(ExecutionTermination::Exited(0))), &request)
            .expect("encode exec");
        encoded[MAGIC.len()] = 4;
        assert!(decode_exec(&encoded, &request).is_err());

        let mut encoded = encode_wait(Ok(0)).expect("encode wait");
        encoded.push(0);
        assert!(decode_wait(&encoded).is_err());

        let broad = CopyFromRequest::new(
            OperationId::new(),
            TargetPath::posix("/workspace/value").expect("source"),
            4,
        )
        .expect("broad request");
        let narrow = CopyFromRequest::new(broad.operation_id(), broad.source().clone(), 3)
            .expect("narrow request");
        let encoded = encode_bytes(&Ok(b"abcd".to_vec()), &broad).expect("encode broad bytes");
        assert!(decode_bytes(&encoded, &narrow).is_err());
    }
}
