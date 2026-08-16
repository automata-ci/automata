use automata_ci_execution::{
    ActionGraphMaterializationRequest, CopyFromRequest, ExecutionCommand, ExecutionError,
    ExecutionErrorKind, ExecutionOutput, ExecutionOutputRecord, ExecutionOutputStream,
    ExecutionStage, ExecutionTermination, MAX_EXECUTION_OUTPUT_RECORDS, MAX_SANDBOX_HANDLE_BYTES,
    SealedActionGraph, SealedActionReadRequest, SealedActionTree, TargetPath,
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

pub(crate) fn sealed_exec_reservation(request: &ExecutionCommand) -> Option<u64> {
    exec_reservation(request)
}

pub(crate) fn copy_from_reservation(request: &CopyFromRequest) -> Option<u64> {
    request
        .byte_limit()
        .checked_add(MAGIC.len() + 8)
        .and_then(|value| u64::try_from(value).ok())
}

pub(crate) fn sealed_read_reservation(request: &SealedActionReadRequest) -> Option<u64> {
    bytes_reservation(request.byte_limit())
}

pub(crate) fn sealed_graph_reservation(request: &ActionGraphMaterializationRequest) -> Option<u64> {
    let fixed = MAGIC
        .len()
        .checked_add(1)?
        .checked_add(1)?
        .checked_add(32)?
        .checked_add(4)?;
    let trees = request
        .archives()
        .iter()
        .try_fold(0_usize, |total, archive| {
            total
                .checked_add(4 + MAX_SANDBOX_HANDLE_BYTES)
                .and_then(|value| value.checked_add(4))
                .and_then(|value| value.checked_add(4 + archive.destination().as_str().len()))
                .and_then(|value| value.checked_add(32))
        })?;
    u64::try_from(fixed.checked_add(trees)?).ok()
}

fn bytes_reservation(byte_limit: usize) -> Option<u64> {
    byte_limit
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
    encode_execution_output(result, request, 0, ExecutionStage::Exec)
}

pub(crate) fn decode_exec(
    encoded: &[u8],
    request: &ExecutionCommand,
) -> Result<Result<ExecutionOutput, ExecutionError>, ()> {
    decode_execution_output(encoded, request, 0, ExecutionStage::Exec)
}

pub(crate) fn encode_sealed_exec(
    result: &Result<ExecutionOutput, ExecutionError>,
    request: &ExecutionCommand,
) -> Result<Vec<u8>, ()> {
    encode_execution_output(result, request, 7, ExecutionStage::ExecSealedAction)
}

pub(crate) fn decode_sealed_exec(
    encoded: &[u8],
    request: &ExecutionCommand,
) -> Result<Result<ExecutionOutput, ExecutionError>, ()> {
    decode_execution_output(encoded, request, 7, ExecutionStage::ExecSealedAction)
}

fn encode_execution_output(
    result: &Result<ExecutionOutput, ExecutionError>,
    request: &ExecutionCommand,
    kind: u8,
    stage: ExecutionStage,
) -> Result<Vec<u8>, ()> {
    let mut encoded = header(kind);
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
        Err(error) => encode_error(&mut encoded, *error, stage)?,
    }
    Ok(encoded)
}

fn decode_execution_output(
    encoded: &[u8],
    request: &ExecutionCommand,
    kind: u8,
    stage: ExecutionStage,
) -> Result<Result<ExecutionOutput, ExecutionError>, ()> {
    let mut reader = Reader::new(encoded, kind)?;
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
        STATUS_ERROR => decode_error(&mut reader, stage).map(Err),
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

pub(crate) fn encode_sealed_read(
    result: &Result<Vec<u8>, ExecutionError>,
    request: &SealedActionReadRequest,
) -> Result<Vec<u8>, ()> {
    encode_bounded_bytes(
        result,
        request.byte_limit(),
        6,
        ExecutionStage::ReadSealedAction,
    )
}

pub(crate) fn decode_sealed_read(
    encoded: &[u8],
    request: &SealedActionReadRequest,
) -> Result<Result<Vec<u8>, ExecutionError>, ()> {
    decode_bounded_bytes(
        encoded,
        request.byte_limit(),
        6,
        ExecutionStage::ReadSealedAction,
    )
}

fn encode_bounded_bytes(
    result: &Result<Vec<u8>, ExecutionError>,
    byte_limit: usize,
    kind: u8,
    stage: ExecutionStage,
) -> Result<Vec<u8>, ()> {
    let mut encoded = header(kind);
    match result {
        Ok(bytes) => {
            if bytes.len() > byte_limit {
                return Err(());
            }
            encoded.push(STATUS_SUCCESS);
            put_bytes(&mut encoded, bytes)?;
        }
        Err(error) => encode_error(&mut encoded, *error, stage)?,
    }
    Ok(encoded)
}

fn decode_bounded_bytes(
    encoded: &[u8],
    byte_limit: usize,
    kind: u8,
    stage: ExecutionStage,
) -> Result<Result<Vec<u8>, ExecutionError>, ()> {
    let mut reader = Reader::new(encoded, kind)?;
    match reader.byte()? {
        STATUS_SUCCESS => {
            let bytes = reader.bytes()?;
            if bytes.len() > byte_limit {
                return Err(());
            }
            let bytes = bytes.to_vec();
            reader.finish()?;
            Ok(Ok(bytes))
        }
        STATUS_ERROR => decode_error(&mut reader, stage).map(Err),
        _ => Err(()),
    }
}

pub(crate) fn encode_sealed_graph(
    result: &Result<SealedActionGraph, ExecutionError>,
    request: &ActionGraphMaterializationRequest,
) -> Result<Vec<u8>, ()> {
    let mut encoded = header(5);
    match result {
        Ok(graph) => {
            if !sealed_graph_matches_request(graph, request) {
                return Err(());
            }
            encoded.push(STATUS_SUCCESS);
            put_digest(&mut encoded, graph.receipt_sha256());
            put_u32(&mut encoded, graph.trees().len())?;
            for tree in graph.trees() {
                put_text(&mut encoded, tree.graph_opaque())?;
                encoded.extend_from_slice(&tree.ordinal().to_be_bytes());
                put_text(&mut encoded, tree.root().as_str())?;
                put_digest(&mut encoded, tree.receipt_sha256());
            }
        }
        Err(error) => encode_error(&mut encoded, *error, ExecutionStage::MaterializeAction)?,
    }
    Ok(encoded)
}

pub(crate) fn decode_sealed_graph(
    encoded: &[u8],
    request: &ActionGraphMaterializationRequest,
) -> Result<Result<SealedActionGraph, ExecutionError>, ()> {
    let mut reader = Reader::new(encoded, 5)?;
    match reader.byte()? {
        STATUS_SUCCESS => {
            let receipt = reader.digest()?;
            let count = reader.length()?;
            if count != request.archives().len() {
                return Err(());
            }
            let mut trees = Vec::with_capacity(count);
            for archive in request.archives() {
                let graph_opaque = reader.text()?;
                let ordinal = reader.u32()?;
                let root = TargetPath::windows(reader.text()?).map_err(|_| ())?;
                let tree_receipt = reader.digest()?;
                if ordinal != archive.ordinal() || &root != archive.destination() {
                    return Err(());
                }
                trees.push(
                    SealedActionTree::new(
                        request.sandbox().clone(),
                        request.generation(),
                        graph_opaque,
                        request.graph_sha256(),
                        ordinal,
                        root,
                        tree_receipt,
                    )
                    .map_err(|_| ())?,
                );
            }
            reader.finish()?;
            SealedActionGraph::new(
                request.sandbox().clone(),
                request.generation(),
                request.graph_sha256(),
                receipt,
                trees,
            )
            .map(Ok)
            .map_err(|_| ())
        }
        STATUS_ERROR => decode_error(&mut reader, ExecutionStage::MaterializeAction).map(Err),
        _ => Err(()),
    }
}

fn sealed_graph_matches_request(
    graph: &SealedActionGraph,
    request: &ActionGraphMaterializationRequest,
) -> bool {
    graph.sandbox() == request.sandbox()
        && graph.generation() == request.generation()
        && graph.graph_sha256() == request.graph_sha256()
        && graph.trees().len() == request.archives().len()
        && graph
            .trees()
            .iter()
            .zip(request.archives())
            .all(|(tree, archive)| {
                tree.ordinal() == archive.ordinal() && tree.root() == archive.destination()
            })
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
        ExecutionStage::MaterializeAction => 5,
        ExecutionStage::ReadSealedAction => 6,
        ExecutionStage::ExecSealedAction => 7,
    }
}

const fn decode_stage(tag: u8) -> Result<ExecutionStage, ()> {
    match tag {
        0 => Ok(ExecutionStage::Exec),
        1 => Ok(ExecutionStage::Signal),
        2 => Ok(ExecutionStage::Wait),
        3 => Ok(ExecutionStage::CopyTo),
        4 => Ok(ExecutionStage::CopyFrom),
        5 => Ok(ExecutionStage::MaterializeAction),
        6 => Ok(ExecutionStage::ReadSealedAction),
        7 => Ok(ExecutionStage::ExecSealedAction),
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

fn put_digest(encoded: &mut Vec<u8>, digest: automata_ci_core::Sha256Digest) {
    encoded.extend_from_slice(digest.as_bytes());
}

fn put_text(encoded: &mut Vec<u8>, value: &str) -> Result<(), ()> {
    put_bytes(encoded, value.as_bytes())
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

    fn u32(&mut self) -> Result<u32, ()> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn digest(&mut self) -> Result<automata_ci_core::Sha256Digest, ()> {
        Ok(automata_ci_core::Sha256Digest::from_bytes(self.array()?))
    }

    fn text(&mut self) -> Result<String, ()> {
        let bytes = self.bytes()?;
        let value = std::str::from_utf8(bytes).map_err(|_| ())?;
        Ok(value.to_owned())
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

    use automata_ci_core::{
        JobContentReference, OperationId, Sha256Digest, WINDOWS_ACTION_ARCHIVE_MEDIA_TYPE,
        WindowsActionArchiveFacts, WindowsRepositoryActionArchive, WindowsRepositoryActionGraph,
    };
    use automata_ci_execution::{
        ActionArchiveMaterialization, CopyFromRequest, ExecutionArgv, ExecutionEnvironment,
        ExecutionOutputRecord, ExecutionOutputStream, ProviderId, SandboxGeneration, SandboxHandle,
        TargetPath,
    };
    use sha2::{Digest as _, Sha256};

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

    fn digest(bytes: &[u8]) -> Sha256Digest {
        Sha256Digest::from_bytes(Sha256::digest(bytes).into())
    }

    fn graph_request() -> ActionGraphMaterializationRequest {
        let content = b"sealed archive".to_vec();
        let action_key_sha256 = Sha256Digest::from_bytes([0x21; 32]);
        let content_sha256 = digest(&content);
        let facts = WindowsActionArchiveFacts::new(1, 1, 14, 14, 1).expect("facts");
        let planned = WindowsRepositoryActionArchive::new(
            0,
            action_key_sha256,
            "",
            JobContentReference::new(
                "windows-actions/0.tar.gz",
                content_sha256,
                u64::try_from(content.len()).expect("archive size"),
                WINDOWS_ACTION_ARCHIVE_MEDIA_TYPE,
            ),
            facts,
        )
        .expect("planned archive");
        let plan_sha256 = WindowsRepositoryActionGraph::new(vec![planned])
            .expect("planned graph")
            .graph_sha256();
        let archive = ActionArchiveMaterialization::new(
            0,
            action_key_sha256,
            "",
            TargetPath::windows(r"C:\actions\0000").expect("destination"),
            content,
            content_sha256,
            facts,
        )
        .expect("archive");
        ActionGraphMaterializationRequest::new(
            OperationId::new(),
            SandboxHandle::new(
                ProviderId::new("windows-hyperv").expect("provider"),
                "sandbox-1",
            )
            .expect("sandbox"),
            SandboxGeneration::new(7).expect("generation"),
            plan_sha256,
            vec![archive],
        )
        .expect("graph request")
    }

    fn sealed_tree(
        request: &ActionGraphMaterializationRequest,
        root: TargetPath,
        receipt: u8,
    ) -> SealedActionTree {
        SealedActionTree::new(
            request.sandbox().clone(),
            request.generation(),
            "sealed-graph-1",
            request.graph_sha256(),
            0,
            root,
            Sha256Digest::from_bytes([receipt; 32]),
        )
        .expect("sealed tree")
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

    #[test]
    fn sealed_graph_codec_round_trips_exact_request_bound_receipts() {
        let request = graph_request();
        let tree = sealed_tree(&request, request.archives()[0].destination().clone(), 0x41);
        let expected = SealedActionGraph::new(
            request.sandbox().clone(),
            request.generation(),
            request.graph_sha256(),
            Sha256Digest::from_bytes([0x51; 32]),
            vec![tree],
        )
        .expect("sealed graph");
        let encoded = encode_sealed_graph(&Ok(expected.clone()), &request).expect("encode graph");
        assert!(
            u64::try_from(encoded.len()).expect("length")
                <= sealed_graph_reservation(&request).expect("reservation")
        );
        assert_eq!(
            decode_sealed_graph(&encoded, &request).expect("decode graph"),
            Ok(expected)
        );

        let substituted = SealedActionGraph::new(
            request.sandbox().clone(),
            request.generation(),
            request.graph_sha256(),
            Sha256Digest::from_bytes([0x52; 32]),
            vec![sealed_tree(
                &request,
                TargetPath::windows(r"C:\actions\other").expect("other root"),
                0x42,
            )],
        )
        .expect("structurally valid substituted graph");
        assert!(encode_sealed_graph(&Ok(substituted), &request).is_err());
    }

    #[test]
    fn sealed_read_and_exec_codecs_reapply_stage_and_result_bounds() {
        let graph = graph_request();
        let tree = sealed_tree(&graph, graph.archives()[0].destination().clone(), 0x61);
        let broad = SealedActionReadRequest::new(OperationId::new(), tree.clone(), "action.yml", 4)
            .expect("broad read");
        let narrow = SealedActionReadRequest::new(broad.operation_id(), tree, "action.yml", 3)
            .expect("narrow read");
        let encoded = encode_sealed_read(&Ok(b"data".to_vec()), &broad).expect("encode read");
        assert_eq!(
            decode_sealed_read(&encoded, &broad).expect("decode read"),
            Ok(b"data".to_vec())
        );
        assert!(decode_sealed_read(&encoded, &narrow).is_err());

        let command = command(1024);
        let expected = output(ExecutionTermination::Exited(0));
        let encoded =
            encode_sealed_exec(&Ok(expected.clone()), &command).expect("encode sealed exec");
        assert_eq!(
            decode_sealed_exec(&encoded, &command).expect("decode sealed exec"),
            Ok(expected)
        );
        let wrong_stage =
            ExecutionError::new(ExecutionErrorKind::InvalidState, ExecutionStage::Exec);
        assert!(encode_sealed_exec(&Err(wrong_stage), &command).is_err());
    }
}
