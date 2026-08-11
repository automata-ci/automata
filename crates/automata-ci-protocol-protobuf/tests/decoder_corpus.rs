mod common;

use std::{
    collections::{BTreeMap, BTreeSet},
    panic::{AssertUnwindSafe, catch_unwind},
};

use automata_ci_core::{ContextValue, JobRuntimeContext, StrategyContext};
use automata_ci_protocol::{LeaseOffer, ProtocolLimits, ServerToRunner};
use automata_ci_protocol_protobuf::{
    DecodeError, EncodeError, decode_job_ir, decode_job_runtime_context, decode_runner_frame,
    decode_runtime_authorities, decode_server_frame, encode_job_ir, encode_job_runtime_context,
    encode_runner_frame, encode_runtime_authorities, encode_server_frame,
};

const FRAME_LIMIT: usize = 1_024;
const STRUCTURAL_CASES: usize = 192;
const OVERSIZED_CASES: usize = 8;
const CANONICAL_MUTATIONS_PER_DECODER: usize = 16;
const UNKNOWN_FIELD_BASE: u64 = 50_000;

#[test]
fn public_decoders_reject_a_deterministic_corpus_and_canonicalize_valid_mutations() {
    let bounded_limits =
        ProtocolLimits::new(FRAME_LIMIT, 64, 512, 16, 512).expect("coherent corpus limits");
    let canonical_limits = ProtocolLimits::default();
    let runner = common::runner_messages()
        .into_iter()
        .next()
        .expect("runner fixture")
        .1;
    let server_messages = common::server_messages();
    let server = server_messages.first().expect("server fixture").1.clone();
    let offer = lease_offer(&server_messages);
    let context = runtime_context();

    let runner_bytes =
        encode_runner_frame(&runner, &canonical_limits).expect("canonical runner frame");
    let server_bytes =
        encode_server_frame(&server, &canonical_limits).expect("canonical server frame");
    let job_bytes =
        encode_job_ir(offer.job(), &canonical_limits).expect("canonical standalone JobIR");
    let context_bytes =
        encode_job_runtime_context(&context, &canonical_limits).expect("canonical runtime context");
    let authority_bytes = encode_runtime_authorities(
        offer
            .runtime_authorities()
            .expect("lease offer runtime authorities"),
        offer.job(),
        offer.lease(),
        &canonical_limits,
    )
    .expect("canonical runtime authorities");
    let canonical_frames = [
        runner_bytes.as_slice(),
        server_bytes.as_slice(),
        job_bytes.as_slice(),
        context_bytes.as_slice(),
        authority_bytes.as_slice(),
    ];
    let (structural, oversized) = malformed_corpus(&canonical_frames);
    assert_eq!(structural.len(), STRUCTURAL_CASES);
    assert_eq!(oversized.len(), OVERSIZED_CASES);

    for (case, bytes) in structural.iter().enumerate() {
        assert!(bytes.len() <= FRAME_LIMIT, "structural case {case}");
        assert_all_decoders_reject(case, bytes, &bounded_limits, offer, None);
    }
    for (offset, bytes) in oversized.iter().enumerate() {
        assert_all_decoders_reject(
            STRUCTURAL_CASES + offset,
            bytes,
            &bounded_limits,
            offer,
            Some(bytes.len()),
        );
    }

    assert_unknown_fields_are_canonicalized(
        "runner",
        &runner_bytes,
        |bytes| decode_runner_frame(bytes, &canonical_limits),
        |decoded| encode_runner_frame(decoded.message(), &canonical_limits),
    );
    assert_unknown_fields_are_canonicalized(
        "server",
        &server_bytes,
        |bytes| decode_server_frame(bytes, &canonical_limits),
        |decoded| encode_server_frame(decoded.message(), &canonical_limits),
    );
    assert_unknown_fields_are_canonicalized(
        "job_ir",
        &job_bytes,
        |bytes| decode_job_ir(bytes, &canonical_limits),
        |decoded| encode_job_ir(decoded, &canonical_limits),
    );
    assert_unknown_fields_are_canonicalized(
        "runtime_context",
        &context_bytes,
        |bytes| decode_job_runtime_context(bytes, &canonical_limits),
        |decoded| encode_job_runtime_context(decoded, &canonical_limits),
    );
    assert_unknown_fields_are_canonicalized(
        "runtime_authorities",
        &authority_bytes,
        |bytes| decode_runtime_authorities(bytes, offer.job(), offer.lease(), &canonical_limits),
        |decoded| {
            encode_runtime_authorities(decoded, offer.job(), offer.lease(), &canonical_limits)
        },
    );
}

fn lease_offer<'a>(messages: &'a [(&'static str, ServerToRunner)]) -> &'a LeaseOffer {
    messages
        .iter()
        .find_map(|(_, message)| match message {
            ServerToRunner::LeaseOffer(offer) => Some(offer.as_ref()),
            _ => None,
        })
        .expect("lease-offer fixture")
}

fn runtime_context() -> JobRuntimeContext {
    JobRuntimeContext::new(
        ContextValue::empty_object(),
        ContextValue::empty_object(),
        ContextValue::empty_object(),
        StrategyContext::new(true, 0, 1, 1).expect("single-job strategy"),
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .expect("minimal runtime context")
}

fn assert_all_decoders_reject(
    case: usize,
    bytes: &[u8],
    limits: &ProtocolLimits,
    offer: &LeaseOffer,
    oversized_length: Option<usize>,
) {
    let errors = [
        (
            "runner",
            typed_rejection("runner", case, || decode_runner_frame(bytes, limits)),
        ),
        (
            "server",
            typed_rejection("server", case, || decode_server_frame(bytes, limits)),
        ),
        (
            "job_ir",
            typed_rejection("job_ir", case, || decode_job_ir(bytes, limits)),
        ),
        (
            "runtime_context",
            typed_rejection("runtime_context", case, || {
                decode_job_runtime_context(bytes, limits)
            }),
        ),
        (
            "runtime_authorities",
            typed_rejection("runtime_authorities", case, || {
                decode_runtime_authorities(bytes, offer.job(), offer.lease(), limits)
            }),
        ),
    ];

    for (decoder, error) in errors {
        if let Some(size) = oversized_length {
            assert!(
                matches!(
                    error,
                    DecodeError::FrameTooLarge { size: actual, maximum }
                        if actual == size && maximum == FRAME_LIMIT
                ),
                "{decoder} case {case} did not reject size first: {error:?}"
            );
        } else {
            assert!(
                !matches!(
                    error,
                    DecodeError::EmptyFrame | DecodeError::FrameTooLarge { .. }
                ),
                "{decoder} structural case {case} bypassed its bounded parse path: {error:?}"
            );
        }
    }
}

fn typed_rejection<T>(
    decoder: &str,
    case: usize,
    decode: impl FnOnce() -> Result<T, DecodeError>,
) -> DecodeError {
    let result = catch_unwind(AssertUnwindSafe(decode))
        .unwrap_or_else(|_| panic!("{decoder} panicked on corpus case {case}"));
    match result {
        Err(error) => error,
        Ok(_) => panic!("{decoder} accepted malformed corpus case {case}"),
    }
}

fn assert_unknown_fields_are_canonicalized<T>(
    entrypoint: &str,
    canonical: &[u8],
    mut decode: impl FnMut(&[u8]) -> Result<T, DecodeError>,
    mut encode: impl FnMut(&T) -> Result<Vec<u8>, EncodeError>,
) {
    let mut random = CorpusRandom::new(0xd1ce_cafe_5eed_u64 ^ stable_seed(entrypoint));
    for mutation in 0..CANONICAL_MUTATIONS_PER_DECODER {
        let payload_length = mutation * 2;
        let mut augmented = canonical.to_vec();
        append_varint(
            ((UNKNOWN_FIELD_BASE + u64::try_from(mutation).expect("small mutation")) << 3) | 2,
            &mut augmented,
        );
        append_varint(
            u64::try_from(payload_length).expect("small payload"),
            &mut augmented,
        );
        augmented.extend(random.bytes(payload_length));

        let decoded = decode(&augmented)
            .unwrap_or_else(|error| panic!("{entrypoint} valid mutation {mutation}: {error:?}"));
        let reencoded = encode(&decoded)
            .unwrap_or_else(|error| panic!("{entrypoint} re-encode {mutation}: {error:?}"));
        assert_eq!(
            reencoded, canonical,
            "{entrypoint} did not discard unknown field in mutation {mutation}"
        );
        assert_ne!(augmented, canonical);
    }
}

fn malformed_corpus(canonical_frames: &[&[u8]]) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut random = CorpusRandom::new(0x5eed_51de_bad5_eed5);
    let mut structural = BTreeSet::new();

    for case in 0..64_u64 {
        let payload_length = usize::try_from(random.next() % 32).expect("small payload");
        let missing = 1 + usize::try_from(random.next() % 4).expect("small truncation");
        let mut bytes = Vec::new();
        append_varint(((UNKNOWN_FIELD_BASE + case) << 3) | 2, &mut bytes);
        append_varint(
            u64::try_from(payload_length + missing).expect("small declared length"),
            &mut bytes,
        );
        bytes.extend(random.bytes(payload_length));
        assert!(structural.insert(bytes), "duplicate length case {case}");
    }

    for case in 0..64_u64 {
        let continuation_bytes = 1 + usize::try_from(random.next() % 10).expect("small varint");
        let mut bytes = Vec::new();
        append_varint((UNKNOWN_FIELD_BASE + 100 + case) << 3, &mut bytes);
        bytes.extend(
            random
                .bytes(continuation_bytes)
                .into_iter()
                .map(|byte| byte | 0x80),
        );
        assert!(structural.insert(bytes), "duplicate varint case {case}");
    }

    for case in 0..32_u64 {
        let mut bytes = Vec::new();
        let invalid_wire_type = 6 + (case % 2);
        append_varint(
            ((UNKNOWN_FIELD_BASE + 200 + case) << 3) | invalid_wire_type,
            &mut bytes,
        );
        let suffix_length = usize::try_from(random.next() % 12).expect("small suffix");
        bytes.extend(random.bytes(suffix_length));
        assert!(structural.insert(bytes), "duplicate wire case {case}");
    }

    for case in 0..32_u64 {
        let frame_index = usize::try_from(case).expect("small case") % canonical_frames.len();
        let canonical = canonical_frames[frame_index];
        let prefix_window = canonical.len().min(128);
        let prefix_length = 1 + usize::try_from(
            random.next() % u64::try_from(prefix_window).expect("small prefix window"),
        )
        .expect("small prefix length");
        let mut bytes = canonical[..prefix_length].to_vec();
        append_varint(((UNKNOWN_FIELD_BASE + 300 + case) << 3) | 2, &mut bytes);
        let payload_length = usize::try_from(random.next() % 8).expect("small payload");
        append_varint(
            u64::try_from(payload_length + 1).expect("small declared length"),
            &mut bytes,
        );
        bytes.extend(random.bytes(payload_length));
        assert!(structural.insert(bytes), "duplicate prefix case {case}");
    }

    let oversized = (1..=OVERSIZED_CASES)
        .map(|extra| random.bytes(FRAME_LIMIT + extra))
        .collect();
    (structural.into_iter().collect(), oversized)
}

fn append_varint(mut value: u64, output: &mut Vec<u8>) {
    loop {
        let low = u8::try_from(value & 0x7f).expect("seven bits");
        value >>= 7;
        if value == 0 {
            output.push(low);
            return;
        }
        output.push(low | 0x80);
    }
}

fn stable_seed(value: &str) -> u64 {
    value.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

struct CorpusRandom(u64);

impl CorpusRandom {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn bytes(&mut self, length: usize) -> Vec<u8> {
        (0..length).map(|_| self.next().to_le_bytes()[0]).collect()
    }
}
