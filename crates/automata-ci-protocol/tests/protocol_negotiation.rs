use automata_ci_core::{JobIrVersion, JobIrVersionError, JobIrVersionRange};
use automata_ci_protocol::{
    PROTOCOL_MAX_VERSION, PROTOCOL_MIN_VERSION, ProtocolNegotiationError, ProtocolRange,
    ProtocolVersion, SUPPORTED_PROTOCOL_RANGE, negotiate_job_ir, negotiate_protocol,
};

fn version(value: u16) -> ProtocolVersion {
    ProtocolVersion::new(value).expect("positive test version")
}

fn range(min: u16, max: u16) -> ProtocolRange {
    ProtocolRange::new(version(min), version(max)).expect("valid test range")
}

#[test]
fn negotiation_selects_highest_common_version() {
    assert_eq!(negotiate_protocol(range(1, 4), range(3, 6)), Ok(version(4)));
    assert_eq!(negotiate_protocol(range(3, 6), range(1, 4)), Ok(version(4)));
}

#[test]
fn disjoint_ranges_return_typed_error() {
    let local = range(1, 2);
    let remote = range(3, 4);
    assert_eq!(
        negotiate_protocol(local, remote),
        Err(ProtocolNegotiationError::NoCommonVersion { local, remote }),
    );
}

#[test]
fn current_protocol_is_exactly_v2_and_rejects_legacy_and_forward_skew() {
    assert_eq!(PROTOCOL_MIN_VERSION, version(2));
    assert_eq!(PROTOCOL_MAX_VERSION, version(2));
    assert_eq!(SUPPORTED_PROTOCOL_RANGE, range(2, 2));

    let legacy = range(1, 1);
    assert_eq!(
        negotiate_protocol(SUPPORTED_PROTOCOL_RANGE, legacy),
        Err(ProtocolNegotiationError::NoCommonVersion {
            local: SUPPORTED_PROTOCOL_RANGE,
            remote: legacy,
        })
    );

    let unsupported = range(3, 3);
    assert_eq!(
        negotiate_protocol(SUPPORTED_PROTOCOL_RANGE, unsupported),
        Err(ProtocolNegotiationError::NoCommonVersion {
            local: SUPPORTED_PROTOCOL_RANGE,
            remote: unsupported,
        })
    );
}

#[test]
fn negotiated_version_is_exactly_highest_intersection_property_style() {
    for local_min in 1..=5 {
        for local_max in local_min..=5 {
            for remote_min in 1..=5 {
                for remote_max in remote_min..=5 {
                    let local = range(local_min, local_max);
                    let remote = range(remote_min, remote_max);
                    let expected_min = local_min.max(remote_min);
                    let expected_max = local_max.min(remote_max);
                    let result = negotiate_protocol(local, remote);
                    if expected_min <= expected_max {
                        assert_eq!(result, Ok(version(expected_max)));
                    } else {
                        assert!(matches!(
                            result,
                            Err(ProtocolNegotiationError::NoCommonVersion { .. }),
                        ));
                    }
                }
            }
        }
    }
}

#[test]
fn job_ir_negotiation_accepts_the_exact_current_contract() {
    let current = JobIrVersionRange::current();
    assert_eq!(
        negotiate_job_ir(current, current),
        Ok(JobIrVersion::current()),
    );
}

#[test]
fn non_current_job_ir_ranges_cannot_enter_negotiation() {
    let unsupported = JobIrVersion::new(JobIrVersion::current().get() + 1)
        .expect("positive unsupported JobIR version");

    assert_eq!(
        JobIrVersionRange::new(unsupported, unsupported),
        Err(JobIrVersionError::UnsupportedRange {
            minimum: unsupported,
            maximum: unsupported,
        })
    );
}
