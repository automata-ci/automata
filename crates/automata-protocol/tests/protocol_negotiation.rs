use automata_core::{JobIrVersion, JobIrVersionRange};
use automata_protocol::{
    JobIrNegotiationError, PROTOCOL_MAX_VERSION, PROTOCOL_MIN_VERSION, ProtocolNegotiationError,
    ProtocolRange, ProtocolVersion, SUPPORTED_PROTOCOL_RANGE, negotiate_job_ir, negotiate_protocol,
};

fn version(value: u16) -> ProtocolVersion {
    ProtocolVersion::new(value).expect("positive test version")
}

fn range(min: u16, max: u16) -> ProtocolRange {
    ProtocolRange::new(version(min), version(max)).expect("valid test range")
}

fn job_ir_range(minimum: u16, maximum: u16) -> JobIrVersionRange {
    JobIrVersionRange::new(
        JobIrVersion::new(minimum).expect("positive JobIR version"),
        JobIrVersion::new(maximum).expect("positive JobIR version"),
    )
    .expect("ordered JobIR range")
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
fn current_lease_request_chaining_protocol_is_exactly_v4_with_no_v3_downgrade() {
    assert_eq!(PROTOCOL_MIN_VERSION, version(4));
    assert_eq!(PROTOCOL_MAX_VERSION, version(4));
    assert_eq!(SUPPORTED_PROTOCOL_RANGE, range(4, 4));

    let legacy = range(3, 3);
    assert_eq!(
        negotiate_protocol(SUPPORTED_PROTOCOL_RANGE, legacy),
        Err(ProtocolNegotiationError::NoCommonVersion {
            local: SUPPORTED_PROTOCOL_RANGE,
            remote: legacy,
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
fn job_ir_negotiation_selects_the_highest_common_schema() {
    assert_eq!(
        negotiate_job_ir(job_ir_range(1, 3), job_ir_range(2, 4)),
        Ok(JobIrVersion::new(3).expect("positive JobIR version")),
    );
    let local = job_ir_range(1, 2);
    let remote = job_ir_range(3, 4);
    assert_eq!(
        negotiate_job_ir(local, remote),
        Err(JobIrNegotiationError::NoCommonVersion { local, remote }),
    );
}

#[test]
fn current_job_ir_has_no_downgrade_intersection_with_v1() {
    let current = JobIrVersionRange::current();
    let legacy = job_ir_range(1, 1);

    assert_eq!(
        negotiate_job_ir(current, legacy),
        Err(JobIrNegotiationError::NoCommonVersion {
            local: current,
            remote: legacy,
        }),
    );
}
