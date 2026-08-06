use automata_protocol::{
    ProtocolNegotiationError, ProtocolRange, ProtocolVersion, negotiate_protocol,
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
