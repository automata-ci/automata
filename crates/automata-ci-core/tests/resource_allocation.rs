use automata_ci_core::{
    JobResourceAllocation, JobResourcePolicy, ResourceAllocationError, ResourceCapacity,
    ResourcePolicyError, ResourceQuantityError, parse_cpu_quantity, parse_storage_quantity,
};

#[test]
fn cpu_quantities_use_exact_millicores() {
    for (source, expected) in [
        ("1m", 1),
        ("500m", 500),
        ("1", 1_000),
        ("1.2", 1_200),
        ("1.25", 1_250),
        ("1.025", 1_025),
    ] {
        assert_eq!(parse_cpu_quantity(source), Ok(expected), "{source}");
    }
    for source in ["", "0", "0m", "-1", "1.0001", "1e3", "1M"] {
        assert!(parse_cpu_quantity(source).is_err(), "{source}");
    }
    assert_eq!(
        parse_cpu_quantity("4294968"),
        Err(ResourceQuantityError::CpuOverflow)
    );
}

#[test]
fn storage_quantities_use_exact_bytes() {
    for (source, expected) in [
        ("1", 1),
        ("1Ki", 1_024),
        ("16Mi", 16 * 1_024 * 1_024),
        ("2Gi", 2 * 1_024 * 1_024 * 1_024),
        ("1G", 1_000_000_000),
    ] {
        assert_eq!(parse_storage_quantity(source), Ok(expected), "{source}");
    }
    for source in ["", "0", "-1", "1.5Gi", "1mi", "1e3"] {
        assert!(parse_storage_quantity(source).is_err(), "{source}");
    }
    assert_eq!(
        parse_storage_quantity("16Ei"),
        Err(ResourceQuantityError::StorageOverflow)
    );
}

#[test]
fn resolved_allocations_enforce_requests_and_limits() {
    let requests = ResourceCapacity::new(500, 512 * 1_024 * 1_024, 1_024, 1);
    let limits = ResourceCapacity::new(2_000, 2 * 1_024 * 1_024 * 1_024, 2_048, 1);
    let allocation = JobResourceAllocation::new(requests, limits).expect("valid allocation");
    assert_eq!(allocation.requests(), requests);
    assert_eq!(allocation.limits(), limits);

    assert_eq!(
        JobResourceAllocation::new(limits, requests),
        Err(ResourceAllocationError::RequestExceedsLimit)
    );
    assert_eq!(
        JobResourceAllocation::new(
            ResourceCapacity::new(500, 512 * 1_024 * 1_024, 1_024, 0),
            limits,
        ),
        Err(ResourceAllocationError::GpuRequestLimitMismatch)
    );
}

#[test]
fn capacity_arithmetic_is_dimension_safe() {
    let left = ResourceCapacity::new(500, 1_000, 2_000, 1);
    let right = ResourceCapacity::new(250, 500, 1_000, 2);
    let total = ResourceCapacity::new(750, 1_500, 3_000, 3);
    assert_eq!(left.checked_add(right), Some(total));
    assert_eq!(total.checked_sub(right), Some(left));
    assert!(right.checked_sub(left).is_none());
    assert!(left.fits_within(total));
}

#[test]
fn pinned_policy_validates_defaults_and_workflow_bounds() {
    let defaults = JobResourceAllocation::new(
        ResourceCapacity::new(500, 512 * 1_024 * 1_024, 0, 0),
        ResourceCapacity::new(1_000, 1_024 * 1_024 * 1_024, 0, 0),
    )
    .expect("defaults");
    let policy = JobResourcePolicy::new(
        defaults,
        ResourceCapacity::new(100, 128 * 1_024 * 1_024, 0, 0),
        ResourceCapacity::new(4_000, 8 * 1_024 * 1_024 * 1_024, 0, 0),
    )
    .expect("policy");
    assert_eq!(policy.defaults(), defaults);
    let below = JobResourceAllocation::new(
        ResourceCapacity::new(50, 512 * 1_024 * 1_024, 0, 0),
        ResourceCapacity::new(1_000, 1_024 * 1_024 * 1_024, 0, 0),
    )
    .expect("allocation");
    assert_eq!(
        policy.validate_allocation(below),
        Err(ResourcePolicyError::RequestBelowMinimum)
    );
}
