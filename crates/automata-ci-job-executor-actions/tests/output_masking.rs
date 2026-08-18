#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExecutorAdapterError;

impl ExecutorAdapterError {
    pub(crate) const fn new(_kind: error::ExecutorAdapterErrorKind) -> Self {
        Self
    }
}

pub(crate) mod error {
    #[allow(dead_code)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum ExecutorAdapterErrorKind {
        InvalidJob,
        ResourceExhausted,
        Internal,
        Cancelled,
    }
}

#[allow(dead_code)]
#[path = "../src/output.rs"]
mod output;

use automata_ci_auth::output_policy::SecretExposureClass;
use automata_ci_core::JobSecretExposure;
use output::SecretMasker;

#[test]
fn registering_a_readable_secret_permanently_narrows_output_safety() {
    let mut masker = SecretMasker::new();
    assert_eq!(masker.exposure_class(), SecretExposureClass::Secretless);
    assert_eq!(masker.job_secret_exposure(), JobSecretExposure::Secretless);

    masker
        .register("")
        .expect("empty values are not credentials");
    assert_eq!(masker.exposure_class(), SecretExposureClass::Secretless);

    masker.register("credential").expect("register credential");
    assert_eq!(masker.exposure_class(), SecretExposureClass::ReadableSecret);
    assert_eq!(
        masker.job_secret_exposure(),
        JobSecretExposure::ReadableSecret
    );
}

#[test]
fn matcher_is_cached_until_a_distinct_mask_is_registered() {
    let mut masker = SecretMasker::new();
    masker.register("alpha").expect("register alpha");
    masker.register("beta").expect("register beta");

    assert_eq!(masker.matcher_builds(), 0);
    assert_eq!(masker.mask(b"alpha beta").expect("mask"), b"*** ***");
    assert_eq!(masker.matcher_builds(), 1);
    assert_eq!(masker.mask(b"beta alpha").expect("mask"), b"*** ***");
    assert_eq!(masker.matcher_builds(), 1);

    masker.register("alpha").expect("duplicate mask");
    assert_eq!(masker.mask(b"alpha").expect("mask"), b"***");
    assert_eq!(masker.matcher_builds(), 1);

    masker.register("gamma").expect("dynamic mask");
    assert_eq!(masker.mask(b"alpha gamma").expect("mask"), b"*** ***");
    assert_eq!(masker.matcher_builds(), 2);
}

#[test]
fn secret_membership_check_is_exact_and_reuses_the_masker() {
    let mut masker = SecretMasker::new();
    masker.register("credential").expect("register credential");

    assert!(!masker.contains_secret("public-value").expect("scan public"));
    assert!(
        masker
            .contains_secret("prefix-credential-suffix")
            .expect("scan secret-derived")
    );
    assert_eq!(masker.matcher_builds(), 1);
}

#[test]
fn overlapping_masks_choose_the_longest_leftmost_match_without_leaking() {
    let mut masker = SecretMasker::new();
    for mask in ["abc", "bcd", "c", "aba", "bab"] {
        masker.register(mask).expect("register overlap");
    }

    let output = masker.mask(b"zabcdz abab z").expect("mask");

    assert_eq!(output, b"z***dz ***b z");
    for mask in [b"abc".as_slice(), b"bcd", b"c", b"aba", b"bab"] {
        assert!(!output.windows(mask.len()).any(|window| window == mask));
    }
}

#[test]
fn synthesized_masks_and_single_byte_markers_fail_closed() {
    let mut joined = SecretMasker::new();
    joined
        .register("left***right")
        .expect("register synthesized value");
    joined.register("secret").expect("register secret");
    assert_eq!(joined.mask(b"leftsecretright").expect("mask"), b"***");

    let mut single_byte = SecretMasker::new();
    single_byte.register("*").expect("register star");
    assert!(
        single_byte
            .mask(b"visible * value")
            .expect("mask")
            .is_empty()
    );

    let mut ordinary = SecretMasker::new();
    ordinary.register("x").expect("register byte");
    assert_eq!(ordinary.mask(b"x").expect("mask"), b"***");
}

#[test]
fn thousands_of_masks_scan_one_long_repetitive_line_with_one_matcher_build() {
    let mut masker = SecretMasker::new();
    for index in 0..4_096 {
        masker
            .register(&format!("mask-{index:04}-value"))
            .expect("register bounded mask set");
    }
    assert!(masker.register("one-mask-too-many").is_err());

    let mut source = vec![b'a'; 1_024 * 1_024];
    source.extend_from_slice(b"mask-4095-value");
    let output = masker.mask(&source).expect("mask long line");

    assert_eq!(output.len(), 1_024 * 1_024 + 3);
    assert!(output.ends_with(b"***"));
    assert_eq!(masker.matcher_builds(), 1);
}

#[test]
fn aggregate_mask_bytes_are_bounded() {
    let mut masker = SecretMasker::new();
    let maximum = "s".repeat(1_024 * 1_024);

    masker.register(&maximum).expect("register maximum bytes");
    assert!(masker.register("t").is_err());
}
