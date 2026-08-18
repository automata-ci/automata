#![forbid(unsafe_code)]

use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExecutorAdapterError;

impl ExecutorAdapterError {
    pub(crate) const fn new(_kind: error::ExecutorAdapterErrorKind) -> Self {
        Self
    }
}

pub(crate) mod error {
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

use output::SecretMasker;

const REPLACEMENT: &[u8] = b"***";

#[test]
fn bounded_exhaustive_matches_leftmost_longest_reference() {
    let alphabet = b"ab*";
    let patterns = words(alphabet, 2)
        .into_iter()
        .filter(|word| !word.is_empty())
        .map(|word| String::from_utf8(word).expect("ASCII pattern"))
        .collect::<Vec<_>>();
    let sources = words(alphabet, 5);
    let mut selected = Vec::new();
    let mut case_index = 0_usize;

    check_combinations(&patterns, &sources, 0, &mut selected, &mut case_index);

    assert_eq!(case_index, 298);
}

#[test]
fn adversarial_overlaps_duplicates_and_marker_collisions_match_reference() {
    for (case_index, (masks, sources)) in [
        (
            vec!["a", "ab", "aba", "ba", "bab", "baba"],
            text_sources(&["ababa", "babab", "zabac", "a", ""]),
        ),
        (
            vec!["abc", "bcd", "c", "aba", "bab"],
            text_sources(&["zabcdz abab z", "abcbd", "cababc"]),
        ),
        (
            vec!["aba", "aba", "bab", "aba"],
            text_sources(&["ababa", "babab", "abaaba"]),
        ),
        (
            vec!["left***right", "secret"],
            text_sources(&["leftsecretright", "secretleftsecretright"]),
        ),
        (
            vec!["***", "secret"],
            text_sources(&["secret", "before-secret-after", "***"]),
        ),
        (
            vec!["*", "**", "needle"],
            text_sources(&["needle", "visible * value", "**needle**"]),
        ),
        (
            vec!["alpha\r\n beta ", "alpha", "beta"],
            text_sources(&["alpha beta", "alpha\r\n beta ", "zbetaz"]),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        assert_mask_set(&masks, &sources, case_index);
    }
}

#[test]
fn duplicate_registration_after_first_scan_keeps_one_matcher_build() {
    let masks = ["aba", "bab"];
    let registered = registered_masks(&masks);
    let mut masker = SecretMasker::new();
    for mask in masks {
        masker.register(mask).expect("register mask");
    }

    for source in text_sources(&["ababa", "babab"]) {
        assert_mask_result(&mut masker, &registered, &source, 0, 0);
    }
    assert_eq!(masker.matcher_builds(), 1);

    masker.register("aba").expect("duplicate mask");
    masker.register("bab").expect("duplicate mask");
    for source in text_sources(&["abaaba", "zzbabzz"]) {
        assert_mask_result(&mut masker, &registered, &source, 0, 1);
    }
    assert_eq!(masker.matcher_builds(), 1);
}

fn check_combinations<'a>(
    patterns: &'a [String],
    sources: &[Vec<u8>],
    start: usize,
    selected: &mut Vec<&'a str>,
    case_index: &mut usize,
) {
    for (index, pattern) in patterns.iter().enumerate().skip(start) {
        selected.push(pattern);
        assert_mask_set(selected, sources, *case_index);
        *case_index += 1;
        if selected.len() < 3 {
            check_combinations(patterns, sources, index + 1, selected, case_index);
        }
        selected.pop();
    }
}

fn assert_mask_set(masks: &[&str], sources: &[Vec<u8>], case_index: usize) {
    let registered = registered_masks(masks);
    let mut masker = SecretMasker::new();
    for mask in masks {
        masker.register(mask).expect("register bounded mask");
    }

    for (source_index, source) in sources.iter().enumerate() {
        assert_mask_result(&mut masker, &registered, source, case_index, source_index);
    }
    assert_eq!(
        masker.matcher_builds(),
        1,
        "mask set {case_index} rebuilt its matcher"
    );
}

fn assert_mask_result(
    masker: &mut SecretMasker,
    masks: &[Vec<u8>],
    source: &[u8],
    case_index: usize,
    source_index: usize,
) {
    let actual = masker.mask(source).expect("mask bounded source");
    let expected = reference_mask(masks, source);
    assert_eq!(
        actual, expected,
        "mask set {case_index}, source {source_index} disagreed with the reference"
    );
    assert!(
        masks.iter().all(|mask| !contains(&actual, mask)),
        "mask set {case_index}, source {source_index} retained registered plaintext"
    );
}

fn reference_mask(masks: &[Vec<u8>], source: &[u8]) -> Vec<u8> {
    if source.is_empty() || masks.is_empty() {
        return source.to_vec();
    }

    let mut output = Vec::with_capacity(source.len());
    let mut cursor = 0_usize;
    while let Some((start, length)) = next_leftmost_longest(masks, source, cursor) {
        output.extend_from_slice(&source[cursor..start]);
        output.extend_from_slice(REPLACEMENT);
        cursor = start + length;
    }
    output.extend_from_slice(&source[cursor..]);

    if masks.iter().any(|mask| contains(&output, mask)) {
        if masks.iter().all(|mask| !contains(REPLACEMENT, mask)) {
            return REPLACEMENT.to_vec();
        }
        return Vec::new();
    }
    output
}

fn next_leftmost_longest(
    masks: &[Vec<u8>],
    source: &[u8],
    cursor: usize,
) -> Option<(usize, usize)> {
    for start in cursor..source.len() {
        let longest = masks
            .iter()
            .filter(|mask| source[start..].starts_with(mask))
            .map(Vec::len)
            .max();
        if let Some(length) = longest {
            return Some((start, length));
        }
    }
    None
}

fn registered_masks(values: &[&str]) -> Vec<Vec<u8>> {
    let mut masks = BTreeSet::new();
    for value in values {
        if value.is_empty() {
            continue;
        }
        masks.insert(value.as_bytes().to_vec());
        for line in value
            .split(['\r', '\n'])
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            masks.insert(line.as_bytes().to_vec());
        }
    }
    masks.into_iter().collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn words(alphabet: &[u8], maximum_length: usize) -> Vec<Vec<u8>> {
    let mut words = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..maximum_length {
        let mut next = Vec::with_capacity(frontier.len() * alphabet.len());
        for prefix in &frontier {
            for byte in alphabet {
                let mut word = prefix.clone();
                word.push(*byte);
                next.push(word);
            }
        }
        words.extend(next.iter().cloned());
        frontier = next;
    }
    words
}

fn text_sources(values: &[&str]) -> Vec<Vec<u8>> {
    values
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect()
}
