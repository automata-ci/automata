use std::collections::HashSet;

use automata_ci_auth::github::GithubEndpointError;
use reqwest::header::{HeaderMap, LINK};
use url::Url;

use crate::config::{GithubTrustedOrigins, same_origin};

const MAX_LINK_HEADER_BYTES: usize = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PageKind {
    ActiveOrganizations,
    Teams,
}

#[derive(Debug)]
pub(crate) struct PageBudget {
    remaining_pages: usize,
    remaining_items: usize,
    visited: HashSet<Url>,
}

impl PageBudget {
    pub(crate) fn new(maximum_pages: usize, maximum_items: usize) -> Self {
        Self {
            remaining_pages: maximum_pages,
            remaining_items: maximum_items,
            visited: HashSet::new(),
        }
    }

    pub(crate) fn visit(&mut self, url: &Url) -> Result<(), GithubEndpointError> {
        self.remaining_pages = self
            .remaining_pages
            .checked_sub(1)
            .ok_or(GithubEndpointError::InvalidResponse)?;
        if !self.visited.insert(url.clone()) {
            return Err(GithubEndpointError::InvalidResponse);
        }
        Ok(())
    }

    pub(crate) fn consume_items(&mut self, count: usize) -> Result<(), GithubEndpointError> {
        self.remaining_items = self
            .remaining_items
            .checked_sub(count)
            .ok_or(GithubEndpointError::InvalidResponse)?;
        Ok(())
    }
}

pub(crate) fn next_page(
    headers: &HeaderMap,
    trusted: &GithubTrustedOrigins,
    expected_path: &str,
    kind: PageKind,
) -> Result<Option<Url>, GithubEndpointError> {
    let mut total_length = 0_usize;
    let mut next = None;
    for value in headers.get_all(LINK) {
        let raw = value
            .to_str()
            .map_err(|_| GithubEndpointError::InvalidResponse)?;
        total_length = total_length
            .checked_add(raw.len())
            .ok_or(GithubEndpointError::InvalidResponse)?;
        if total_length > MAX_LINK_HEADER_BYTES {
            return Err(GithubEndpointError::InvalidResponse);
        }
        for link in split_links(raw)? {
            let parsed = parse_link(link)?;
            validate_page_url(&parsed.url, trusted, expected_path, kind)?;
            if parsed.is_next {
                if next.is_some() {
                    return Err(GithubEndpointError::InvalidResponse);
                }
                next = Some(parsed.url);
            }
        }
    }
    Ok(next)
}

struct ParsedLink {
    url: Url,
    is_next: bool,
}

fn split_links(raw: &str) -> Result<Vec<&str>, GithubEndpointError> {
    let mut links = Vec::new();
    let mut start = 0;
    let mut inside_angle = false;
    let mut inside_quote = false;
    let mut escaped = false;
    for (index, character) in raw.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if inside_quote => escaped = true,
            '"' if !inside_angle => inside_quote = !inside_quote,
            '<' if !inside_quote => {
                if inside_angle {
                    return Err(GithubEndpointError::InvalidResponse);
                }
                inside_angle = true;
            }
            '>' if !inside_quote => {
                if !inside_angle {
                    return Err(GithubEndpointError::InvalidResponse);
                }
                inside_angle = false;
            }
            ',' if !inside_angle && !inside_quote => {
                links.push(raw[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    if inside_angle || inside_quote || escaped {
        return Err(GithubEndpointError::InvalidResponse);
    }
    links.push(raw[start..].trim());
    if links.iter().any(|link| link.is_empty()) {
        return Err(GithubEndpointError::InvalidResponse);
    }
    Ok(links)
}

fn parse_link(raw: &str) -> Result<ParsedLink, GithubEndpointError> {
    let target_end = raw
        .strip_prefix('<')
        .and_then(|remainder| remainder.find('>').map(|index| index + 1))
        .ok_or(GithubEndpointError::InvalidResponse)?;
    let target = &raw[1..target_end];
    if target
        .bytes()
        .any(|character| character.is_ascii_control() || character == b' ')
    {
        return Err(GithubEndpointError::InvalidResponse);
    }
    let url = Url::parse(target).map_err(|_| GithubEndpointError::InvalidResponse)?;
    let suffix = raw
        .get(target_end + 1..)
        .ok_or(GithubEndpointError::InvalidResponse)?;
    let mut relations = None;
    if suffix.is_empty() {
        return Ok(ParsedLink {
            url,
            is_next: false,
        });
    }
    let parameters = suffix
        .strip_prefix(';')
        .ok_or(GithubEndpointError::InvalidResponse)?;
    for parameter in parameters.split(';') {
        if parameter.trim().is_empty() {
            return Err(GithubEndpointError::InvalidResponse);
        }
        let (name, value) = parameter
            .trim()
            .split_once('=')
            .ok_or(GithubEndpointError::InvalidResponse)?;
        let name = name.trim();
        let value = parse_parameter_value(value.trim())?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|character| character.is_ascii_alphanumeric() || character == b'-')
        {
            return Err(GithubEndpointError::InvalidResponse);
        }
        if name.eq_ignore_ascii_case("rel") {
            if relations.is_some() {
                return Err(GithubEndpointError::InvalidResponse);
            }
            relations = Some(value.to_owned());
        }
    }
    let is_next = relations
        .as_deref()
        .is_some_and(|relations| relations.split_ascii_whitespace().any(|rel| rel == "next"));
    Ok(ParsedLink { url, is_next })
}

fn parse_parameter_value(value: &str) -> Result<&str, GithubEndpointError> {
    if let Some(quoted) = value.strip_prefix('"') {
        let quoted = quoted
            .strip_suffix('"')
            .ok_or(GithubEndpointError::InvalidResponse)?;
        if quoted.contains('"') || quoted.contains('\\') || quoted.chars().any(char::is_control) {
            return Err(GithubEndpointError::InvalidResponse);
        }
        return Ok(quoted);
    }
    if value.is_empty()
        || value.contains('"')
        || !value.bytes().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, b'-' | b'_' | b'.')
        })
    {
        return Err(GithubEndpointError::InvalidResponse);
    }
    Ok(value)
}

fn validate_page_url(
    url: &Url,
    trusted: &GithubTrustedOrigins,
    expected_path: &str,
    kind: PageKind,
) -> Result<(), GithubEndpointError> {
    if !trusted.trusts_api_url(url)
        || !same_origin(trusted.api_base(), url)
        || url.path() != expected_path
        || url.query().is_none()
    {
        return Err(GithubEndpointError::InvalidResponse);
    }

    let mut page = None;
    let mut per_page = None;
    let mut state = None;
    for (name, value) in url.query_pairs() {
        let slot = match name.as_ref() {
            "page" => &mut page,
            "per_page" => &mut per_page,
            "state" if kind == PageKind::ActiveOrganizations => &mut state,
            _ => return Err(GithubEndpointError::InvalidResponse),
        };
        if slot.replace(value.into_owned()).is_some() {
            return Err(GithubEndpointError::InvalidResponse);
        }
    }
    let valid_page = page
        .as_deref()
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|value| value > 0);
    if !valid_page || per_page.as_deref() != Some("100") {
        return Err(GithubEndpointError::InvalidResponse);
    }
    match kind {
        PageKind::ActiveOrganizations if state.as_deref() != Some("active") => {
            Err(GithubEndpointError::InvalidResponse)
        }
        PageKind::Teams if state.is_some() => Err(GithubEndpointError::InvalidResponse),
        _ => Ok(()),
    }
}
