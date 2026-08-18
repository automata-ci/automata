use automata_ci_core::Sha256Digest;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use xmlparser::{ElementEnd, Token, Tokenizer};

const MAXIMUM_DECODED_BLOCK_ID_BYTES: usize = 64;
const MAXIMUM_ENCODED_BLOCK_ID_BYTES: usize = 128;
const BLOCK_LIST_DIGEST_DOMAIN: &[u8] = b"automata-results-block-list-v1\0";

/// Azure Block Blob request rejected at the compatibility boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum AzureProtocolError {
    #[error("block identifier is invalid")]
    InvalidBlockId,
    #[error("block-list XML is invalid")]
    InvalidBlockList,
    #[error("block-list count exceeds its configured ceiling")]
    TooManyBlocks,
}

pub(crate) fn validate_block_id(value: &str) -> Result<String, AzureProtocolError> {
    if value.is_empty() || value.len() > MAXIMUM_ENCODED_BLOCK_ID_BYTES {
        return Err(AzureProtocolError::InvalidBlockId);
    }
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| AzureProtocolError::InvalidBlockId)?;
    if decoded.is_empty()
        || decoded.len() > MAXIMUM_DECODED_BLOCK_ID_BYTES
        || STANDARD.encode(&decoded) != value
    {
        return Err(AzureProtocolError::InvalidBlockId);
    }
    Ok(value.to_owned())
}

pub(crate) fn parse_block_list(
    bytes: &[u8],
    maximum_blocks: usize,
) -> Result<Vec<String>, AzureProtocolError> {
    let document = std::str::from_utf8(bytes).map_err(|_| AzureProtocolError::InvalidBlockList)?;
    let mut stack: Vec<&str> = Vec::with_capacity(2);
    let mut pending_element = None;
    let mut current_block = None;
    let mut blocks = Vec::new();
    let mut root_seen = false;
    let mut root_closed = false;

    for token in Tokenizer::from(document) {
        let token = token.map_err(|_| AzureProtocolError::InvalidBlockList)?;
        match token {
            Token::Declaration {
                version, encoding, ..
            } if !root_seen
                && version.as_str() == "1.0"
                && encoding.is_none_or(|value| value.as_str().eq_ignore_ascii_case("UTF-8")) => {}
            Token::ElementStart { prefix, local, .. } => {
                if !prefix.as_str().is_empty() || pending_element.is_some() || root_closed {
                    return Err(AzureProtocolError::InvalidBlockList);
                }
                let name = local.as_str();
                match stack.as_slice() {
                    [] if !root_seen && name == "BlockList" => {
                        root_seen = true;
                    }
                    ["BlockList"] if name == "Latest" => {}
                    _ => return Err(AzureProtocolError::InvalidBlockList),
                }
                pending_element = Some(name);
            }
            Token::ElementEnd {
                end: ElementEnd::Open,
                ..
            } => {
                let name = pending_element
                    .take()
                    .ok_or(AzureProtocolError::InvalidBlockList)?;
                stack.push(name);
                if name == "Latest" {
                    current_block = None;
                }
            }
            Token::ElementEnd {
                end: ElementEnd::Close(prefix, local),
                ..
            } => {
                if !prefix.as_str().is_empty() || pending_element.is_some() {
                    return Err(AzureProtocolError::InvalidBlockList);
                }
                let open = stack.pop().ok_or(AzureProtocolError::InvalidBlockList)?;
                if open != local.as_str() {
                    return Err(AzureProtocolError::InvalidBlockList);
                }
                match open {
                    "Latest" => {
                        let block = current_block
                            .take()
                            .ok_or(AzureProtocolError::InvalidBlockList)?;
                        blocks.push(validate_block_id(block)?);
                        if blocks.len() > maximum_blocks {
                            return Err(AzureProtocolError::TooManyBlocks);
                        }
                    }
                    "BlockList" => root_closed = true,
                    _ => return Err(AzureProtocolError::InvalidBlockList),
                }
            }
            Token::Text { text } => match stack.as_slice() {
                ["BlockList"] if text.as_str().trim().is_empty() => {}
                ["BlockList", "Latest"] if current_block.is_none() => {
                    current_block = Some(text.as_str());
                }
                _ => return Err(AzureProtocolError::InvalidBlockList),
            },
            Token::Attribute { .. }
            | Token::ElementEnd {
                end: ElementEnd::Empty,
                ..
            }
            | Token::ProcessingInstruction { .. }
            | Token::Comment { .. }
            | Token::DtdStart { .. }
            | Token::EmptyDtd { .. }
            | Token::EntityDeclaration { .. }
            | Token::DtdEnd { .. }
            | Token::Cdata { .. }
            | Token::Declaration { .. } => {
                return Err(AzureProtocolError::InvalidBlockList);
            }
        }
    }
    if !root_seen || !root_closed || !stack.is_empty() || pending_element.is_some() {
        return Err(AzureProtocolError::InvalidBlockList);
    }
    Ok(blocks)
}

pub(crate) fn block_list_digest(block_ids: &[String]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(BLOCK_LIST_DIGEST_DOMAIN);
    hasher.update(
        u64::try_from(block_ids.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for block_id in block_ids {
        hasher.update(
            u64::try_from(block_id.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(block_id.as_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}
