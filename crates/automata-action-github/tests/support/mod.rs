#![allow(dead_code)]

use std::io::Cursor;

use automata_action::{
    ActionBundleLimits, ActionDefinitionDocument, ActionSubpath, inspect_archive,
};
use automata_scm::{
    ArchiveFormat, RepositoryId, RepositorySnapshot, ResolvedRevision, RevisionSpec, ScmProviderId,
};
use bytes::Bytes;
use flate2::{Compression, write::GzEncoder};
use tar::{Builder, Header};

const SHA: &str = "de0fac2e4500dabe0009e67214ff5f5447ce83dd";

pub fn metadata_document(source: &[u8]) -> ActionDefinitionDocument {
    definition("action.yml", source)
}

pub fn dockerfile_document(source: &[u8]) -> ActionDefinitionDocument {
    definition("Dockerfile", source)
}

fn definition(name: &str, source: &[u8]) -> ActionDefinitionDocument {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut archive = Builder::new(&mut encoder);
        let mut header = Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(u64::try_from(source.len()).unwrap());
        header.set_cksum();
        archive
            .append_data(&mut header, format!("root/{name}"), Cursor::new(source))
            .unwrap();
        archive.finish().unwrap();
    }
    let snapshot = RepositorySnapshot::from_bytes(
        ScmProviderId::new("github").unwrap(),
        RepositoryId::new("actions/example").unwrap(),
        RevisionSpec::new(SHA).unwrap(),
        ResolvedRevision::new(SHA).unwrap(),
        ArchiveFormat::TarGzip,
        Bytes::from(encoder.finish().unwrap()),
    );
    inspect_archive(
        &snapshot,
        &ActionSubpath::root(),
        ActionBundleLimits::default(),
    )
    .unwrap()
}

pub fn decode(
    source: &str,
) -> Result<automata_action_github::GithubActionMetadata, automata_action_github::MetadataDecodeError>
{
    use automata_action_github::ActionMetadataDecoder as _;
    automata_action_github::GithubActionMetadataDecoder::default()
        .decode(&metadata_document(source.as_bytes()))
}
