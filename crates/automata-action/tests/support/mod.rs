#![allow(dead_code)]

use std::io::Cursor;

use automata_scm::{
    ArchiveFormat, RepositoryId, RepositorySnapshot, ResolvedRevision, RevisionSpec, ScmProviderId,
};
use bytes::Bytes;
use flate2::{Compression, write::GzEncoder};
use tar::{Builder, EntryType, Header};

pub const SHA: &str = "de0fac2e4500dabe0009e67214ff5f5447ce83dd";

#[derive(Clone, Debug)]
pub enum TestEntry<'a> {
    File(&'a str, &'a [u8]),
    Symlink(&'a str, &'a str),
    PaxGlobal(&'a [u8]),
    Fifo(&'a str),
}

pub fn snapshot(entries: &[TestEntry<'_>]) -> RepositorySnapshot {
    snapshot_from_bytes(build_archive(entries))
}

pub fn snapshot_from_bytes(bytes: Bytes) -> RepositorySnapshot {
    RepositorySnapshot::from_bytes(
        ScmProviderId::new("github").unwrap(),
        RepositoryId::new("actions/example").unwrap(),
        RevisionSpec::new("v1").unwrap(),
        ResolvedRevision::new(SHA).unwrap(),
        ArchiveFormat::TarGzip,
        bytes,
    )
}

pub fn build_archive(entries: &[TestEntry<'_>]) -> Bytes {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut archive = Builder::new(&mut encoder);
        for entry in entries {
            match entry {
                TestEntry::File(path, bytes) => append_file(&mut archive, path, bytes),
                TestEntry::Symlink(path, target) => append_link(&mut archive, path, target),
                TestEntry::PaxGlobal(bytes) => append_pax_global(&mut archive, bytes),
                TestEntry::Fifo(path) => append_fifo(&mut archive, path),
            }
        }
        archive.finish().unwrap();
    }
    Bytes::from(encoder.finish().unwrap())
}

fn append_pax_global(archive: &mut Builder<&mut GzEncoder<Vec<u8>>>, bytes: &[u8]) {
    let mut header = Header::new_ustar();
    header.set_mode(0o644);
    header.set_size(u64::try_from(bytes.len()).unwrap());
    header.set_entry_type(EntryType::XGlobalHeader);
    header.set_path("pax_global_header").unwrap();
    header.set_cksum();
    archive
        .append(&header, Cursor::new(bytes))
        .expect("append global PAX header");
}

fn append_file(archive: &mut Builder<&mut GzEncoder<Vec<u8>>>, path: &str, bytes: &[u8]) {
    let mut header = Header::new_gnu();
    header.set_mode(0o644);
    header.set_size(u64::try_from(bytes.len()).unwrap());
    header.set_entry_type(EntryType::Regular);
    header.set_cksum();
    archive
        .append_data(&mut header, path, Cursor::new(bytes))
        .unwrap();
}

fn append_link(archive: &mut Builder<&mut GzEncoder<Vec<u8>>>, path: &str, target: &str) {
    let mut header = Header::new_gnu();
    header.set_mode(0o777);
    header.set_size(0);
    header.set_entry_type(EntryType::Symlink);
    header.set_path(path).unwrap();
    header.set_link_name(target).unwrap();
    header.set_cksum();
    archive.append(&header, std::io::empty()).unwrap();
}

fn append_fifo(archive: &mut Builder<&mut GzEncoder<Vec<u8>>>, path: &str) {
    let mut header = Header::new_gnu();
    header.set_mode(0o644);
    header.set_size(0);
    header.set_entry_type(EntryType::Fifo);
    header.set_path(path).unwrap();
    header.set_cksum();
    archive.append(&header, std::io::empty()).unwrap();
}
