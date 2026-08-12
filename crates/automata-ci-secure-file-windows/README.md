# automata-ci-secure-file-windows

`automata-ci-secure-file-windows` is Automata's reviewed Windows adapter for
owner-private bounded file inputs. It accepts only unambiguous absolute drive
paths, walks every ancestor without following reparse points while pinning
each verified directory handle against replacement, opens the file itself
without following reparse points, proves the owner and every DACL entry from
the opened handle, and bounds the read before and after it happens. Errors are
sanitized and never reflect the path or file content.

The crate forbids `unsafe` and confines Windows security APIs to the pinned
reviewed wrappers selected in the durable Windows control-plane design:
`windows-permissions` for SID, DACL, and security-descriptor evidence and
`winapi-util` for by-handle file information. Platforms other than Windows
compile an empty crate; the portable caller keeps its typed unavailable error.

- [Durable Windows control-plane design](https://github.com/automata-ci/automata/blob/main/docs/windows-control-plane-design-proposal.md)
- [Windows release roadmap](https://github.com/automata-ci/automata/blob/main/docs/windows-release-roadmap.md)
- [Issues and support](https://github.com/automata-ci/automata/issues)
