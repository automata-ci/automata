#!/usr/bin/env python3
"""Tests for the non-executing service-proxy Buildah policy."""

from __future__ import annotations

import importlib.util
import pathlib
import shutil
import sys
import unittest


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[3]
SCRIPT = REPOSITORY_ROOT / "scripts/ci/validate-service-proxy-buildah-containerfile.py"
SPEC = importlib.util.spec_from_file_location(
    "service_proxy_buildah_containerfile", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)


class BuildahContainerfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = REPOSITORY_ROOT / "target/service-proxy-buildah-policy-tests"
        shutil.rmtree(self.scratch, ignore_errors=True)
        self.scratch.mkdir(parents=True)
        self.containerfile = self.scratch / "Containerfile"
        self.reviewed = (
            REPOSITORY_ROOT / "images/service-proxy/Containerfile"
        ).read_bytes()

    def tearDown(self) -> None:
        shutil.rmtree(self.scratch, ignore_errors=True)

    def write(self, contents: bytes) -> pathlib.Path:
        self.containerfile.write_bytes(contents)
        return self.containerfile

    def assert_rejected(self, contents: bytes) -> None:
        with self.assertRaisesRegex(
            SystemExit, "instructions differ from the reviewed non-executing policy"
        ):
            validator.validate(self.write(contents))

    def test_accepts_the_reviewed_containerfile(self) -> None:
        validator.validate(self.write(self.reviewed))

    def test_rejects_run_even_when_the_rest_is_reviewed(self) -> None:
        self.assert_rejected(self.reviewed + b"RUN echo network-capable-step\n")

    def test_rejects_add_even_when_the_rest_is_reviewed(self) -> None:
        self.assert_rejected(self.reviewed + b"ADD https://example.invalid/payload /\n")

    def test_rejects_an_extra_build_stage(self) -> None:
        self.assert_rejected(self.reviewed + b"FROM scratch AS extra\n")

    def test_rejects_copy_from_an_unreviewed_stage(self) -> None:
        self.assert_rejected(
            self.reviewed
            + b"COPY --from=unreviewed /payload /usr/libexec/unreviewed\n"
        )

    def test_rejects_comments_and_parser_directives(self) -> None:
        with self.assertRaisesRegex(SystemExit, "unsupported comment"):
            validator.validate(
                self.write(b"# syntax=example.invalid/frontend\n" + self.reviewed)
            )

    def test_rejects_non_lf_control_bytes(self) -> None:
        with self.assertRaisesRegex(SystemExit, "control bytes"):
            validator.validate(self.write(self.reviewed + b"\x0b"))

    def test_rejects_malformed_continuations(self) -> None:
        with self.assertRaisesRegex(SystemExit, "ends inside a continued instruction"):
            validator.validate(self.write(self.reviewed + b"LABEL unexpected=value \\\n"))


if __name__ == "__main__":
    unittest.main()
