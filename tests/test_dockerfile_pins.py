"""Guard the Dockerfile pins Dependabot is supposed to be updating.

Every Docker ARG in this repo had gone stale because the Dockerfiles pinned
images as `FROM image:${VERSION}` and assumed Dependabot resolved the ARG. It
does not: its parser is a regex over FROM lines whose image and tag groups both
require literal characters, so an interpolated line matches with no version and
is skipped without any error. Nothing failed; the pins just never moved.

These tests re-implement that parser against the real Dockerfiles, so the same
mistake fails loudly instead of silently.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILES = (
    REPO_ROOT / "Dockerfile",
    REPO_ROOT / "Dockerfile.heavy",
    REPO_ROOT / "app_tests" / "Dockerfile",
)
DEPENDABOT_CONFIG = REPO_ROOT / ".github" / "dependabot.yml"

# Transcribed from dependabot-core's docker parser (docker/lib/dependabot/
# shared/shared_file_parser.rb and docker/file_parser.rb). Keeping the literal
# character classes is the point: they are what an interpolated line fails.
DOMAIN_COMPONENT = r"(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])"
DOMAIN = rf"(?:{DOMAIN_COMPONENT}(?:\.{DOMAIN_COMPONENT})+)"
REGISTRY = rf"(?P<registry>{DOMAIN}(?::\d+)?)"
NAME_COMPONENT = r"(?:[a-z\d]+(?:(?:[._]|__|[-]*)[a-z\d]+)*)"
IMAGE = rf"(?P<image>{NAME_COMPONENT}(?:/{NAME_COMPONENT})*)"
TAG = r":(?P<tag>[\w][\w.-]{0,127})"
DIGEST = r"@(?P<digest>[^\s]+)"
NAME = r"\s+AS\s+(?P<name>[\w-]+)"
FROM_LINE = re.compile(
    rf"^FROM\s+(--platform=\S+\s+)?({REGISTRY}/)?{IMAGE}({TAG})?({DIGEST})?({NAME})?",
    re.IGNORECASE | re.VERBOSE,
)

# The one image Dependabot is meant to ignore: Socket's own Trivy build, pinned
# by digest and moved only by the trivy-dist release process.
UNTRACKED_FROM = "FROM ${TRIVY_IMAGE}"


def _from_lines(dockerfile: Path) -> list[str]:
    return [
        line
        for line in dockerfile.read_text().splitlines()
        if line.startswith("FROM ") and not line.startswith(UNTRACKED_FROM)
    ]


def _parsed_images(dockerfile: Path) -> dict[str, str]:
    """{image: tag} for every FROM line dependabot-core would actually parse."""
    images: dict[str, str] = {}
    for line in _from_lines(dockerfile):
        match = FROM_LINE.match(line)
        if not match or not match.group("tag"):
            continue
        registry, image = match.group("registry"), match.group("image")
        name = image if registry in (None, "docker.io") else f"{registry}/{image}"
        images[name] = match.group("tag")
    return images


@pytest.mark.parametrize("dockerfile", DOCKERFILES, ids=lambda p: p.name)
def test_every_from_line_is_pinned_where_dependabot_can_read_it(dockerfile: Path) -> None:
    for line in _from_lines(dockerfile):
        match = FROM_LINE.match(line)
        assert match and match.group("tag"), (
            f"{dockerfile.relative_to(REPO_ROOT)}: Dependabot cannot read a version out of "
            f"{line!r}. Pin the tag inline (FROM image:1.2.3); it does not expand ARGs."
        )


@pytest.mark.parametrize("dockerfile", DOCKERFILES, ids=lambda p: p.name)
def test_trufflehog_label_arg_matches_its_from_tag(dockerfile: Path) -> None:
    """The one pin stated twice, because a LABEL cannot read a FROM tag back."""
    content = dockerfile.read_text()
    arg = re.search(r"^ARG TRUFFLEHOG_VERSION=(?P<version>\S+)$", content, re.MULTILINE)
    if not arg:
        pytest.skip(f"{dockerfile.name} has no trufflehog label to feed")
    assert _parsed_images(dockerfile)["trufflesecurity/trufflehog"] == arg.group("version")


def test_dependabot_allows_every_trackable_image() -> None:
    """An `allow:` list silently drops images it does not name — catch that."""
    config = yaml.safe_load(DEPENDABOT_CONFIG.read_text())
    allowed: dict[str, set[str]] = {
        update["directory"]: {entry["dependency-name"] for entry in update.get("allow", [])}
        for update in config["updates"]
        if update["package-ecosystem"] == "docker"
    }

    for dockerfile in DOCKERFILES:
        directory = "/" if dockerfile.parent == REPO_ROOT else f"/{dockerfile.parent.name}"
        missing = set(_parsed_images(dockerfile)) - allowed[directory]
        assert not missing, (
            f"{dockerfile.relative_to(REPO_ROOT)} pins {sorted(missing)}, which the "
            f"dependabot.yml entry for {directory} does not allow, so they will never "
            f"be updated."
        )
