"""Libarary to extract data from .hwp files."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("hwp-extract")
except PackageNotFoundError:
    __version__ = "0.0.0-unknown"

from .hwp import (
    HWPExtractor,
    HWPExtractorError,
    HWPExtractorNoPasswordError,
    HWPMetadataObject,
    HWPStreamObject,
)

__all__ = [
    "HWPExtractor",
    "HWPExtractorError",
    "HWPExtractorNoPasswordError",
    "HWPMetadataObject",
    "HWPStreamObject",
]
