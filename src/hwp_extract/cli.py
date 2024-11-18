# HWPExtract
# Copyright (C) 2024 Volexity, Inc.


"""Command line interface for hwpextract."""

import argparse
import logging
import sys
import textwrap
from datetime import datetime
from pathlib import Path

try:
    # Python 3.11+
    from datetime import UTC
except ImportError:
    # Fallback for Python 3.10
    from datetime import timezone

    UTC = timezone.utc

from . import __version__
from .hwp import HWPExtractor, HWPExtractorNoPasswordError

logger = logging.getLogger(__name__)
year = datetime.now(tz=UTC).year


def run() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description=textwrap.dedent(
            f"""
            Volexity HWPExtractor | Extract metadata and/or files from HWP files
            Version {__version__}
            https://www.volexity.com
            (C) {year} Volexity, Inc. All rights reserved"""
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("target_file", help="Input file to parse", type=Path, nargs="+")
    parser.add_argument("--debug", help="If enabled, sets log level to debug", action="store_true")
    parser.add_argument("--extract-meta", help="If set, extracts metadata from .hwp file", action="store_true")
    parser.add_argument("--extract-files", help="If set, extracts files from .hwp file", action="store_true")
    parser.add_argument(
        "--output-directory", help="Where should extracted objects be saved to?", default=Path.cwd(), type=Path
    )
    parser.add_argument(
        "--password", help="Password to use to extract files from encrypted " "HWP files", action="store"
    )
    parser.add_argument("--version", action="version", help="print the version of hwp-extract", version=__version__)
    args = parser.parse_args()

    if not args.extract_meta and not args.extract_files:
        sys.exit("Must either attempt to extract metadata or files.")

    if args.debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s %(name)s %(levelname)-8s %(message)s",
            handlers=[logging.StreamHandler()],
        )
        logger.debug("Debug logging enabled.")

    for target_file in args.target_file:
        if not target_file.exists():
            sys.exit("Target file does not exist.")
        with target_file.open("rb") as infile:
            data = infile.read()

        document = HWPExtractor(data=data, password=args.password, raise_pw_error=False)
        # Extract subfile objects from the document
        if args.extract_files:
            if document.is_pwd_protected and not document.enc_info:
                error_message = "PasswordProtected HWP file encountered but no password was supplied."
                raise HWPExtractorNoPasswordError(error_message)
            args.output_directory.mkdir(exist_ok=True)
            bn = target_file.name
            for idx, obj in enumerate(document.extract_files()):
                # Remove any non-file-system friendly chars from object_name
                object_name = "".join([c for c in obj.name if c.isalnum() or c in ["_", "."]])
                target_path = args.output_directory / f"{bn}_{idx}_{object_name}.extracted"
                print(f"Writing extracted file to: {target_path}")
                with target_path.open("wb") as outf:
                    outf.write(obj.data)

        # Extract metadata from the document
        if args.extract_meta:
            for on_meta in document.extract_meta():
                print(on_meta)


# ruff: noqa: T201
