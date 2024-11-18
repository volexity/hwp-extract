# HWPExtract
# Copyright (C) 2024 Volexity, Inc.

"""Quick extractor for HWP files, allowing for programmatic extraction of subfiles."""

from __future__ import annotations

import json
import logging
import zlib
from typing import TYPE_CHECKING

import olefile

from .encrypt import decrypt_data, genkey, pad

if TYPE_CHECKING:
    from collections.abc import Iterator

HWP5_SIGNATURE = b"HWP Document File" + (b"\x00" * 15)
logger = logging.getLogger(__name__)


class HWPExtractorError(Exception):
    """Custom exception handler for HWPExtractor."""


class HWPExtractorNoPasswordError(Exception):
    """Custom exception handler for HWPExtractor when no password is provided."""


class HWPMetadataObject:
    """Object to represent HWPMetadata components.

    Attributes:
        version: The HWP version.
        ole_names: The OLE names.
        is_compressed: Whether the HWP is compressed or not.
        is_pwd_protected: Whether the HWP is password protected or not.
    """

    def __init__(
        self,
        version: str,
        ole_names: list[str],
        *,
        is_compressed: bool = False,
        is_pwd_protected: bool = False,
    ) -> None:
        """Initialise the HWPMetadata Object.

        Args:
            version: The HWP version.
            ole_names: The OLE names.
            is_compressed: Whether the HWP is compressed or not.
            is_pwd_protected: Whether the HWP is password protected or not.
        """
        self.is_compressed = is_compressed
        self.is_pwd_protected = is_pwd_protected
        self.version = version
        self.ole_names = ole_names

    def __repr__(self) -> str:
        """Print JSON repr of this object."""
        j = self.__dict__
        return json.dumps(j, sort_keys=True, indent=4)


class HWPStreamObject:
    """Object to represent HWPStream components.

    Attributes:
        name: The name of the HWP stream.
        data: The data of the HWP stream.
    """

    def __init__(
        self,
        name: str,
        data: bytes,
    ) -> None:
        """Initialise the HWPStreamObject.

        Args:
            name: The name of the HWP stream.
            data: The data of the HWP stream.
        """
        self.name = name
        self.data = data

    def __repr__(self) -> str:
        """Print JSON repr of this object."""
        j = self.__dict__
        return json.dumps(j, sort_keys=True, indent=4)


class HWPExtractor:
    """Simple HWPExtractor class to assist in extraction of embedded files."""

    def __init__(self, data: bytes, password: str | None = None, *, raise_pw_error: bool = True) -> None:
        """Init a HWPExtractor object.

        Args:
            data: The file data from a .hwp file.
            password: The password for the given .hwp. file.
            raise_pw_error: Whether to raise and exception on incorrect password.

        Raises:
            HWPExtractorException: when data doesn't match known .hwp file format
        """
        self.data = data
        self.enc_info = None
        self.is_valid = self._is_valid()
        self.is_pwd_protected = False
        self.is_compressed = False
        self.version: str = ""
        if self.is_valid is False:
            msg = "Invalid HWP file encountered"
            raise HWPExtractorError(msg)

        if self._read_flags() is False:
            msg = "Error while reading the header flags."
            raise HWPExtractorError(msg)

        if self.is_pwd_protected is True:
            if not password:
                msg = "PasswordProtected HWP file encountered but no password was supplied."
                if raise_pw_error:
                    raise HWPExtractorNoPasswordError(msg)
            self.enc_info = password

    def _is_valid(self) -> bool:
        """Check if `self.data` match known HWP file header structure.

        Returns:
            If the file is a valid HWP file.
        """
        try:
            olestg = olefile.isOleFile(self.data)
        except HWPExtractorError:
            msg = "Not an OLE object."
            raise HWPExtractorError(msg) from None
        if olestg:
            t = olefile.OleFileIO(self.data).get_type("FileHeader")
            if t == 2:  # Stream
                ole = olefile.OleFileIO(self.data).openstream("FileHeader")
            else:
                return False

            streamheader = ole.read()
            self.header = streamheader
            if streamheader[0:32] == HWP5_SIGNATURE:
                return True
        return False

    def _read_flags(self) -> bool:
        """Check the header flags.

        Returns:
            If the flags were read successfully.
        """
        try:
            flags = self.header[36:44]
            value = int.from_bytes(flags, "little")
            if value & 0x02 == 0x02:
                self.is_pwd_protected = True
            if value & 0x01 == 0x01:
                self.is_compressed = True
            version = self.header[32:36]
            self.version = f"{version[0]}.{version[1]}.{version[2]}.{version[3]}"
            return True  # noqa: TRY300
        except HWPExtractorError:
            return False

    def extract_meta(self) -> Iterator[HWPMetadataObject]:
        """Extract metadata from .hwp files.

        Returns:
            An iterator of HWP metadata.
        """
        ole_dir = olefile.OleFileIO(self.data).listdir(storages=False)
        ole_names = []
        for d in ole_dir:
            if len(d) == 2:
                ole_names.append(f"{d[0]}/{d[1]}")
            else:
                ole_names.append(d[0])

        yield HWPMetadataObject(
            is_compressed=self.is_compressed,
            is_pwd_protected=self.is_pwd_protected,
            version=self.version,
            ole_names=ole_names,
        )

    def _decompress(self, data_raw: bytes) -> bytes:
        """Decompress an object (excluding the first 15 bytes)."""
        try:
            decompressed = zlib.decompress(data_raw, -15)  # without gzip header
        except zlib.error:
            # Objects getting this far should be already decrypted -- if we tried to decrypt
            # but it can't be decompressed, the most likely reason for a failure is a bad password
            if self.is_pwd_protected:
                logger.error("Couldn't decrypt stream - probably bad password")
            logger.warning("Cannot inflate the OLE object... The file is maybe corrupted")
            return data_raw
        return decompressed

    def _decrypt(self, data_raw: bytes) -> bytearray:
        if not self.enc_info:
            logger.error("Likely coding error - _decrypt called but self.enc_info is None")
            return bytearray(data_raw)
        pwd = genkey(self.enc_info.encode())
        return decrypt_data(pwd, pad(data_raw))

    def extract_files(self) -> Iterator[HWPStreamObject]:
        """Find embedded objects in .hwp files.

        Returns:
            An iterator containing those objects.
        """
        if self.is_valid is False:
            logger.error("Cannot extract files - header is invalid.")
            return
        oledir = olefile.OleFileIO(self.data).listdir(storages=False)
        for d in oledir:
            obj_name = f"{d[0]}/{d[1]}" if len(d) == 2 else d[0]
            ole = olefile.OleFileIO(self.data).openstream(obj_name)
            data_raw = ole.read()

            if obj_name.startswith(("BinData/", "BodyText/", "ViewText/", "DocInfo/", "Scripts/")):
                # check if it needs to be decrypted
                data_unprotected = self._decrypt(data_raw) if self.is_pwd_protected else data_raw
                # check if it needs to be inflated
                data = self._decompress(data_unprotected) if self.is_compressed else data_unprotected
            else:
                data = data_raw

            yield HWPStreamObject(
                name=obj_name,
                data=data,
            )
