from pathlib import Path

import pytest

from hwp_extract import HWPExtractor


def test_extract_example() -> None:
    path = Path(__file__).parent / "files" / "example.hwp"
    with path.open("rb") as f:
        data = f.read()

    document = HWPExtractor(data=data)
    if document.is_pwd_protected:
        pytest.fail("example.hwp should not be password protected")

    files = list(document.extract_files())
    assert len(files) == 12
