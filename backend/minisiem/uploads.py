"""Validation and decoding of uploaded log files."""

MAX_LINE_CHARS = 8192


class UploadError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def decode_log_upload(data: bytes, max_line: int = MAX_LINE_CHARS) -> list[str]:
    if b"\x00" in data:
        raise UploadError(415, "File looks binary, expected a text log")
    try:
        text = data.decode("utf-8-sig")  # strips a leading BOM
    except UnicodeDecodeError:
        raise UploadError(415, "File is not UTF-8 text") from None
    lines = text.splitlines()
    for n, line in enumerate(lines, 1):
        if len(line) > max_line:
            raise UploadError(413, f"Line {n} is longer than {max_line} characters")
    return lines
