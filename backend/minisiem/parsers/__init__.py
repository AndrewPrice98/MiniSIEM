"""Log parsers. Each turns one raw line into an Event, or None if unparseable."""

from .base import ParseContext, Parser
from .linux_auth import LinuxAuthParser
from .web_access import WebAccessParser

PARSERS: dict[str, Parser] = {
    LinuxAuthParser.source_type: LinuxAuthParser(),
    WebAccessParser.source_type: WebAccessParser(),
}


def get_parser(source_type: str) -> Parser:
    try:
        return PARSERS[source_type]
    except KeyError:
        raise ValueError(
            f"Unknown source type {source_type!r}. Choose one of: {', '.join(sorted(PARSERS))}"
        ) from None


__all__ = ["PARSERS", "ParseContext", "Parser", "get_parser"]
