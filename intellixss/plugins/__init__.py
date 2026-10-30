"""Scanner plugins."""

from .header_xss import scan_header_xss
from .redirect_xss import scan_redirect_xss
from .stored_xss import scan_stored_auto, scan_client_stored, scan_server_stored
from .json_xss import scan_json_xss
from .graphql_xss import scan_graphql_xss
from .upload_xss import scan_upload_xss

__all__ = [
    "scan_header_xss",
    "scan_redirect_xss",
    "scan_stored_auto",
    "scan_client_stored",
    "scan_server_stored",
    "scan_json_xss",
    "scan_graphql_xss",
    "scan_upload_xss",
]
