"""
Parser for Postman Collection v2.x (Schema exporter format) JSON exports.

Flattens nested folders/requests into a flat list of `PostmanEndpoint`
objects, substituting `{{variable}}` placeholders using the collection's own
`variable` array merged with an optional Postman Environment export.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

from ..models.postman_result import PostmanAuthInfo, PostmanEndpoint

_VAR_PATTERN = re.compile(r"\{\{([^{}]+)\}\}")
_PATH_PARAM_PATTERN = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)")


def load_collection(path: str | Path) -> dict[str, Any]:
    """Load and JSON-parse a Postman collection export file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if "info" not in data or "item" not in data:
        raise ValueError(
            "File does not look like a Postman Collection v2.x export "
            "(missing 'info' or 'item')."
        )
    return data


def load_environment(path: str | Path | None) -> dict[str, str]:
    """Load a Postman Environment export file into a flat {key: value} dict."""
    if not path:
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    values = data.get("values", [])
    return {
        v["key"]: str(v.get("value", ""))
        for v in values
        if v.get("enabled", True) and v.get("key")
    }


def _collect_variables(
    collection: dict[str, Any], environment: dict[str, str] | None
) -> dict[str, str]:
    variables: dict[str, str] = {}
    for var in collection.get("variable", []) or []:
        key = var.get("key")
        if key:
            variables[key] = str(var.get("value", ""))
    if environment:
        variables.update(environment)
    return variables


def _substitute(text: str, variables: dict[str, str]) -> tuple[str, list[str]]:
    """Replace {{var}} with resolved values. Returns (resolved_text, unresolved_var_names)."""
    if not text:
        return text, []
    unresolved: list[str] = []

    def _replace(match: re.Match) -> str:
        name = match.group(1).strip()
        if name in variables:
            return variables[name]
        unresolved.append(name)
        return match.group(0)

    return _VAR_PATTERN.sub(_replace, text), unresolved


def _extract_url(url_field: Any) -> str:
    if isinstance(url_field, str):
        return url_field
    if isinstance(url_field, dict):
        raw = url_field.get("raw")
        if raw:
            return raw
        host = ".".join(str(h) for h in url_field.get("host", []) or [])
        path = "/".join(str(p) for p in url_field.get("path", []) or [])
        return f"{host}/{path}".strip("/")
    return ""


def _extract_headers(headers_field: Any) -> dict[str, str]:
    headers: dict[str, str] = {}
    if isinstance(headers_field, list):
        for h in headers_field:
            if isinstance(h, dict) and not h.get("disabled", False):
                key = h.get("key")
                if key:
                    headers[key] = str(h.get("value", ""))
    return headers


def _extract_query(url_field: Any) -> dict[str, str]:
    query: dict[str, str] = {}
    if isinstance(url_field, dict):
        for q in url_field.get("query", []) or []:
            if isinstance(q, dict) and not q.get("disabled", False):
                key = q.get("key")
                if key:
                    query[key] = str(q.get("value", ""))
    return query


def _extract_body(request: dict[str, Any]) -> tuple[str, str]:
    body = request.get("body") or {}
    mode = body.get("mode", "")
    if mode == "raw":
        return str(body.get("raw", "")), mode
    if mode == "urlencoded":
        parts = body.get("urlencoded", []) or []
        pairs = [f"{p.get('key')}={p.get('value', '')}" for p in parts if not p.get("disabled", False)]
        return "&".join(pairs), mode
    if mode == "formdata":
        parts = body.get("formdata", []) or []
        pairs = [f"{p.get('key')}={p.get('value', '')}" for p in parts if not p.get("disabled", False)]
        return "&".join(pairs), mode
    if mode == "graphql":
        gql = body.get("graphql", {}) or {}
        return json.dumps(gql), mode
    return "", mode or "none"


def _extract_auth(auth_field: Any) -> PostmanAuthInfo:
    if not isinstance(auth_field, dict):
        return PostmanAuthInfo(type="noauth")
    return PostmanAuthInfo(type=auth_field.get("type", "noauth"), raw=auth_field)


def _extract_description(desc_field: Any) -> str:
    if isinstance(desc_field, str):
        return desc_field
    if isinstance(desc_field, dict):
        return str(desc_field.get("content", ""))
    return ""


def flatten_items(
    items: list[dict[str, Any]],
    variables: dict[str, str],
    folder_path: str = "",
) -> list[PostmanEndpoint]:
    """Recursively flatten Postman collection items into PostmanEndpoint objects."""
    endpoints: list[PostmanEndpoint] = []
    for item in items or []:
        name = item.get("name", "")
        if "item" in item:  # folder
            sub_path = f"{folder_path} > {name}" if folder_path else name
            endpoints.extend(flatten_items(item["item"], variables, sub_path))
            continue

        request = item.get("request")
        if not isinstance(request, dict):
            continue

        raw_url = _extract_url(request.get("url"))
        resolved_url, unresolved_url = _substitute(raw_url, variables)

        raw_headers = _extract_headers(request.get("header"))
        headers: dict[str, str] = {}
        unresolved_headers: list[str] = []
        for k, v in raw_headers.items():
            resolved_v, unres = _substitute(v, variables)
            headers[k] = resolved_v
            unresolved_headers.extend(unres)

        query_params = _extract_query(request.get("url"))

        raw_body, body_mode = _extract_body(request)
        resolved_body, unresolved_body = _substitute(raw_body, variables)

        path_params = _PATH_PARAM_PATTERN.findall(raw_url)
        unresolved = list(dict.fromkeys(unresolved_url + unresolved_headers + unresolved_body))

        endpoints.append(PostmanEndpoint(
            name=name,
            folder_path=folder_path,
            method=(request.get("method") or "GET").upper(),
            url=resolved_url,
            raw_url=raw_url,
            headers=headers,
            query_params=query_params,
            path_params=path_params,
            body=resolved_body,
            body_mode=body_mode,
            auth=_extract_auth(request.get("auth")),
            description=_extract_description(request.get("description")),
            unresolved_variables=unresolved,
        ))
    return endpoints


def apply_target_override(endpoint: PostmanEndpoint, target_override: str) -> PostmanEndpoint:
    """Replace scheme+host of endpoint.url with target_override, keeping path/query intact."""
    if not target_override.startswith(("http://", "https://")):
        target_override = "https://" + target_override
    override_parsed = urlparse(target_override)

    url = endpoint.url
    if not url:
        return endpoint
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    endpoint.url = urlunparse(parsed._replace(scheme=override_parsed.scheme, netloc=override_parsed.netloc))
    return endpoint


def parse_collection(
    collection_path: str | Path,
    environment_path: str | Path | None = None,
    target_override: str | None = None,
) -> tuple[str, list[PostmanEndpoint]]:
    """
    Parse a Postman collection file into a flat list of PostmanEndpoint.

    Args:
        collection_path:  Path to the Postman collection JSON export.
        environment_path: Optional path to a Postman environment JSON export.
        target_override:  If set, replaces the scheme+host of every resolved URL
                           with this base URL (keeps path/query intact). Useful to
                           point a collection captured against one host at a
                           different target for testing.

    Returns:
        (collection_name, endpoints)
    """
    collection = load_collection(collection_path)
    environment = load_environment(environment_path)
    variables = _collect_variables(collection, environment)

    endpoints = flatten_items(collection.get("item", []), variables)

    if target_override:
        endpoints = [apply_target_override(ep, target_override) for ep in endpoints]

    name = collection.get("info", {}).get("name", "Postman Collection")
    return name, endpoints
