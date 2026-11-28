from ipaddress import ip_address
import re
from urllib.parse import quote

import httpx

BASE_URL = "https://api.cloudflare.com/client/v4"
HOST_TYPES = ("A", "AAAA", "CNAME", "NS")
TTL_VALUES = (1, 60, 300, 600, 1800, 3600)


class APIError(Exception):
    def __init__(self, status=None, codes=()):
        self.status = status
        self.codes = codes
        super().__init__("Cloudflare API request failed")


async def request(method, path, token, *, params=None, payload=None):
    try:
        async with httpx.AsyncClient(base_url=BASE_URL, timeout=25, follow_redirects=False) as client:
            response = await client.request(
                method, path, headers={"Authorization": f"Bearer {token}"}, params=params, json=payload,
            )
    except httpx.RequestError:
        raise APIError() from None
    try:
        data = response.json()
    except ValueError:
        raise APIError(response.status_code) from None
    if not isinstance(data, dict):
        raise APIError(response.status_code)
    if not response.is_success or data.get("success") is not True:
        codes = tuple(e["code"] for e in data.get("errors", []) if isinstance(e, dict) and type(e.get("code")) is int)
        raise APIError(response.status_code, codes)
    return data


async def collection(path, token, per_page, **filters):
    page = 1
    rows = []
    while True:
        result = await request("GET", path, token, params={"page": page, "per_page": per_page, **filters})
        items = result.get("result")
        if not isinstance(items, list):
            raise APIError()
        rows.extend(items)
        total = (result.get("result_info") or {}).get("total_pages")
        if not items or (page >= total if type(total) is int else len(items) < per_page):
            return rows
        page += 1


def records_path(zone_id, record_id=None):
    path = f"/zones/{quote(zone_id, safe='')}/dns_records"
    return path if record_id is None else path + "/" + quote(record_id, safe="")


async def zones(token):
    return await collection("/zones", token, 50)


async def records(token, zone_id, search=""):
    filters = {"name.contains": search} if search else {}
    return await collection(records_path(zone_id), token, 100, **filters)


async def record(token, zone_id, record_id):
    result = (await request("GET", records_path(zone_id, record_id), token)).get("result")
    if not isinstance(result, dict) or result.get("id") != record_id:
        raise APIError()
    return result


def domain(value, *, wildcard=False):
    labels = value.rstrip(".").lower().split(".")
    output = []
    for index, label in enumerate(labels):
        if wildcard and index == 0 and label == "*":
            output.append(label)
            continue
        encoded = label.encode("idna").decode("ascii")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", encoded):
            raise ValueError()
        output.append(encoded)
    name = ".".join(output)
    if len(name) > 253:
        raise ValueError()
    return name


def is_subdomain(name, zone):
    return name.rstrip(".").casefold().endswith("." + zone.casefold())


def subdomain(value, zone):
    name = domain(value, wildcard=True)
    if name == zone or value == "@":
        raise ValueError()
    if not is_subdomain(name, zone):
        if value.endswith("."):
            raise ValueError()
        name = domain(f"{name}.{zone}", wildcard=True)
    return name


def destination(value, kind):
    if kind in {"CNAME", "NS"}:
        name = domain(value)
        if "." not in name or (kind == "NS" and name.rsplit(".", 1)[1].isdigit()):
            raise ValueError()
        return name
    address = ip_address(value)
    if address.version != (4 if kind == "A" else 6) or "%" in value:
        raise ValueError()
    return str(address)
