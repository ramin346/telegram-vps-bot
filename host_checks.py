import asyncio
from ipaddress import ip_address
import math
import re
import socket
from urllib.parse import quote

import httpx

CHECK_HOST = "https://check-host.net"
IP_INFO = "https://ipwho.is"
HEADERS = {"Accept": "application/json"}


class CheckError(Exception):
    pass


def parse_host(value):
    host = value.strip()
    try:
        address = ip_address(host)
    except ValueError:
        try:
            host = host.removesuffix(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise ValueError from None
        labels = host.split(".")
        if len(host) > 253 or len(labels) < 2 or not any(char.isalpha() for char in labels[-1]):
            raise ValueError
        if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
            raise ValueError
        return host
    if not address.is_global or address.is_multicast or "%" in host:
        raise ValueError
    return str(address)


async def get_json(client, url, *, params=None):
    try:
        response = await client.get(url, params=params, headers=HEADERS)
        response.raise_for_status()
        result = response.json()
    except (httpx.HTTPError, ValueError):
        raise CheckError() from None
    if not isinstance(result, dict):
        raise CheckError()
    return result


def iran_node(location):
    return isinstance(location, list) and len(location) >= 3 and location[0] == "ir"


async def ping_iran(host):
    async with httpx.AsyncClient(timeout=6, follow_redirects=False) as client:
        directory = (await get_json(client, CHECK_HOST + "/nodes/hosts")).get("nodes")
        if not isinstance(directory, dict):
            raise CheckError()
        iran = {
            node for node, metadata in directory.items()
            if isinstance(metadata, dict) and iran_node(metadata.get("location"))
        }
        if not iran:
            return {}, {}
        params = [("host", host), *(("node", node) for node in sorted(iran))]
        started = await get_json(client, CHECK_HOST + "/check-ping", params=params)
        request_id = started.get("request_id")
        nodes = started.get("nodes")
        if started.get("ok") != 1 or not isinstance(request_id, str) or not re.fullmatch(r"[a-zA-Z0-9_-]+", request_id):
            raise CheckError()
        if not isinstance(nodes, dict):
            raise CheckError()
        selected = {node: location[2] for node, location in nodes.items() if node in iran and iran_node(location)}
        if not selected:
            return {}, {}
        results = {}
        for attempt in range(6):
            if attempt:
                await asyncio.sleep(2)
            results = await get_json(client, CHECK_HOST + "/check-result/" + request_id)
            if all(results.get(node) is not None for node in selected):
                break
        return selected, {node: results.get(node) for node in selected}


def ping_summary(result):
    if result is None:
        return "هنوز پاسخ نرسیده"
    if not isinstance(result, list) or not result or not isinstance(result[0], list):
        return "نتیجه در دسترس نیست"
    packets = result[0]
    if packets == [None]:
        return "نام دامنه resolve نشد"
    if not packets:
        return "نتیجه در دسترس نیست"
    values = [
        item[1] * 1000 for item in packets if isinstance(item, list) and len(item) >= 2 and item[0] == "OK"
        and type(item[1]) in (int, float) and math.isfinite(item[1]) and item[1] >= 0
    ]
    if not values:
        return f"بدون پاسخ (۰ از {len(packets)})"
    return f"{len(values)} از {len(packets)} پاسخ · میانگین {sum(values) / len(values):.1f} ms"


async def public_ips(host):
    try:
        addresses = [ip_address(host)]
    except ValueError:
        try:
            records = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout=6,
            )
        except (OSError, asyncio.TimeoutError):
            raise CheckError() from None
        addresses = sorted({ip_address(row[4][0]) for row in records}, key=lambda ip: (ip.version, int(ip)))
    return [str(ip) for ip in addresses if ip.is_global and not ip.is_multicast]


async def ip_metadata(client, ip):
    try:
        data = await get_json(client, IP_INFO + "/" + quote(ip, safe=":"))
    except CheckError:
        return {}
    return data if data.get("success") is True else {}


async def ip_information(host):
    public = (await public_ips(host))[:3]
    async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
        data = await asyncio.gather(*(ip_metadata(client, ip) for ip in public))
    return list(zip(public, data))
