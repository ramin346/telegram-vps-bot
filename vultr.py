import asyncio
from urllib.parse import quote

import httpx

BASE_URL = "https://api.vultr.com/v2"
POWER = {"start": "روشن کردن", "halt": "خاموش کردن", "reboot": "ری‌استارت"}
COMPUTE_TYPES = {"vc2", "vhf", "vhp"}
NON_LINUX = {"iso", "snapshot", "backup", "application", "marketplace_app", "windows", "freebsd", "openbsd"}


class APIError(Exception):
    def __init__(self, status=None):
        self.status = status
        super().__init__("Vultr API request failed")


async def request(method, path, token=None, *, params=None, payload=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        async with httpx.AsyncClient(base_url=BASE_URL, timeout=25, follow_redirects=False) as client:
            response = await client.request(method, path, headers=headers, params=params, json=payload)
        response.raise_for_status()
        if not response.content:
            return {}
        data = response.json()
    except httpx.HTTPStatusError as exc:
        raise APIError(exc.response.status_code) from None
    except (httpx.RequestError, ValueError):
        raise APIError() from None
    if not isinstance(data, dict):
        raise APIError()
    return data


async def catalog(path, key, token=None):
    params = {"per_page": 100}
    rows = []
    cursors = set()
    while True:
        result = await request("GET", path, token, params=params)
        items = result.get(key)
        if not isinstance(items, list):
            raise APIError()
        rows.extend(items)
        cursor = ((result.get("meta") or {}).get("links") or {}).get("next")
        if not cursor:
            return rows
        if not isinstance(cursor, str) or cursor in cursors:
            raise APIError()
        cursors.add(cursor)
        params = {**params, "cursor": cursor}


def monthly_price(plan, region):
    local = (plan.get("location_cost") or {}).get(region) or {}
    value = local.get("monthly_cost", plan.get("monthly_cost"))
    return value if type(value) in (int, float) and value >= 0 else None


async def region_options(region):
    availability, plans, images = await asyncio.gather(
        request("GET", f"/regions/{quote(region, safe='')}/availability"),
        catalog("/plans", "plans"),
        catalog("/os", "os"),
    )
    available = availability.get("available_plans")
    if not isinstance(available, list):
        raise APIError()
    available = set(available)
    choices = [
        plan for plan in plans if plan.get("id") in available and plan.get("type") in COMPUTE_TYPES
        and plan.get("deploy_ondemand", True) and monthly_price(plan, region) is not None
        and str(plan.get("cpu_vendor", "")).lower() in {"intel", "amd"}
    ]
    system_images = [
        image for image in images if type(image.get("id")) is int and image.get("family")
        and image.get("family") not in NON_LINUX and image.get("arch") == "x64"
    ]
    return sorted(choices, key=lambda plan: (monthly_price(plan, region), plan["id"])), system_images


def instance_path(instance_id):
    return "/instances/" + quote(instance_id, safe="")


async def details(token, instance_id):
    result = (await request("GET", instance_path(instance_id), token)).get("instance")
    if not isinstance(result, dict) or result.get("id") != instance_id:
        raise APIError()
    return result


async def create(token, form):
    ipv6_only = form["plan"].endswith("-v6")
    payload = {**form, "backups": "disabled", "activation_email": False,
               "enable_ipv6": ipv6_only, "disable_public_ipv4": ipv6_only}
    result = (await request("POST", "/instances", token, payload=payload)).get("instance")
    if not isinstance(result, dict) or not isinstance(result.get("id"), str) or not result["id"]:
        raise APIError()
    return result


async def change_instance(token, instance_id, operation):
    path = instance_path(instance_id)
    if operation == "delete":
        await request("DELETE", path, token)
    elif operation in POWER:
        await request("POST", f"{path}/{operation}", token)
    else:
        raise ValueError("Invalid Vultr operation")
