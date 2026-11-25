import asyncio
from urllib.parse import quote

import httpx

BASE_URL = "https://api.linode.com/v4"
POWER = {"boot": "روشن کردن", "shutdown": "خاموش کردن", "reboot": "ری‌استارت"}


class APIError(Exception):
    def __init__(self, status=None):
        self.status = status
        super().__init__("Linode API request failed")


async def request(method, path, token=None, *, params=None, payload=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        async with httpx.AsyncClient(base_url=BASE_URL, timeout=25, follow_redirects=False) as client:
            response = await client.request(method, path, headers=headers, params=params, json=payload)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        raise APIError(exc.response.status_code) from None
    except (httpx.RequestError, ValueError):
        raise APIError() from None


async def catalog(path, token=None):
    page = 1
    rows = []
    while True:
        result = await request("GET", path, token, params={"page": page, "page_size": 100})
        if not isinstance(result, dict) or not isinstance(result.get("data"), list):
            raise APIError()
        rows.extend(row for row in result["data"] if isinstance(row, dict))
        if page >= result.get("pages", 1):
            return rows
        page += 1


async def verify(token):
    await request("GET", "/linode/instances", token, params={"page_size": 25})


async def regions():
    return [row for row in await catalog("/regions") if row.get("status") == "ok" and "Linodes" in row.get("capabilities", [])]


async def region_options(region):
    availability, plans, images = await asyncio.gather(
        request("GET", "/regions/" + quote(region, safe="") + "/availability"),
        catalog("/linode/types"),
        catalog("/images"),
    )
    if not isinstance(availability, list):
        raise APIError()
    available = {row["plan"] for row in availability if row.get("available") and row.get("plan")}
    plans = [row for row in plans if row.get("id") in available and price(row, region)]
    images = [
        row for row in images if row.get("id") and row.get("status") == "available"
        and not row.get("deprecated") and (not row.get("regions") or region in row["regions"])
    ]
    return plans, images


def price(plan, region):
    value = next((row for row in plan.get("region_prices", []) if row.get("id") == region), plan.get("price") or {})
    return value if all(isinstance(value.get(unit), (int, float)) for unit in ("hourly", "monthly")) else None


def instance_path(instance_id):
    return f"/linode/instances/{int(instance_id)}"


async def create(token, payload):
    result = await request("POST", "/linode/instances", token, payload=payload)
    if not isinstance(result, dict) or type(result.get("id")) is not int:
        raise APIError()
    return result


async def details(token, instance_id):
    return await request("GET", instance_path(instance_id), token)


async def set_power(token, instance_id, operation):
    if operation not in POWER:
        raise ValueError("Invalid Linode power operation")
    await request("POST", f"{instance_path(instance_id)}/{operation}", token)
