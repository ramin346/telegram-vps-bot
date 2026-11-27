from urllib.parse import quote

import httpx

BASE_URL = "https://api.cherryservers.com/v1"
VIRTUAL_TYPES = {"vps", "vds", "virtual", "arm-vds", "performance-vds", "premium-vds", "storage-vps"}
POWER = {"power-on": "روشن کردن", "power-off": "خاموش کردن", "reboot": "ری‌استارت"}


class APIError(Exception):
    def __init__(self, status=None):
        self.status = status
        super().__init__("Cherry Servers API request failed")


async def request(method, path, token=None, *, params=None, payload=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        async with httpx.AsyncClient(base_url=BASE_URL, timeout=25, follow_redirects=False) as client:
            response = await client.request(method, path, headers=headers, params=params, json=payload)
        response.raise_for_status()
        return response.json() if response.content else None
    except httpx.HTTPStatusError as exc:
        raise APIError(exc.response.status_code) from None
    except (httpx.RequestError, ValueError):
        raise APIError() from None


async def catalog(path, token=None, **filters):
    limit = 50
    offset = 0
    items = []
    seen = set()
    while True:
        page = await request("GET", path, token, params={**filters, "limit": limit, "offset": offset})
        if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
            raise APIError()
        if len(page) < limit:
            return items + page
        signature = tuple((item.get("id"), item.get("slug")) for item in page)
        if signature in seen:
            raise APIError()
        seen.add(signature)
        items.extend(page)
        offset += len(page)


def prices(plan):
    return {
        row["unit"].lower(): row
        for row in plan.get("pricing", [])
        if row.get("unit") in {"Hourly", "Monthly"} and type(row.get("price")) in (int, float)
        and row["price"] >= 0 and isinstance(row.get("currency"), str)
    }


async def plans(token, team_id, region):
    rows = await catalog(f"/teams/{int(team_id)}/plans", token, region=region)
    result = []
    for row in rows:
        if row.get("type") not in VIRTUAL_TYPES or row.get("disabled") or not row.get("slug") or not prices(row):
            continue
        locations = row.get("available_regions")
        if isinstance(locations, list) and not any(
            entry.get("slug") == region and entry.get("stock_qty", 1) != 0 for entry in locations
        ):
            continue
        result.append(row)
    return result


async def images(token, team_id, plan):
    rows = await catalog(f"/teams/{int(team_id)}/plans/{quote(plan, safe='')}/images", token)
    return [
        row for row in rows if row.get("slug") and "windows" not in str(row.get("name", "")).casefold()
        and not row.get("pricing")
    ]


async def create(token, project_id, form):
    data = await request("POST", f"/projects/{int(project_id)}/servers", token, payload=form)
    if not isinstance(data, dict) or type(data.get("id")) is not int:
        raise APIError()
    return data


async def details(token, server_id):
    data = await request("GET", f"/servers/{int(server_id)}", token)
    if not isinstance(data, dict) or data.get("id") != server_id:
        raise APIError()
    return data


async def change_server(token, server_id, operation):
    path = f"/servers/{int(server_id)}"
    if operation == "delete":
        await request("DELETE", path, token)
    elif operation in POWER:
        await request("POST", f"{path}/actions", token, payload={"type": operation})
    else:
        raise ValueError("Invalid Cherry Servers operation")
