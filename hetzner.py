import httpx

BASE_URL = "https://api.hetzner.cloud/v1"
POWER = {"poweron": "روشن کردن", "shutdown": "خاموش کردن", "reboot": "ری‌استارت"}


class APIError(Exception):
    def __init__(self, status=None):
        self.status = status
        super().__init__("Hetzner API request failed")


async def request(method, path, token, *, params=None, payload=None):
    try:
        async with httpx.AsyncClient(base_url=BASE_URL, timeout=25, follow_redirects=False) as client:
            response = await client.request(
                method, path, headers={"Authorization": f"Bearer {token}"}, params=params, json=payload,
            )
        response.raise_for_status()
        if response.status_code == 204:
            return {}
        data = response.json()
    except httpx.HTTPStatusError as exc:
        raise APIError(exc.response.status_code) from None
    except (httpx.RequestError, ValueError):
        raise APIError() from None
    if not isinstance(data, dict):
        raise APIError()
    return data


async def catalog(token, resource, **filters):
    page = 1
    rows = []
    while page:
        result = await request("GET", f"/{resource}", token, params={**filters, "page": page, "per_page": 50})
        items = result.get(resource)
        if not isinstance(items, list):
            raise APIError()
        rows.extend(items)
        next_page = (result.get("meta") or {}).get("pagination", {}).get("next_page")
        if next_page is not None and (type(next_page) is not int or next_page <= page):
            raise APIError()
        page = next_page
    return rows


def regional_price(plan, location):
    availability = plan.get("locations")
    if availability is not None and not any(
        row.get("name") == location and row.get("available")
        for row in availability
    ):
        return None
    if availability is None and plan.get("deprecated"):
        return None
    for price in plan.get("prices", []):
        if price.get("location") == location:
            hourly = (price.get("price_hourly") or {}).get("gross")
            monthly = (price.get("price_monthly") or {}).get("gross")
            if hourly is not None and monthly is not None:
                return hourly, monthly
    return None


async def server_details(token, instance_id):
    data = await request("GET", f"/servers/{int(instance_id)}", token)
    server = data.get("server")
    if not isinstance(server, dict) or server.get("id") != instance_id:
        raise APIError()
    return server


async def create(token, form):
    data = await request("POST", "/servers", token, payload={
        **form, "start_after_create": True, "public_net": {"enable_ipv4": True, "enable_ipv6": True},
    })
    if not isinstance(data.get("server"), dict) or type(data["server"].get("id")) is not int:
        raise APIError()
    return data


async def change_server(token, instance_id, operation):
    path = f"/servers/{int(instance_id)}"
    if operation == "delete":
        return await request("DELETE", path, token)
    if operation not in POWER:
        raise ValueError("Invalid Hetzner server operation")
    return await request("POST", f"{path}/actions/{operation}", token)


async def reset_root_password(token, instance_id):
    result = await request("POST", f"/servers/{int(instance_id)}/actions/reset_password", token)
    action = result.get("action")
    if not isinstance(action, dict) or type(action.get("id")) is not int:
        raise APIError()
    password = result.get("root_password")
    if action.get("status") != "error" and not (isinstance(password, str) and password):
        raise APIError()
    return action, password


async def action_status(token, action_id):
    result = await request("GET", f"/actions/{int(action_id)}", token)
    action = result.get("action")
    if not isinstance(action, dict) or action.get("id") != action_id:
        raise APIError()
    return action
