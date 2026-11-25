from urllib.parse import quote

import httpx

BASE_URL = "https://console.kamatera.com/service"


class APIError(Exception):
    def __init__(self, status=None):
        self.status = status
        super().__init__("Kamatera API request failed")


async def request(method, path, *, token=None, payload=None):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        async with httpx.AsyncClient(timeout=25, follow_redirects=False) as client:
            response = await client.request(method, BASE_URL + path, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        raise APIError(exc.response.status_code) from None
    except (httpx.RequestError, ValueError):
        raise APIError() from None


async def authenticate(client_id, secret):
    data = await request("POST", "/authenticate", payload={"clientId": client_id, "secret": secret})
    if not isinstance(data, dict) or not isinstance(data.get("authentication"), str) or not data["authentication"]:
        raise APIError()
    return data["authentication"]


async def options(token, path):
    return await request("GET", "/server/options/" + path, token=token)


async def create_server(token, form):
    result = await request("POST", "/server", token=token, payload={
        **form, "billing": "hourly", "managed": False, "backup": False,
        "power": True, "network_name_0": "wan",
    })
    if isinstance(result, list) and len(result) == 1:
        result = result[0]
    if not isinstance(result, (int, str)) or not str(result).isascii() or not str(result).isdigit():
        raise APIError()
    return str(result)


async def command_status(token, command_id):
    result = await request("GET", "/queue/" + quote(command_id, safe=""), token=token)
    if not isinstance(result, dict) or not isinstance(result.get("status"), str):
        raise APIError()
    return result
