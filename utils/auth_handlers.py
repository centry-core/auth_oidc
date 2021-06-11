import base64
import json
import requests
from base64 import b64decode
from typing import Tuple


from ...auth_root.utils.decorators import require_auth_settings
from ...auth_root.utils.token_manager import set_auth_token


def decode_id_token(id_token):
    segments = id_token.split('.')
    if len(segments) != 3:
        raise Exception('Wrong number of segments in token: %s' % id_token)
    b64string = segments[1]
    padded = b64string + '=' * (4 - len(b64string) % 4)
    padded = base64.b64decode(padded)
    return json.loads(padded)


@require_auth_settings
def _validate_basic_auth(
        login: str, password: str, scope: str = "openid groups", auth_settings: dict = None
) -> Tuple[bool, dict]:
    url = f'{auth_settings["oidc"]["issuer"]}/protocol/openid-connect/token'
    data = {
        "username": login,
        "password": password,
        "scope": scope,
        "grant_type": "password",
        "client_id": auth_settings["oidc"]["registration"]["client_id"],
        "client_secret": auth_settings["oidc"]["registration"]["client_secret"],
    }
    resp = json.loads(requests.post(
        url, data=data, headers={"content-type": "application/x-www-form-urlencoded"}
    ).content)
    if resp.get("error"):
        return False, {}
    id_token = decode_id_token(resp.get("id_token"))
    auth_data = {
        "username": id_token["preferred_username"],
        "groups": id_token["groups"]
    }
    return True, auth_data


@require_auth_settings
def basic(auth_value: str, **kwargs) -> Tuple[str, int]:
    KEY_NAME = 'basic'
    username, password = b64decode(auth_value.strip()).decode().split(":", 1)
    is_ok, auth_data = _validate_basic_auth(username, password, **kwargs)
    if is_ok:
        set_auth_token(auth_header=f'{KEY_NAME} {auth_value}', value=json.dumps(auth_data))
        return 'OK', 200
    return 'KO', 401


@require_auth_settings
def _validate_token_auth(
        refresh_token: str, scope: str = "openid groups", auth_settings: dict = None
) -> Tuple[bool, dict]:
    url = f'{auth_settings["oidc"]["issuer"]}/protocol/openid-connect/token'
    data = {
        "refresh_token": refresh_token,
        "scope": scope,
        "grant_type": "refresh_token",
        "client_id": auth_settings["oidc"]["registration"]["client_id"],
        "client_secret": auth_settings["oidc"]["registration"]["client_secret"],
    }
    resp = json.loads(requests.post(
        url, data=data, headers={"content-type": "application/x-www-form-urlencoded"}
    ).content)
    if resp.get("error"):
        return False, {}
    id_token = decode_id_token(resp.get("id_token"))
    auth_data = {
        "username": id_token["preferred_username"],
        "groups": id_token["groups"]
    }
    return True, auth_data


@require_auth_settings
def bearer(auth_value: str, **kwargs) -> Tuple[str, int]:
    KEY_NAME = 'bearer'
    is_ok, auth_data = _validate_token_auth(auth_value, **kwargs)
    if is_ok:
        set_auth_token(auth_header=f'{KEY_NAME} {auth_value}', value=json.dumps(auth_data))
        return 'OK', 200
    return 'KO', 401


@require_auth_settings
def _delete_refresh_token(refresh_token: str, auth_settings: dict = None) -> None:
    url = f'{auth_settings["oidc"]["issuer"]}/protocol/openid-connect/logout'
    data = {
        "refresh_token": refresh_token,
        "client_id": auth_settings["oidc"]["registration"]["client_id"],
        "client_secret": auth_settings["oidc"]["registration"]["client_secret"],
    }
    requests.post(
        url,
        data=data,
        params={"delete_offline_token": True},
        headers={"content-type": "application/x-www-form-urlencoded"}
    )
