import json
from base64 import b64decode
from typing import Tuple

import requests

from ...auth_root.utils.token_manager import set_auth_token

from .base import BaseAuthHandler


class BasicAuthHandler(BaseAuthHandler):
    KEY_NAME = 'basic'

    def validate(self, login: str, password: str, scope: str = "openid groups", **kwargs) -> Tuple[bool, dict]:
        url = f'{self.issuer}/protocol/openid-connect/token'
        data = {
            "username": login,
            "password": password,
            "scope": scope,
            "grant_type": "password",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        resp = json.loads(requests.post(
            url, data=data, headers={"content-type": "application/x-www-form-urlencoded"}
        ).content)
        if resp.get("error"):
            return False, {}
        id_token = self.decode_id_token(resp.get("id_token"))
        auth_data = {
            "username": id_token["preferred_username"],
            "groups": id_token["groups"]
        }
        return True, auth_data

    def main(self, auth_value: str, **kwargs) -> Tuple[str, int]:

        username, password = b64decode(auth_value.strip()).decode().split(":", 1)
        is_ok, auth_data = self.validate(
            login=username, password=password,
            **kwargs
        )
        if is_ok:
            set_auth_token(auth_header=f'{self.KEY_NAME} {auth_value}', value=json.dumps(auth_data))
            return 'OK', 200
        return 'KO', 401
