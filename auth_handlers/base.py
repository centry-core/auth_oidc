import base64
import json
from abc import ABC, abstractmethod

import requests


class BaseAuthHandler(ABC):
    def __init__(self, issuer: str, client_id: str, client_secret: str):
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret

    @property
    @abstractmethod
    def KEY_NAME(self):
        raise NotImplementedError

    @abstractmethod
    def main(self, *args, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def validate(self, *args, **kwargs):
        raise NotImplementedError

    @staticmethod
    def decode_id_token(id_token):
        segments = id_token.split('.')
        if len(segments) != 3:
            raise Exception('Wrong number of segments in token: %s' % id_token)
        b64string = segments[1]
        padded = b64string + '=' * (4 - len(b64string) % 4)
        padded = base64.b64decode(padded)
        return json.loads(padded)

    @staticmethod
    def _delete_refresh_token(refresh_token: str, issuer: str, client_id: str, client_secret: str) -> None:
        url = f'{issuer}/protocol/openid-connect/logout'
        data = {
            "refresh_token": refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        requests.post(
            url,
            data=data,
            params={"delete_offline_token": True},
            headers={"content-type": "application/x-www-form-urlencoded"}
        )

