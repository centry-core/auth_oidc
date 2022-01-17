#   Copyright 2021 getcarrier.io
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Module """
import json
from typing import Optional

import flask  # pylint: disable=E0401
import jinja2  # pylint: disable=E0401
from flask import redirect, request, session
from oic import rndstr
from oic.oauth2 import GrantError
from oic.oic.message import AuthorizationResponse

from pylon.core.tools import log  # pylint: disable=E0611,E0401
from pylon.core.tools import module  # pylint: disable=E0611,E0401

from .auth_handlers.basic import BasicAuthHandler
from .auth_handlers.bearer import BearerAuthHandler
from .utils.oidc_client import create_oidc_client, clear_session


class Module(module.ModuleModel):
    """ Pylon module """

    def __init__(self, settings, root_path, context):
        self.settings = settings
        self.root_path = root_path
        self.context = context

        self.rpc_prefix = None
        self.root_settings = None

    def init(self):
        """ Init module """
        log.info('Initializing module auth_oidc')
        _, _, root_module = self.context.module_manager.get_module("auth_root")
        self.root_settings = root_module.settings
        self.rpc_prefix = self.root_settings['rpc_manager']['prefix']['root']

        auth_handlers = (BasicAuthHandler, BearerAuthHandler)
        for auth_handler in auth_handlers:
            handler = auth_handler(
                issuer=self.settings['issuer'],
                client_id=self.settings['registration']['client_id'],
                client_secret=self.settings['registration']['client_secret']
            )
            self.context.rpc_manager.register_function(
                func=handler.main,
                name=f'{self.rpc_prefix}{handler.KEY_NAME}'
            )
            log.debug(f'Auth handler {str(auth_handler)} registered in rpc_manager under name {self.rpc_prefix}{handler.KEY_NAME}')

        bp = flask.Blueprint(
            'auth_oidc', 'plugins.auth_oidc',
            root_path=self.root_path,
            url_prefix=f'{self.context.url_prefix}/{self.settings["endpoints"]["root"]}/'
        )
        bp.add_url_rule('/login', 'login', self.login)
        bp.add_url_rule('/token', 'token', self.token)
        bp.add_url_rule('/token/redirect', 'new_token', self.new_token)
        bp.add_url_rule('/logout', 'logout', self.logout)
        bp.add_url_rule('/callback', 'callback', self.callback)

        # Register in app
        self.context.app.register_blueprint(bp)

    def deinit(self):  # pylint: disable=R0201
        """ De-init module """
        log.info('De-initializing module auth_oidc')

    def login(self):
        return redirect(self._auth_request(scope="openid groups"), 302)

    def token(self):
        return redirect(self._do_logout(to="/forward-auth/oidc/token/redirect"))

    def new_token(self):
        return redirect(self._auth_request(scope="openid offline_access groups"))

    def logout(self):
        logout_url = self._do_logout()
        return redirect(logout_url, 302)

    def get_client(self):
        return create_oidc_client(
            self.settings["issuer"],
            self.settings["registration"]
        )

    def _auth_request(self, scope="openid", redirect_uri="/callback", response_type="code"):
        session["state"] = rndstr()
        session["nonce"] = rndstr()
        client = self.get_client()
        auth_req = client.construct_AuthorizationRequest(request_args={
            "client_id": client.client_id,
            "response_type": response_type,
            "scope": scope,
            "state": session["state"],
            "nonce": session["nonce"],
            "redirect_uri": f"{client.registration_response['redirect_uris'][0]}{redirect_uri}",
        })
        login_url = auth_req.request(client.authorization_endpoint)
        return login_url

    def callback(self):
        client = self.get_client()
        auth_resp = client.parse_response(
            AuthorizationResponse,
            info=json.dumps(request.args.to_dict()),
            sformat="json"
        )
        if "state" not in session or auth_resp["state"] != session["state"]:
            return redirect(self.root_settings["endpoints"]["access_denied"], 302)
        access_token_resp = client.do_access_token_request(
            state=auth_resp["state"],
            request_args={"code": auth_resp["code"]},
            authn_method="client_secret_basic"
        )
        session_state = session.pop("state")
        session_nonce = session.pop("nonce")
        id_token = dict(access_token_resp["id_token"])
        if access_token_resp["refresh_expires_in"] == 0:
            session["X-Forwarded-Uri"] = f"/token?id={access_token_resp['refresh_token']}"
        redirect_to = self.redirect_url
        clear_session(session)
        session["name"] = self.context.app.session_cookie_name
        session["auth_cookie"] = flask.request.cookies.get(session["name"], "")
        #
        session["state"] = session_state
        session["nonce"] = session_nonce
        session["auth_attributes"] = id_token
        session["auth"] = True
        session["auth_errors"] = []
        session["auth_nameid"] = ""
        session["auth_sessionindex"] = ""
        #
        if self.settings["debug"]:
            log.warning("Callback redirect URL: %s", redirect_to)
        #
        return redirect(redirect_to, 302)

    @property
    def redirect_url(self) -> str:
        for header in ("X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port"):
            if header not in session:
                if "X-Forwarded-Uri" not in session:
                    return self.settings['login']["default_redirect_url"]
                return session.pop("X-Forwarded-Uri")
        proto = session.pop("X-Forwarded-Proto")
        host = session.pop("X-Forwarded-Host")
        port = session.pop("X-Forwarded-Port")
        if (proto == "http" and port != "80") or (proto == "https" and port != "443"):
            port = f":{port}"
        else:
            port = ""
        # uri = session.pop("X-Forwarded-Uri")
        try:
            uri = session.pop("X-Forwarded-Uri")
        except KeyError:
            uri = ''
            log.warning(f'NO X-Forwarded-Uri in session found, redirecting to root')
        return f"{proto}://{host}{port}{uri}"

    def _do_logout(self, to: Optional[str] = None) -> str:
        if not to:
            to = request.args.get('to', self.settings["login"]["handler_url"])
        return_to = self.settings["logout"]["default_redirect_url"]
        if to is not None and to in self.settings["logout"]["allowed_redirect_urls"]:
            return_to = to
        client = self.get_client()
        try:
            end_req = client.construct_EndSessionRequest(
                state=session.get('state'),
                request_args={"redirect_uri": return_to}
            )
        except GrantError:
            clear_session(session)
            return f"{client.end_session_endpoint}?redirect_uri={return_to}"
        logout_url = end_req.request(client.end_session_endpoint)
        if self.settings["debug"]:
            log.warning("Logout URL: %s", logout_url)
        clear_session(session)
        return logout_url
