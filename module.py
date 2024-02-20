#!/usr/bin/python3
# coding=utf-8

#   Copyright 2022 getcarrier.io
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

import urllib
import datetime

import requests  # pylint: disable=E0401
import flask  # pylint: disable=E0611,E0401
import jwt  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401
from pylon.core.tools import web  # pylint: disable=E0611,E0401
from pylon.core.tools import module  # pylint: disable=E0611,E0401

from tools import auth  # pylint: disable=E0401

from . import tools


class Module(module.ModuleModel):
    """ Pylon module """

    def __init__(self, context, descriptor):
        self.context = context
        self.descriptor = descriptor

    def _get_url(self, endpoint):
        url_mode = self.descriptor.config.get("url_mode", "default")
        #
        if url_mode == "request":
            return f'{flask.request.host_url.rstrip("/")}{flask.url_for(endpoint)}'
        #
        if url_mode == "external":
            return flask.url_for(endpoint, _external=True)
        #
        return flask.url_for(endpoint)  # default

    #
    # Module
    #

    def init(self):
        """ Init module """
        log.info("Initializing module")
        # Init blueprint
        self.descriptor.init_blueprint(
            url_prefix=self.descriptor.config.get("url_prefix", None)
        )
        # Register auth provider
        self.context.rpc_manager.call.auth_register_auth_provider(
            "oidc",
            login_route="auth_oidc.login",
            logout_route="auth_oidc.logout",
        )
        # Use metadata endpoint if set in config
        metadata_endpoint = self.descriptor.config.get("metadata_endpoint", "").strip()
        if metadata_endpoint:
            log.info("Getting metadata")
            metadata = requests.get(
                metadata_endpoint,
                verify=self.descriptor.config.get("metadata_endpoint_verify", True),
            ).json()
            #
            for endpoint in [
                "authorization_endpoint",
                "token_endpoint",
                "userinfo_endpoint",
                "end_session_endpoint",
            ]:
                if endpoint in metadata:
                    log.info("Using %s: %s", endpoint, metadata[endpoint])
                    self.descriptor.config[endpoint] = metadata[endpoint]

    def deinit(self):
        """ De-init module """
        log.info("De-initializing module")
        # Unregister auth provider
        self.context.rpc_manager.call.auth_unregister_auth_provider("oidc")

    #
    # Routes
    #

    @web.route("/login")
    def login(self):
        """ Login """
        target_token = flask.request.args.get("target_to", "")
        #
        if "auth_oidc" not in flask.session:
            flask.session["auth_oidc"] = {}
        #
        while True:
            state_uuid, target_state = tools.generate_state_id(self)
            if state_uuid not in flask.session["auth_oidc"]:
                break
        #
        flask.session["auth_oidc"][state_uuid] = {}
        flask.session["auth_oidc"][state_uuid]["target_token"] = target_token
        flask.session.modified = True
        #
        return self.descriptor.render_template(
            "redirect.html",
            action=self.descriptor.config["authorization_endpoint"],
            parameters=[
                {
                    "name": "response_type",
                    "value": "code",
                },
                {
                    "name": "client_id",
                    "value": self.descriptor.config["client_id"],
                },
                {
                    "name": "redirect_uri",
                    "value": self._get_url("auth_oidc.login_callback"),
                },
                {
                    "name": "scope",
                    "value": "openid profile email",
                },
                {
                    "name": "state",
                    "value": target_state,
                },
            ],
        )

    @web.route("/login_callback")
    def login_callback(self):  # pylint: disable=R0912,R0914,R0915,R0911
        """ Login callback """
        log.info("GET arguments: %s", flask.request.args)
        #
        if "state" not in flask.request.args:
            log.error("No state in OIDC callback")
            return auth.access_denied_reply()
        #
        target_state = flask.request.args["state"]
        #
        try:
            state_uuid = tools.get_state_id(self, target_state)
            if state_uuid not in flask.session["auth_oidc"]:
                raise ValueError("Unknown state")
        except:  # pylint: disable=W0702
            log.error("Invalid state")
            return auth.access_denied_reply()
        #
        oidc_state = flask.session["auth_oidc"].pop(state_uuid)
        flask.session.modified = True
        #
        target_token = oidc_state.get("target_token", "")
        #
        if "code" not in flask.request.args:
            log.error("No code in OIDC callback")
            return auth.access_denied_reply()
        #
        oidc_code = flask.request.args["code"]
        #
        try:
            oidc_token = requests.post(
                self.descriptor.config["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": oidc_code,
                    "redirect_uri": self._get_url("auth_oidc.login_callback"),
                },
                auth=(
                    self.descriptor.config["client_id"],
                    self.descriptor.config["client_secret"],
                ),
                verify=self.descriptor.config.get("token_endpoint_verify", True),
            ).json()
        except:  # pylint: disable=W0702
            log.error("Failed to get token")
            return auth.access_denied_reply()
        #
        log.info("Token: %s", oidc_token)
        #
        if "error" in oidc_token:
            log.error("Error in OIDC token: %s", oidc_token.get("error_description", "unknown"))
            return auth.access_denied_reply()
        #
        if "id_token" not in oidc_token:
            log.error("Invalid OIDC token: no id_tokeb")
            return auth.access_denied_reply()
        #
        id_data = jwt.decode(oidc_token["id_token"], options={"verify_signature": False})
        #
        log.info("ID data: %s", id_data)
        #
        if "sub" not in id_data:
            log.error("Invalid ID token: no sub")
            return auth.access_denied_reply()
        #
        oidc_sub = id_data["sub"]
        #
        auth_ok = True
        # log.info("Auth: %s", auth_ok)
        #
        if "preferred_username" not in id_data:
            auth_name = oidc_sub
        else:
            auth_name = id_data["preferred_username"]
        # log.info("User: %s", auth_name)
        #
        auth_attributes = id_data
        #
        # log.info("Auth attributes: %s", auth_attributes)
        #
        auth_sessionindex = oidc_token["id_token"]
        #
        if "exp" not in id_data:
            auth_exp = datetime.datetime.now() + datetime.timedelta(seconds=86400)  # 24h
        else:
            auth_exp = datetime.datetime.fromtimestamp(id_data["exp"])
        #
        try:
            auth_user_id = \
                self.context.rpc_manager.call.auth_get_user_from_provider(
                    auth_name
                )["id"]
        except:  # pylint: disable=W0702
            auth_user_id = None
        #
        auth_ctx = auth.get_auth_context()
        auth_ctx["done"] = auth_ok
        auth_ctx["error"] = ""
        auth_ctx["expiration"] = auth_exp
        auth_ctx["provider"] = "oidc"
        auth_ctx["provider_attr"]["nameid"] = auth_name
        auth_ctx["provider_attr"]["attributes"] = auth_attributes
        auth_ctx["provider_attr"]["sessionindex"] = auth_sessionindex
        auth_ctx["user_id"] = auth_user_id
        auth.set_auth_context(auth_ctx)
        #
        log.info("Context: %s", auth_ctx)
        #
        return auth.access_success_redirect(target_token)

    @web.route("/logout")
    def logout(self):
        """ Logout """
        target_token = flask.request.args.get("target_to", "")
        auth_ctx = auth.get_auth_context()
        #
        if "auth_oidc" not in flask.session:
            flask.session["auth_oidc"] = {}
        #
        while True:
            state_uuid, target_state = tools.generate_state_id(self)
            if state_uuid not in flask.session["auth_oidc"]:
                break
        #
        flask.session["auth_oidc"][state_uuid] = {}
        flask.session["auth_oidc"][state_uuid]["target_token"] = target_token
        flask.session.modified = True
        #
        logout_mode = self.descriptor.config.get("logout_mode", "get")
        #
        if logout_mode == "get":
            url_params = urllib.parse.urlencode({
                "id_token_hint": auth_ctx["provider_attr"].get("sessionindex", ""),
                "post_logout_redirect_uri": self._get_url("auth_oidc.logout_callback"),
                "state": target_state,
            })
            return flask.redirect(f'{self.descriptor.config["end_session_endpoint"]}?{url_params}')
        #
        if logout_mode == "post":
            return self.descriptor.render_template(
                "redirect.html",
                action=self.descriptor.config["end_session_endpoint"],
                parameters=[
                    {
                        "name": "id_token_hint",
                        "value": auth_ctx["provider_attr"].get("sessionindex", ""),
                    },
                    {
                        "name": "post_logout_redirect_uri",
                        "value": self._get_url("auth_oidc.logout_callback"),
                    },
                    {
                        "name": "state",
                        "value": target_state,
                    },
                ],
            )
        #
        if logout_mode == "local":
            return auth.logout_success_redirect(target_token)
        #
        return auth.access_denied_reply()

    @web.route("/logout_callback")
    def logout_callback(self):  # pylint: disable=R0912,R0914,R0915
        """ Logout callback """
        log.info("GET arguments: %s", flask.request.args)
        #
        if "state" not in flask.request.args:
            log.error("No state in OIDC callback")
            return auth.access_denied_reply()
        #
        target_state = flask.request.args["state"]
        #
        try:
            state_uuid = tools.get_state_id(self, target_state)
            if state_uuid not in flask.session["auth_oidc"]:
                raise ValueError("Unknown state")
        except:  # pylint: disable=W0702
            log.error("Invalid state")
            return auth.access_denied_reply()
        #
        oidc_state = flask.session["auth_oidc"].pop(state_uuid)
        flask.session.modified = True
        #
        target_token = oidc_state.get("target_token", "")
        #
        return auth.logout_success_redirect(target_token)
