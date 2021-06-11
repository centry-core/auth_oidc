import requests
from flask import g
from oic.oic import Client
from oic.oic.message import ProviderConfigurationResponse, RegistrationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD


def create_oidc_client(issuer=None, registration_info=None):
    if "oidc" not in g:
        g.oidc = Client(client_authn_method=CLIENT_AUTHN_METHOD)
        config = requests.get(
            f"{issuer}/.well-known/openid-configuration",
            headers={"Content-type": "application/json"}
        ).json()
        provider_config = ProviderConfigurationResponse(**config)
        g.oidc.handle_provider_config(provider_config, issuer)
        g.oidc.store_registration_info(
            RegistrationResponse(**registration_info)
        )
        g.oidc.redirect_uris.append(f"{g.oidc.registration_response['redirect_uris'][0]}/callback")
    return g.oidc


def clear_session(session):
    session["name"] = "auth"
    session["state"] = ""
    session["nonce"] = ""
    session["auth"] = False
    session["auth_errors"] = []
    session["auth_nameid"] = ""
    session["auth_sessionindex"] = ""
    session["auth_attributes"] = ""

