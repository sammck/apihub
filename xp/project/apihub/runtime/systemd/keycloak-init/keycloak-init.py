#!/usr/bin/env python3

from typing import cast, Optional, List, Dict, Any, Union

import os
import json
from copy import deepcopy

import keycloak
from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakError

import logging
import sys

Jsonable = Union[str, int, float, bool, None, Dict[str, Any], List[Any]]
"""A Type hint for a simple JSON-serializable value; i.e., str, int, float, bool, None, Dict[str, Jsonable], List[Jsonable]"""

JsonableDict = Dict[str, Jsonable]
"""A type hint for a simple JSON-serializable dict; i.e., Dict[str, Jsonable]"""

JsonableList = List[Jsonable]
"""A type hint for a simple JSON-serializable list; i.e., List[Jsonable]"""


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

logging.basicConfig(level=logging.DEBUG)

keycloak_password: str = os.environ.get('KEYCLOAK_ADMIN_PASSWORD', '')
if keycloak_password == '':
  raise RuntimeError('Environment variable KEYCLOAK_ADMIN_PASSWORD is required')
keycloak_server_url = os.environ.get('KEYCLOAK_BACKEND_URL', 'http://keycloak:8080')
keycloak_master_realm: str = 'master'
keycloak_master_client_id: str = 'admin-cli'
keycloak_master_username: str = os.environ.get('KEYCLOAK_ADMIN', 'admin')
sso_admin_username: str = os.environ.get("SSO_ADMIN_USERNAME", '')
if sso_admin_username == '':
  raise RuntimeError('Environment variable SSO_ADMIN_USERNAME is required')
if not '@' in sso_admin_username:
  raise RuntimeError('SSO_ADMIN_USERNAME must be a valid email address')
sso_admin_password: str = os.environ.get("SSO_ADMIN_PASSWORD", '')
if sso_admin_password == '':
  raise RuntimeError('Environment variable SSO_ADMIN_PASSWORD is required')
sso_admin_friendly_name: str = os.environ.get("SSO_ADMIN_FRIENDLY_NAME", '')
if sso_admin_friendly_name == '':
  raise RuntimeError('Environment variable SSO_ADMIN_FRIENDLY_NAME is required')
sso_admin_first_name, sso_admin_last_name = sso_admin_friendly_name.split(None, 1)
shared_auth_domain: str = os.environ.get('SHARED_AUTH_DOMAIN', '')
if shared_auth_domain == '':
  raise RuntimeError('Environment variable SHARED_AUTH_DOMAIN is required')
base_url: str = os.environ.get('BASE_URL', f'https://www.{shared_auth_domain}')
redirect_uris_comma_delimited: str = os.environ.get('REDIRECT_URIS', f'https://auth.{shared_auth_domain}/*')
redirect_uris = redirect_uris_comma_delimited.split(',')
sso_client_secret: str = os.environ.get('SSO_CLIENT_SECRET', 'sso-client-secret-314159')

smtp_user: str = os.environ.get('SMTP_USER', '')
if smtp_user == '':
  raise RuntimeError('Environment variable SMTP_USER is required')
smtp_password: str = os.environ.get('SMTP_PASSWORD', '')
if smtp_password == '':
  raise RuntimeError('Environment variable SMTP_PASSWORD is required')
smtp_host: str = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
smtp_port: str = os.environ.get("SMTP_PORT", "587")
smtp_display_name: str = os.environ.get("SMTP_DISPLAY_NAME", sso_admin_friendly_name)
smtp_from: str = os.environ.get("SMTP_FROM", smtp_user)
smtp_from_display_name: str = os.environ.get("SMTP_FROM_DISPLAY_NAME", smtp_display_name)
smtp_envelope_from: str = os.environ.get("SMTP_ENVELOPE_FROM", smtp_from)
smtp_reply_to: str = os.environ.get("SMTP_REPLY_TO", smtp_from)
smtp_reply_to_display_name: str = os.environ.get("SMTP_REPLY_TO_DISPLAY_NAME", smtp_display_name)
smtp_ssl: str = os.environ.get("SMTP_SSL", "")
smtp_starttls: str = os.environ.get("SMTP_STARTTLS", "true")
smtp_auth = "true"

keycloak_openid = KeycloakOpenID(
    server_url = keycloak_server_url,
    client_id = keycloak_master_client_id,
    realm_name = keycloak_master_realm,
  )

#cfg = keycloak_openid.well_know()
# Get WellKnow
#config_well_know = keycloak_openid.well_know()
#logger.info("Well-known info=%s", json.dumps(config_well_know, indent=2, sort_keys=True))

# Get Token
#token = keycloak_openid.token(keycloak_master_username, keycloak_password)
#token = keycloak_openid.token("user", "password", totp="012345")
#logger.info("Token=%s", json.dumps(token, indent=2, sort_keys=True))


# Get Userinfo
#userinfo = keycloak_openid.userinfo(token['access_token'])
#logger.info("userinfo=%s", json.dumps(userinfo, indent=2, sort_keys=True))

# Decode Token
#KEYCLOAK_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" + keycloak_openid.public_key() + "\n-----END PUBLIC KEY-----"
#options = {"verify_signature": True, "verify_aud": True, "verify_exp": True}
#token_info = keycloak_openid.decode_token(token['access_token'], key=KEYCLOAK_PUBLIC_KEY, options=options)
#logger.info("token_info=%s", json.dumps(token_info, indent=2, sort_keys=True))

class CustomKeycloakAdmin(keycloak.KeycloakAdmin):
  def get_client_scope_id(self, name: str) -> Optional[str]:
    scopes: List[JsonableDict] = self.get_client_scopes()
    for scope in scopes:
      if name == scope.get('name', None):
        return scope['id']
    return None

keycloak_master_admin = CustomKeycloakAdmin(server_url = keycloak_server_url,
                               username = keycloak_master_username,
                               password = keycloak_password,
                               realm_name = keycloak_master_realm,
                               # user_realm_name="only_if_other_realm_than_master",
                               # client_secret_key="client-secret",
                               verify=True)

#logger.info("KeycloakAdmin master Token=%s", json.dumps(keycloak_master_admin.token, indent=2, sort_keys=True))

smtp_server_info = {
    "auth": str(smtp_auth).lower(),
    "envelopeFrom": smtp_envelope_from,
    "from": smtp_from,
    "fromDisplayName": smtp_from_display_name,
    "host": smtp_host,
    "password": smtp_password,
    "port": str(smtp_port),
    "replyTo": smtp_reply_to,
    "replyToDisplayName": smtp_reply_to_display_name,
    "ssl": smtp_ssl,
    "starttls": str(smtp_starttls).lower(),
    "user": smtp_user
  }


old_master_realm_info = keycloak_master_admin.export_realm()
master_realm_info = deepcopy(old_master_realm_info)
smtp_settings = master_realm_info.get('smtpServer', {})
new_smtp_settings = deepcopy(smtp_server_info)
new_smtp_settings.update(smtp_settings)
master_realm_info['smtpServer'] = new_smtp_settings

if json.dumps(master_realm_info, sort_keys=True) != json.dumps(old_master_realm_info, sort_keys=True):
  logger.info("KeycloakAdmin master realm has not been initialized; updating info")
  keycloak_master_admin.update_realm('master', master_realm_info)
else:
  logger.info("KeycloakAdmin master realm already correct; not updating")

master_user_id = keycloak_master_admin.get_user_id('admin')
logger.info("KeycloakAdmin master admin user id=%s", master_user_id)

old_master_user_info = keycloak_master_admin.get_user(master_user_id)
# initial content:
#  {
#    "id": "31cd6f33-ac95-4ae8-83de-e002feb6c543",
#    "createdTimestamp": 1651945207354,
#    "username": "admin",
#    "enabled": true,
#    "totp": false,
#    "emailVerified": false,
#    "disableableCredentialTypes": [],
#    "requiredActions": [],
#    "notBefore": 0,
#    "access": {
#      "manageGroupMembership": true,
#      "view": true,
#      "mapRoles": true,
#      "impersonate": true,
#      "manage": true
#    }
#  }

# update:
#  {
#    "id": "31cd6f33-ac95-4ae8-83de-e002feb6c543",
#    "createdTimestamp": 1651945207354,
#    "username": "admin",
#    "enabled": true,
#    "totp": false,
#    "emailVerified": true,  # set
#    "disableableCredentialTypes": [],
#    "requiredActions": [],
#    "notBefore": 0,
#    "access": {
#      "manageGroupMembership": true,
#      "view": true,
#      "mapRoles": true,
#      "impersonate": true,
#      "manage": true
#    },
#    "attributes": {},  # added
#    "email": "sammck@gmail.com", # added
#    "firstName": "Sam",  # added
#    "lastName": "McKelvie"  #added
#  }

master_user_info = deepcopy(old_master_user_info)
if master_user_info.get('email', '') == '':
  master_user_info['email'] = sso_admin_username
master_user_info['emailVerified'] = True
if master_user_info.get('firstName', '') == '':
  master_user_info['firstName'] = sso_admin_first_name
if master_user_info.get('lastName', '') == '':
  master_user_info['lastName'] = sso_admin_last_name
if json.dumps(master_user_info, sort_keys=True) != json.dumps(old_master_user_info, sort_keys=True):
  logger.info("KeycloakAdmin master admin user has not been initialized; updating info")
  keycloak_master_admin.update_user(master_user_id, master_user_info)
else:
  logger.info("KeycloakAdmin master admin user already correct; not updating")

keycloak_sso_admin: Optional[CustomKeycloakAdmin] = None
# Try to import SSO realm:
try:
  keycloak_sso_admin = CustomKeycloakAdmin(server_url = keycloak_server_url,
                                username = keycloak_master_username,
                                password = keycloak_password,
                                realm_name = 'sso',
                                user_realm_name='master',
                                # client_secret_key="client-secret",
                                verify=True)
  keycloak_sso_admin.export_realm()
  logger.info("SSO realm already exists, not recreating...")
except KeycloakError as e:
  logger.info("Failed to export sso realm, will have to create: %s", e)
  keycloak_sso_admin = None

# sso_client_id = "caba12aa-bcc7-4db5-bcac-4ecda32d116b"

sso_client_obj =               {
    "alwaysDisplayInConsole": True,
    "attributes": {},
    "authenticationFlowBindingOverrides": {},
    "baseUrl": base_url,
    "bearerOnly": False,
    "clientAuthenticatorType": "client-secret",
    "clientId": "sso-client",
    "consentRequired": False,
    "defaultClientScopes": [
      "web-origins",
      "acr",
      "roles",
      "profile",
      "email"
    ],
    "description": "Simple OIDC client config for SSO realm",
    "directAccessGrantsEnabled": True,   # This allows getting token directly with username + password
    "enabled": True,
    "frontchannelLogout": False,
    "fullScopeAllowed": True,
    # "id": sso_client_id,
    "implicitFlowEnabled": False,
    "name": "SSO OIDC client",
    "nodeReRegistrationTimeout": -1,
    "notBefore": 0,
    "optionalClientScopes": [
        "address",
        "phone",
        "offline_access",
        "microprofile-jwt"
      ],
    "origin": base_url,
    "protocol": "openid-connect",
    "protocolMappers": [
        dict(
            id="888cc32a-dabe-4150-ae4e-50b375976add",
            name="realm roles",
            protocol="openid-connect",
            protocolMapper="oidc-usermodel-realm-role-mapper",
            consentRequired=False,
            config={
                "user.attribute": "foo",
                "access.token.claim": "true",
                "claim.name": "realm_access.roles",
                "jsonType.label": "String",
                "multivalued": "true",
                "id.token.claim": "true",
                "userinfo.token.claim": "true",
              }
          ),
      ],
    "publicClient": False,
    "redirectUris": redirect_uris,
    "secret": sso_client_secret,
    "serviceAccountsEnabled": False,
    "standardFlowEnabled": True,
    "surrogateAuthRequired": False,
    "webOrigins": [ "*" ]
  }

demo_client_obj =               {
    "alwaysDisplayInConsole": False,
    "attributes": {},
    "authenticationFlowBindingOverrides": {},
    "baseUrl": f"https://demo.{shared_auth_domain}",
    "bearerOnly": False,
    "clientAuthenticatorType": "public",
    "clientId": "demo-client",
    "consentRequired": False,
    "defaultClientScopes": [
      "web-origins",
      "acr",
      "roles",
      "profile",
      "email"
    ],
    "description": "Demo Web App SSO realm",
    "directAccessGrantsEnabled": True,   # This allows getting token directly with username + password
    "enabled": True,
    "frontchannelLogout": False,
    "fullScopeAllowed": True,
    # "id": sso_client_id,
    "implicitFlowEnabled": False,
    "name": "SSO Demo Web App",
    "nodeReRegistrationTimeout": -1,
    "notBefore": 0,
    "optionalClientScopes": [
        "address",
        "phone",
        "offline_access",
        "microprofile-jwt"
      ],
    "origin": f"https://demo.{shared_auth_domain}",
    "protocol": "openid-connect",
    "protocolMappers": [
        dict(
            id="aa297a85-5727-46f7-a81f-ea118c286812",
            name="realm roles",
            protocol="openid-connect",
            protocolMapper="oidc-usermodel-realm-role-mapper",
            consentRequired=False,
            config={
                "user.attribute": "foo",
                "access.token.claim": "true",
                "claim.name": "realm_access.roles",
                "jsonType.label": "String",
                "multivalued": "true",
                "id.token.claim": "true",
                "userinfo.token.claim": "true",
              }
          ),
      ],
    "publicClient": True,
    "redirectUris": [ f"https://demo.{shared_auth_domain}/*" ],
    "serviceAccountsEnabled": False,
    "standardFlowEnabled": True,
    "surrogateAuthRequired": False,
    "webOrigins": [ f"https://demo.{shared_auth_domain}" ]
  }

if keycloak_sso_admin is None:
  # Create a new Realm
  keycloak_master_admin.create_realm(
      payload=dict(
          realm = "sso",
          enabled = True,
          displayName = f"{shared_auth_domain} Single Sign-on",
          displayNameHtml = f"Welcome to {shared_auth_domain}",
          rememberMe = True,
          verifyEmail = True,
          registrationAllowed = True,
          registrationEmailAsUsername = True,
          loginWithEmailAllowed = True,
          resetPasswordAllowed = True,
          smtpServer = deepcopy(smtp_server_info),
          #groups = [
          #    dict(
          #        name='user',
          #      ),
          #    dict(
          #        name='admin',
          #      ),
          #  ],
          clients = [
              sso_client_obj,
              demo_client_obj,
            ],
        ),
      skip_exists=False
    )

  keycloak_sso_admin = CustomKeycloakAdmin(server_url = keycloak_server_url,
                                username = keycloak_master_username,
                                password = keycloak_password,
                                realm_name = 'sso',
                                user_realm_name='master',
                                # client_secret_key="client-secret",
                                verify=True)
  logger.info("Successfully created sso realm")

  #logger.info("KeycloakAdmin sso Token=%s", json.dumps(keycloak_master_admin.token, indent=2, sort_keys=True))


sso_realm_info = keycloak_sso_admin.export_realm(
    export_clients=True,
    export_groups_and_role=True
  )

sso_realm_id = sso_realm_info['id']
logger.info("sso realm id=%s", sso_realm_id)

sso_client_id = keycloak_sso_admin.get_client_id("sso-client")
logger.info("sso client id=%s", sso_client_id)
demo_client_id = keycloak_sso_admin.get_client_id("demo-client")
logger.info("demo client id=%s", demo_client_id)

#roles_scope_id = keycloak_sso_admin.get_client_scope_id('roles') 
#roles_scope = keycloak_sso_admin.get_client_scope(roles_scope_id)

try:
  keycloak_sso_admin.get_realm_role("user")
  logger.info("sso realm user role already exists, not creating")
except KeycloakError as e:
  logger.info("Failed to get sso realm user role, will have to create: %s", e)
  keycloak_sso_admin.create_realm_role(
      {
          "attributes": {},
          "clientRole": False,
          "composite": False,
          #"containerId": sso_realm_id,
          "description": "An authorized user that has registered and been approved to use the service",
          "name": "user"
        }
    )

sso_user_role_info = keycloak_sso_admin.get_realm_role("user")
sso_user_role_id = sso_user_role_info["id"]
logger.info("sso realm user role id=%s", sso_user_role_id)

try:
  keycloak_sso_admin.get_realm_role("admin")
  logger.info("sso realm admin role already exists, not creating")
except KeycloakError as e:
  logger.info("Failed to get sso realm admin role, will have to create: %s", e)
  keycloak_sso_admin.create_realm_role(
      {
          "attributes": {},
          "clientRole": False,
          "composite": True,
          "composites": {
            "realm": [
              "user"
            ]
          },
          #"containerId": sso_realm_id,
          "description": "An administrative user that can do anything the service allows",
          "name": "admin"
        }
    )
sso_admin_role_info = keycloak_sso_admin.get_realm_role("admin")
sso_admin_role_id = sso_admin_role_info["id"]
logger.info("sso realm admin role id=%s", sso_admin_role_id)

sso_user_id: Optional[str] = None

try:
  sso_user_id = keycloak_sso_admin.get_user_id(sso_admin_username)
except KeycloakError as e:
  logger.info("Failed to get sso admin user, will have to create: %s", e)

if not sso_user_id is None:
  logger.info("sso admin user already exists, not creating... id=%s", sso_user_id)
else:
  logger.info("sso admin user does not exists; creating")
  keycloak_sso_admin.create_user(
      {
          "access": {
            "impersonate": True,
            "manage": True,
            "manageGroupMembership": True,
            "mapRoles": True,
            "view": True,
          },
          #"createdTimestamp": 1651786376067,
          #"disableableCredentialTypes": [],
          "email": sso_admin_username,
          "emailVerified": True,
          "enabled": True,
          "firstName": sso_admin_first_name,
          #"id": sso_user_id,   # Doesn't work, see above
          "lastName": sso_admin_last_name,
          #"notBefore": 0,
          "requiredActions": [],
          "totp": False,
          "username": sso_admin_username
        }
    )

  sso_user_id = keycloak_sso_admin.get_user_id(sso_admin_username)
  keycloak_sso_admin.set_user_password(sso_user_id, sso_admin_password, temporary=False)

  # Assign role to user. Note that BOTH role_name and role_id appear to be required.
  keycloak_sso_admin.assign_realm_roles(
      user_id=sso_user_id,
      roles = [
          {
              "clientRole": False,
              "composite": True,
              "containerId": sso_realm_id,
              "id": sso_admin_role_id,
              "name": "admin",
            },
        ],
    )
