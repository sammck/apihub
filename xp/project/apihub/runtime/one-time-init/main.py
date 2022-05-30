#!/usr/bin/env python3

from typing import cast, Optional

import json
import yaml
import boto3
import boto3.session
from pulumi_crypto import decrypt_string
from pulumi_crypto.internal_types import Jsonable, JsonableDict
from base64 import b64decode
from copy import deepcopy
from urllib.parse import urlparse, ParseResult, urlunparse, unquote as url_unquote
import requests
import logging
import sys
import os
import subprocess
import shutil
import project_init_tools
from project_init_tools import download_url_file, append_lines_to_file_if_missing, dedent
from project_init_tools.installer.docker_compose import install_docker_compose
from pwd import getpwnam


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

logging.basicConfig(level=logging.DEBUG)

oneshot_dir = '/var/opt/cloudservice/oneshot'
active_dir = '/var/opt/cloudservice/active'
staged_dir = '/var/opt/cloudservice/staged'
oneshot_runtime_dir = os.path.join(oneshot_dir, 'runtime')
oneshot_config_dir = os.path.join(oneshot_dir, 'config')
oneshot_secrets_dir = os.path.join(oneshot_dir, 'secrets')
staged_runtime_dir = os.path.join(staged_dir, 'runtime')
staged_config_dir = os.path.join(staged_dir, 'config')
staged_secrets_dir = os.path.join(staged_dir, 'secrets')
staged_systemd_dir = os.path.join(staged_runtime_dir, 'systemd')
active_runtime_dir = os.path.join(active_dir, 'runtime')
active_systemd_dir = os.path.join(active_runtime_dir, 'systemd')

cloudservice_config_s3_obj_uri = sys.argv[1]
logger.info("Cloudservice Config URI=%s", cloudservice_config_s3_obj_uri)

uname_data = os.uname()

# Get the AWS region we are in from the EC2 metadata service
aws_region = requests.get('http://169.254.169.254/latest/meta-data/placement/region').text
logger.info("AWS region=%s", aws_region)

# get aws account info etc.
instance_identity_obj = json.loads(requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document').text)
aws_account = instance_identity_obj['accountId']

aws = boto3.session.Session(region_name=aws_region)

ssm = aws.client('ssm')
s3 = aws.client('s3')

def read_s3_blob(blob_uri: str) -> bytes:
  parts = urlparse(blob_uri)
  if parts.scheme != 's3':
    raise RuntimeError(f"Invalid 's3:' URI: {blob_uri}")
  bucket = parts.netloc
  key = parts.path
  while key.startswith('/'):
    key = key[1:]
  s3_resp = s3.get_object(Bucket=bucket, Key=key)
  bin_data = s3_resp['Body'].read()
  assert isinstance(bin_data, bytes)
  return bin_data

def quote_dotenv_value(value: str) -> str:
  result = '"' + value.replace("\\","\\\\").replace('"', '\\"').replace('$', '\\$').replace("\n", '\\n') + '"'
  return result

# read the cloudservice configuration from S3 and save it
config_text = read_s3_blob(cloudservice_config_s3_obj_uri).decode('utf-8')
config_obj: JsonableDict = json.loads(config_text)
config_obj['aws_region'] = aws_region
config_obj['aws_account'] = aws_account
os.makedirs(oneshot_config_dir, mode=0o755, exist_ok=True)
with open(os.path.join(oneshot_config_dir, 'cloudservice.json'), 'w', encoding='utf-8') as fw:
  json.dump(config_obj, fw, indent=2, sort_keys=True)
  fw.write('\n')

stack_s3_uri = cast(str, config_obj['stack_s3_uri'])
secrets_s3_obj_uri = cast(str, config_obj['secrets_s3_obj_uri'])
ssm_param_secret_key = cast(str, config_obj['ssm_param_secret_key'])
primary_username = cast(str, config_obj['primary_username'])
primary_user_ssh_public_key = cast(str, config_obj['primary_user_ssh_public_key'])
dns_zone = cast(str, config_obj['dns_zone'])

# read the AES key for the cloudservice secrets from AWS SSM Parameter Store
resp = ssm.get_parameter(Name=ssm_param_secret_key, WithDecryption=True)
secrets_key_b64: str = resp['Parameter']['Value']
secrets_key = b64decode(secrets_key_b64)

# Read and decrypyt the cloudservice secrets from S3, using the AES key
secrets_encrypted = read_s3_blob(secrets_s3_obj_uri).decode('utf-8')
secrets: JsonableDict = json.loads(decrypt_string(secrets_encrypted, secrets_key))

os.makedirs(oneshot_secrets_dir, mode=0o700, exist_ok=True)
with open(
      os.open(os.path.join(oneshot_secrets_dir, 'secrets.json'), os.O_CREAT | os.O_WRONLY, 0o600),
      'w',
      encoding='utf-8'
    ) as fw:
  json.dump(secrets, fw, indent=2, sort_keys=True)
  fw.write('\n')


# Before we make any actual changes, shut down any running service
subprocess.call(['systemctl', 'stop', 'cloudservice'])

# Clone the runtime directory that came with us into the staged area.  This ensures that update is
# atomic and not done while the service is running
subprocess.check_call(['rm', '-fr', staged_dir])
os.makedirs(staged_dir, mode=0o755)
subprocess.check_call(['rsync', '-a', oneshot_runtime_dir + '/', staged_runtime_dir + '/'])

os.makedirs(staged_secrets_dir, mode=0o700, exist_ok=True)
with open(
      os.open(os.path.join(staged_secrets_dir, 'secrets.json'), os.O_CREAT | os.O_WRONLY, 0o600),
      'w',
      encoding='utf-8'
    ) as fw:
  json.dump(secrets, fw, indent=2, sort_keys=True)
  fw.write('\n')
with open(
      os.open(os.path.join(staged_secrets_dir, 'secrets.env'), os.O_CREAT | os.O_WRONLY, 0o600),
      'w',
      encoding='utf-8'
    ) as fw:
  for k in sorted(secrets):
    v = secrets[k]
    print(f"{k}={quote_dotenv_value(v)}", file=fw)

os.makedirs('/data/docker-static-volumes', mode=0o755, exist_ok=True)
os.makedirs('/data/docker-static-volumes/letsencrypt', mode=0o700, exist_ok=True)
os.makedirs('/data/docker-static-volumes/keycloak-db', mode=0o700, exist_ok=True)

# ECR is AWS's equivalent of Dockerhub. There is a distinct endpoint in each
# region, and for each AWS account. Also, there is a customized authentication
# plugin for docker that allows you to access the repository using your AWS
# credentials.
ecr_domain: str = f"{aws_account}.dkr.ecr.{aws_region}.amazonaws.com"

# Create docker config to automatically authenticate against ECR using EC2 role
docker_config_obj = dict(
    credHelpers = {
        "public.ecr.aws": "ecr-login",
        ecr_domain: "ecr-login"
      }
  )
docker_config_text = json.dumps(docker_config_obj, indent=2, sort_keys=True) + '\n'

# Make sure all home directories are properly set up
for user in ('root', 'cloudservice', primary_username):
  homedir = '/root' if user == 'root' else f'/home/{user}'
  pwn = getpwnam(user)
  uid = pwn.pw_uid
  gid = pwn.pw_gid

  docker_config_dir = os.path.join(homedir, '.docker')
  docker_config_file = os.path.join(docker_config_dir, 'config.json')
  if not os.path.exists(docker_config_file):
    os.makedirs(docker_config_dir, mode=0o700, exist_ok=True)
    os.chown(docker_config_dir, uid, gid)
    with open(
          os.open(docker_config_file, os.O_CREAT | os.O_WRONLY, 0o600),
          'w',
          encoding='utf-8'
        ) as fw:
      fw.write(docker_config_text)
    os.chown(docker_config_file, uid, gid)

  if user != 'root':
    if not os.path.exists(homedir):
      subprocess.check_call(['mkhomedir_helper', user])
    if user == primary_username:
      ssh_dir = os.path.join(homedir, '.ssh')
      os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
      os.chown(ssh_dir, uid, gid)
      ssh_authorized_keys_file = os.path.join(ssh_dir, 'authorized_keys')
      append_lines_to_file_if_missing(ssh_authorized_keys_file, primary_user_ssh_public_key, create_file=True, create_mode=0o600)
      os.chown(ssh_authorized_keys_file, uid, gid)

# Install docker-compose:
install_docker_compose('/usr/local/bin', min_version='latest')

admin_email = config_obj['admin_email']
ssl_email = config_obj.get('ssl_email', admin_email)
smtp_username = config_obj.get('smtp_username', admin_email)
smtp_reply_to = config_obj.get('smtp_reply_to', smtp_username)

# Nonsecret env vars used by our docker-compose
cloudservice_docker_compose_env_obj: JsonableDict = dict(
    COMPOSE_PROJECT_NAME = 'cloudservice',
    ssl_email = ssl_email,
    dns_zone = dns_zone,
    admin_email = admin_email,
    smtp_username = smtp_username,
    smtp_reply_to = smtp_reply_to,
    admin_friendly_name = config_obj['admin_friendly_name'],
    smtp_port = str(config_obj.get('smtp_port', 587)),
    smtp_host = config_obj.get('smtp_host', 'smtp.gmail.com'),
  )

# add our secrets to the docker-compose environment. Ugly, but docker-compose
# only allows a single environment to be passed. We will make sure
# permissions are 600 on .env
cloudservice_docker_compose_env_obj.update(secrets)

with open(
      os.open(os.path.join(staged_systemd_dir, '.env'), os.O_CREAT | os.O_WRONLY, 0o600),
      'w',
      encoding='utf-8'
    ) as fw:
  for k in sorted(cloudservice_docker_compose_env_obj):
    v = cloudservice_docker_compose_env_obj[k]
    print(f"{k}={quote_dotenv_value(v)}", file=fw)

#  --log.level=DEBUG
#  --accesslog=true
#  --api.insecure=true
#  # look at docker container tags to auto-configuree microservices
#  --providers.docker=true
#  --providers.docker.exposedbydefault=false
#  # redirect all HTTP to HTTPS
#  --entrypoints.web.address=:80
#  --entrypoints.web.http.redirections.entryPoint.to=websecure
#  --entrypoints.web.http.redirections.entryPoint.scheme=https
#  --entrypoints.web.http.redirections.entrypoint.permanent=true
#  --entrypoints.websecure.address=:443
#  # redirect all www.<domain> to <domain>
#  --http.middlewares.redirect-www.redirectregex.regex='^https://www\\.(.+)'
#  --http.middlewares.redirect-www.redirectregex.replacement='https://$$1'
#  --http.middlewares.redirect-www.redirectregex.permanent=true
#  --http.routers.global-www-redirect.rule='HostRegexp(`^www\\..+`)'
#  --http.routers.global-www-redirect.priority=200
#  --http.routers.global-www-redirect.middlewares=redirect-www
#  # use LetsEncrypt to provide SSL certs for everything
#  --certificatesresolvers.myresolver.acme.tlschallenge=true
#  --certificatesresolvers.myresolver.acme.email=${ssl_email}
#  --certificatesresolvers.myresolver.acme.storage=/letsencrypt/acme.json

# Create a traefik config file
traefik_config_obj: JsonableDict = dict(
    pilot=dict(
        token=secrets['traefik_pilot_token'],
      ),
    log=dict(
        level='DEBUG'
      ),
    accesslog=True,
    api=dict(
        insecure=True
      ),
    providers=dict(
        docker=dict(
            exposedbydefault=False
          )
      ),
    entrypoints=dict(
        web=dict(
            address=':80',
            http=dict(
                redirections=dict(
                    entryPoint={
                        'to': 'websecure',
                        'scheme': 'https',
                        'permanent': True
                      }
                  )
              )
          ),
        websecure=dict(
            address=':443',

          ),
      ),
    #http=dict(
    #    middlewares={
    #        'redirect-www': dict(
    #            redirectRegex=dict(
    #                regex=r'^https://www\.(.+)',
    #                replacement='https://$1',
    #                permanent=True
    #              ),
    #          ),
    #      },
    #    routers={
    #        'global-www-redirect': dict(
    #            rule='HostRegexp(`' + r'^www\..+' + '`)',
    #            priority=200,
    #            middlewares=[ 'redirect-www' ],
    #          ),
    #      },
    #  ),
    certificatesresolvers=dict(
        myresolver=dict(
            acme=dict(
                tlschallenge=True,
                email=ssl_email,
                storage='/letsencrypt/acme.json'
              )
          )
      ),
  )

with open(
      os.open(os.path.join(staged_systemd_dir, 'traefik.yml'), os.O_CREAT | os.O_WRONLY, 0o600),
      'w',
      encoding='utf-8'
    ) as fw:
  yaml.safe_dump(traefik_config_obj, fw)

# point systemd at the active copy, which will be replaced in a moment
cloudservice_service_target = '/etc/systemd/system/cloudservice.service'
cloudservice_service_source = os.path.join(active_systemd_dir, 'cloudservice.service')
if not os.path.exists(cloudservice_service_target) or os.path.realpath(
    cloudservice_service_target) != os.path.realpath(cloudservice_service_source):
  if os.path.exists(cloudservice_service_target) or os.path.islink(cloudservice_service_target):
    os.remove(cloudservice_service_target)
  os.symlink(cloudservice_service_source, cloudservice_service_target)

# replace active with staged
old_active_dir = active_dir + '.old'
subprocess.check_call(['rm', '-fr', old_active_dir])
os.replace(active_dir, old_active_dir)
os.replace(staged_dir, active_dir)
subprocess.check_call(['rm', '-fr', old_active_dir])

# start up the service.  after it is enabled it will auto-start on reboot.

subprocess.check_call(['systemctl', 'daemon-reload'])
subprocess.check_call(['systemctl', 'enable', 'cloudservice'])
subprocess.check_call(['systemctl', 'start', '--no-block', 'cloudservice'])

print("All done with one-time-init!")
