#!/usr/bin/env python

import click
import json
import py
from keyme import KeyMe

class Config(dict):
    def __init__(self, *args, **kwargs):
        self.config = py.path.local(
            click.get_app_dir('keyme')
        ).join('config.json') # A

        super(Config, self).__init__(*args, **kwargs)

    def load(self):
        """load a JSON config file from disk"""
        try:
            self.update(json.loads(self.config.read())) # B
        except py.error.ENOENT:
            pass

    def save(self):
    	self.config.ensure()
        with self.config.open('w') as f: # B
            f.write(json.dumps(self))




def generate_keys(event, context):
    username = event.get('username')
    password = event.get('password')
    mfa_code = event.get('mfa_code')
    region = event.get('region', 'us-east-1')

    # The following, we expect, to come from $stageVariables
    idp = event.get('idpid')
    sp  = event.get('spid')
    role = event.get('role')
    principal = event.get('principal')

    # Duplication is to avoid defaulting values in the class
    # - thats logic we shouldn't be doing there
    return KeyMe(username=username,
                password=password,
                mfa_code=mfa_code,
                idp=idp,
                sp=sp,
                region=region,
                role=role,
                principal=principal).key()


pass_config = click.make_pass_decorator(Config, ensure=True)

@click.group(chain=True)
@pass_config
def cli(config):
    config.load()
    pass

@cli.command('show-config')
@pass_config
def show_config(config):
    data = json.dumps(config)
    click.echo(data)


@cli.command('init')
@pass_config
@click.option('--update', help="update configuration for given env name")
def setup(config,update):
    if update not in config:
        name = click.prompt('Please enter a name for this config', default='default')
    else:
        name = update

    idp_id = click.prompt('Please enter your google idp id')
    sp_id = click.prompt('Please enter your aws sp id')
    aws_region = click.prompt('Which AWS Region do you want to be default?', default='us-east-1')
    principal_arn = click.prompt('Please provide your default principal ARN')
    role_arn = click.prompt('Please provide your default role arn')
    duration_seconds = click.prompt('Please provide the duration in seconds of the sts token', default=3600, type=int)
    data = {
        'idpid':idp_id,
        'spid': sp_id,
        'region': aws_region,
        'principal': principal_arn,
        'role': role_arn,
        'duration_seconds':duration_seconds
    }
    if click.confirm('Do you want to provide a default username?'):
        username = click.prompt('Please enter your default username')
        data['username'] = username
    if click.confirm('Do your want to enable MFA tokens?'):
        mfa_token = True
    else:
        mfa_token = None

    data['mfa'] = mfa_token
    config[name] = data
    config.save()

@cli.command('login')
@pass_config
@click.option('--mfa', '-m', is_flag=True, help="Enables MFA if disabled in default configuration")
@click.option('--username', '-u', help="Allows overriding of the stored username")
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
@click.option('--idp', '-i', help="Allows overrideing of the IDP id")
@click.option('--sp', '-s', help="Allows overriding of the store SP id ")
@click.option('--principal','-a', help='Allows overriding of the store principal')
@click.option('--role', '-r', help='Allows overriding of the stored role ARN')
@click.option('--region', help='Allows changing the aws region by overriding default stored value')
@click.option('--env', '-e', help="Environment name given during setup")
@click.option('--duration', '-d', help="override stored duration for creds from sts")
def login(config, mfa, username, password, idp, sp, principal, role, region, env, duration):

    if env is None:
        click.echo("Loading Default config")
        data = config['default']
    else:
        data = config[env]

    if mfa or data['mfa']:
        mfa = click.prompt('Please enter MFA Token')
    else:
        mfa = None

    if 'username' in data:
        username = data.get('username')
    else:
        username = click.prompt('Please Enter your username')


    if region is not None:
        aws_region = region
    else:
        aws_region = data['region']

    if principal is not None:
        aws_principal = principal
    else:
        aws_principal = data['principal']

    if role is not None:
        aws_role = role
    else:
        aws_role = data['role']

    if idp is not None:
        google_idp = idp
    else:
        google_idp = data['idpid']

    if sp is not None:
        aws_sp = sp
    else:
        aws_sp = data['spid']

    if duration is not None:
        duration_seconds = duration
    else:
        duration_seconds = data['duration_seconds']

    k = generate_keys(
        {'username': username,
         'password': password,
         'mfa_code': mfa,
         'role': aws_role,
         'principal': aws_principal,
         'idpid': google_idp,
         'spid': aws_sp,
         'region': aws_region,
         'duration': duration_seconds
        },
        {}
    )

    click.echo('export AWS_ACCESS_KEY=\'' + k['aws']['access_key'].encode('utf-8') + '\'')
    click.echo('export AWS_SECRET_ACCESS_KEY=\'' + k['aws']['secret_key'].encode('utf-8') +'\'')
    click.echo('export AWS_SESSION_TOKEN=\'' + k['aws']['session_token'].encode('utf-8') + '\'')
