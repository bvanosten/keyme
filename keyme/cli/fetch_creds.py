#!/usr/bin/env python

import json
import os
import sys
import textwrap

import click

from keyme import KeyMe
from keyme import writer


class Config(writer.ConfigParser):
    def __init__(self, path='~/.aws/keyme', *args, **kwargs):
        writer.ConfigParser.__init__(self, *args, **kwargs)
        self._path = path

    def load(self):
        path = os.path.expanduser(self._path)
        if os.path.exists(path):
            self.read(path)

    def save(self):
        path = os.path.expanduser(self._path)

        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path))

        with open(path, 'w') as fp:
            self.write(fp)


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
    return KeyMe(
        username=username,
        password=password,
        mfa_code=mfa_code,
        idp=idp,
        sp=sp,
        region=region,
        role=role,
        principal=principal
    ).key()


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
@click.option('--update', help='update configuration for given env name')
def setup(config, update):
    """
    Creates a KeyMe environment populated with the settings necessary for
    subsequent login actions with that environment.

    :param config:
        The configuration parser where the environment data will be stored.
    :param update:
        The name of the environment that will be populated. If omitted, the
        "default" environment is used.
    """

    if not config.has_section(update):
        name = click.prompt(
            'Please enter a name for this config',
            default='default'
        )
    else:
        name = update

    idp_id = click.prompt('Please enter your google idp id')
    sp_id = click.prompt('Please enter your aws sp id')
    aws_region = click.prompt(
        'Which AWS Region do you want to be default?',
        default='us-east-1'
    )
    principal_arn = click.prompt('Please provide your default principal ARN')
    role_arn = click.prompt('Please provide your default role arn')
    duration_seconds = click.prompt(
        'Please provide the duration in seconds of the sts token',
        default=3600,
        type=int
    )

    use_mfa = click.confirm('Enable MFA tokens?')
    use_s3v4 = click.confirm('Enable S3 signature version 4?')

    writer.add_options(config, name, dict(
        idpid=idp_id,
        spid=sp_id,
        region=aws_region,
        principal=principal_arn,
        role=role_arn,
        duration_seconds=duration_seconds,
        mfa='yes' if use_mfa else 'no',
        s3v4='yes' if use_s3v4 else 'no'
    ))

    config.save()


@cli.command('login')
@pass_config
@click.option(
    '--mfa', '-m',
    is_flag=True,
    help='Enables MFA if disabled in default configuration'
)
@click.option(
    '--s3v4',
    is_flag=True,
    help='Enables S3 signature version 4. Only applicable with the save flag'
)
@click.option('--username', prompt='Please Enter your user name')
@click.option(
    '--password',
    prompt='Please enter your password',
    hide_input=True
)
@click.option('--idp', '-i', help='Allows overriding of the IDP id')
@click.option('--sp', '-s', help='Allows overriding of the store SP id ')
@click.option(
    '--principal','-a',
    help='Allows overriding of the store principal'
)
@click.option('--role', '-r', help='Allows overriding of the stored role ARN')
@click.option(
    '--region',
    help='Allows changing the aws region by overriding default stored value'
)
@click.option('--env', '-e', help='Environment name given during setup')
@click.option(
    '--duration', '-d',
    help='override stored duration for creds from sts'
)
@click.option(
    '--save',
    is_flag=True,
    help='Write the credentials to the standard AWS configuration files'
)
def login(
        config,
        username,
        password,
        mfa,
        duration,
        idp,
        sp,
        principal,
        role,
        region,
        env,
        save,
        s3v4
):

    profile_name = env or 'default'
    if not config.has_section(profile_name):
        click.echo(textwrap.dedent(
            """
            Login failed. The "{}" KeyMe profile is not 
            initialized. Please run the fetch_creds init command 
            first to create this profile or specify a different 
            profile with the --env flag.
            """.format(env or 'default')
        ))
        sys.exit(1)

    if mfa or config.getboolean(profile_name, 'mfa'):
        mfa = click.prompt('Please enter MFA Token')
    else:
        mfa = None

    click.echo('Loading "{}" config'.format(env or 'default'))

    payload = {
        'username': username,
        'password': password,
        'mfa_code': mfa,
        'role': role or config.get(profile_name, 'role'),
        'principal': principal or config.get(profile_name, 'principal'),
        'idpid': idp or config.get(profile_name, 'idpid'),
        'spid': sp or config.get(profile_name, 'spid'),
        'region': region or config.get(profile_name, 'region'),
        'duration': duration or config.get(profile_name, 'duration_seconds')
    }
    k = generate_keys(payload, {})
    aws = k['aws']

    if save:
        writer.write_credentials_file(env, **aws)
        writer.write_config_file(
            profile_name=env,
            default_region=region,
            enable_s3v4=s3v4 or config.getboolean(profile_name, 's3v4')
        )

    click.echo('export AWS_ACCESS_KEY_ID=\'%(access_key)s\'' % aws)
    click.echo('export AWS_SECRET_ACCESS_KEY=\'%(secret_key)s\'' % aws)
    click.echo('export AWS_SESSION_TOKEN=\'%(session_token)s\'' % aws)
