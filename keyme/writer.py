import os
import shutil

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser

DEFAULT_REGION = 'us-east-1'
DEFAULT_OUTPUT_TYPE = 'json'


def create_backup(source_path):
    """
    Creates a backup copy of the specified file in the same location but with
    a backup extension.
    """

    backup_path = '{}.keyme.backup'.format(source_path)
    try:
        if os.path.exists(backup_path):
            os.remove(backup_path)
        shutil.copy2(source_path, backup_path)
        return True
    except Exception:
        return False


def write_credentials_file(profile_name, access_key, secret_key, session_token):
    """
    Writes the specified AWS credentials to the standard aws credentials
    file in the user's home directory.

    :param profile_name:
        The name of the profile for which the credentials will be written.
    :param access_key:
        The "aws_access_key_id" value for the specified profile.
    :param secret_key:
        The "aws_secret_access_key" value for the specified profile.
    :param session_token:
        The "aws_session_token" value for the specified profile.
    :return:
        A dictionary representation of the contents of the config file after
        it has been modified by this function.
    """

    credentials_path = os.path.expanduser('~/.aws/credentials')
    credentials = ConfigParser()

    if os.path.exists(credentials_path):
        credentials.read(credentials_path)

    credentials[profile_name] = dict(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )

    create_backup(credentials_path)
    with open(credentials_path, 'w') as fp:
        credentials.write(fp)

    return dict(credentials.items())


def write_config_file(
        profile_name,
        default_region=DEFAULT_REGION,
        output_type=DEFAULT_OUTPUT_TYPE,
        enable_s3v4=False
):
    """
    Write an AWS config file for the specified profile, which includes
    information about region, output type and other session configuration
    data.

    :param profile_name:
        The name of the profile for which the config settings will be written.
    :param default_region:
        The default AWS region for the profile.
    :param output_type:
        The default data type returned by console commands for this profile.
    :param enable_s3v4:
        Whether or not to enable signature version 4 when interacting with
        S3 data encrypted by KMS.
    :return:
        A dictionary representation of the contents of the config file after
        it has been modified by this function.
    """

    configs_path = os.path.expanduser('~/.aws/config')
    configs = ConfigParser()

    if os.path.exists(configs_path):
        configs.read(configs_path)

    profile_key = 'profile {}'.format(profile_name)
    if profile_key not in configs:
        configs[profile_key] = {}
    config_data = configs[profile_key]
    config_data['region'] = default_region or DEFAULT_REGION
    config_data['output'] = output_type or DEFAULT_OUTPUT_TYPE

    if enable_s3v4:
        config_data['s3'] = '\nsignature_version = s3v4'
    elif 's3' in config_data:
        del config_data['s3']

    create_backup(configs_path)
    with open(configs_path, 'w') as fp:
        configs.write(fp)

    return dict(configs.items())
