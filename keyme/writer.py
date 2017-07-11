import os
import shutil
import six


try:
    from io import StringIO
    import configparser
    from configparser import ConfigParser
except ImportError:
    from StringIO import StringIO
    import ConfigParser as configparser
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


def add_section(config, section_name):
    """
    Adds a section to the config, which gets around the convention difference
    in default naming between ConfigParser and AWS credential files. Does
    nothing if the section already exists.

    :param config:
        The config parser you want to add a section to
    :param section_name:
        The name of the section to add
    """

    if config.has_section(section_name):
        return config

    if section_name == 'default':
        config.readfp(StringIO('[default]'))
    else:
        config.add_section(section_name)

    return config


def add_options(config, section_name, options):
    """
    Adds a dictionary of options to the config parser object in the given
    section.

    :param config:
        The config parser to modify with the specified options
    :param section_name:
        The section where the options should be stored
    :param options:
        A dictionary containing the options to set
    :return:
        The modified config parser
    """

    add_section(config, section_name or 'default')

    for key, value in six.iteritems(options):
        config.set(section_name, key, '{}'.format(value))

    return config


def configs_to_dict(configs):
    """
    Converts a config parser object into a dictionary.

    :param configs:
        The config parser instance to convert into a dictionary.
    :return:
        A dictionary representation of the config parser.
    """

    out = {}
    for section in configs.sections():
        out[section] = dict(configs.items(section))

    return out


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

    credentials = add_options(credentials, profile_name, dict(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    ))

    create_backup(credentials_path)
    with open(credentials_path, 'w') as fp:
        credentials.write(fp)

    return configs_to_dict(credentials)


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
    add_options(configs, profile_key, dict(
        region=default_region or DEFAULT_REGION,
        output=output_type or DEFAULT_OUTPUT_TYPE
    ))

    if enable_s3v4:
        configs.set(profile_key, 's3', '\nsignature_version = s3v4')
    elif configs.has_option(profile_key, 's3'):
        configs.remove_option(profile_key, 's3')

    create_backup(configs_path)
    with open(configs_path, 'w') as fp:
        configs.write(fp)

    return configs_to_dict(configs)
