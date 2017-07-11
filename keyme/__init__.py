#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import sys

from six.moves.urllib.parse import urlencode
import boto3
import requests
from bs4 import BeautifulSoup


class KeyMe:
    def __init__(self, **kwargs):
        """Initialise an Alky object

        Keyword Arguments:
        username -- username **with fqdn** to login with
        password -- corresponding password
        """
        self.username = kwargs.pop('username')
        self.password = kwargs.pop('password')
        self.mfa_code = kwargs.pop('mfa_code')
        self.role = kwargs.pop('role')
        self.principal = kwargs.pop('principal')
        self.session = None
        self.sts = None

        self.region = kwargs.pop('region')
        self.idp = kwargs.pop('idp')
        self.sp = kwargs.pop('sp')
        if kwargs.get('duration_seconds'):
            self.timeout = kwargs.pop('duration_seconds')
        else:
            self.duration_seconds = 3600

        self.google_accounts_url = self.idp_entry_url
        if kwargs:
            raise ValueError("Extraneous keys passed: %s" % kwargs.keys())

    @property
    def idp_entry_url(self):
        """Returns the SAML SSO init URL populated with IDP & SP parameters"""
        url = 'https://accounts.google.com/o/saml2/initsso'
        url_params = dict(
            idpid=self.idp or '',
            spid=self.sp or '',
            forceauthn='false'
        )
        return '{}?{}'.format(url, urlencode(url_params))

    def key(self):
        """Return a key object"""
        self.session = self.login_to_google()
        self.sts = self.login_to_sts(self.region)

        saml = self.parse_google_saml()

        (
            access_key,
            secret_key,
            session_token,
            expiration
        ) = self.get_tokens(saml, self.role, self.principal)

        return {
            'aws': {
                'access_key': access_key,
                'secret_key': secret_key,
                'session_token': session_token
            },
            'expiration': expiration
        }

#    def login_to_google(self, idpid, spid, email, password, mfapin):
    def login_to_google(self):
        # Initiate session handler
        session = requests.Session()

        # Configure Session Headers
        session.headers['User-Agent'] = 'AWS Sign-in'

        # Initial Page load
        google_session = session.get(self.idp_entry_url)
        google_session.raise_for_status()
        session.headers['Referrer'] = google_session.url

        # Collect information from the page source
        decoded = BeautifulSoup(google_session.text, 'html.parser')
        gxf = decoded.find('input', {'name': 'gxf'}).get('value')
        cont = decoded.find('input', {'name': 'continue'}).get('value')
        page = decoded.find('input', {'name': 'Page'}).get('value')
        sign_in = decoded.find('input', {'name': 'signIn'}).get('value')
        account_login_url = (
            decoded
            .find('form', {'id': 'gaia_loginform'})
            .get('action')
        )

        # Setup the payload
        payload = {
            'Page': page,
            'gxf': gxf,
            'continue': cont,
            'ltmpl': 'popup',
            'scc': 1,
            'sarp': 1,
            'oauth': 1,
            'ProfileInformation': '',
            'SessionState': '',
            '_utf8': '?',
            'bgresponse': 'js_disabled',
            'pstMsg': 0,
            'checkConnection': '',
            'checkedDomains': 'youtube',
            'Email': self.username,
            'identifiertoken': '',
            'identifiertoken_audio': '',
            'identifier-captcha-input': '',
            'signIn': sign_in,
            'Passwd': '',
            'PersistentCookie': 'yes',
        }

        # POST to account login info page, to collect profile and session info
        google_session = session.post(account_login_url, data=payload)
        google_session.raise_for_status()
        session.headers['Referrer'] = google_session.url

        # Collect ProfileInformation, SessionState, signIn, and Password
        # Challenge URL
        decoded = BeautifulSoup(google_session.text, 'html.parser')

        profile_information = (
            decoded
            .find('input', {'name': 'ProfileInformation'})
            .get('value')
        )
        session_state = (
            decoded
            .find('input', {'name': 'SessionState'})
            .get('value')
        )
        sign_in = decoded.find('input', {'name': 'signIn'}).get('value')
        passwd_challenge_url = (
            decoded
            .find('form', {'id': 'gaia_loginform'})
            .get('action')
        )

        # Update the payload
        payload['SessionState'] = session_state
        payload['ProfileInformation'] = profile_information
        payload['signIn'] = sign_in
        payload['Passwd'] = self.password

        # POST to Authenticate Password
        google_session = session.post(passwd_challenge_url, data=payload)
        google_session.raise_for_status()
        decoded = BeautifulSoup(google_session.text, 'html.parser')
        error = decoded.find(class_='error-msg')
        cap = decoded.find('input', {'name': 'logincaptcha'})
        if error is not None or cap is not None:
            try:
                raise ValueError(
                    'Wrong Password or Captcha Required. '
                    'Manually Login to remove this.'
                )
            except ValueError as e:
                print(e)
                sys.exit(1)

        session.headers['Referrer'] = google_session.url
        if self.mfa_code is not None:
            # Collect the TL, and Updated gxf
            decoded = BeautifulSoup(google_session.text, 'html.parser')
            tl = decoded.find('input', {'name': 'TL'}).get('value')
            gxf = decoded.find('input', {'name': 'gxf'}).get('value')

            # Dynamically configure TOTP URL and ID based upon the session url
            challenge_url = google_session.url.split("?")[0]
            challenge_id = challenge_url.split("totp/")[1]

            # Create a new payload
            payload = {
                'challengeId': challenge_id,
                'challengeType': 6,
                'continue': cont,
                'scc': 1,
                'sarp': 1,
                'checkedDomains': 'youtube',
                'pstMsg': 0,
                'TL': tl,
                'gxf': gxf,
                'Pin': self.mfa_code,
                'TrustDevice': 'on',
            }
            # Submit TOTP
            google_session = session.post(challenge_url, data=payload)
            google_session.raise_for_status()

        return google_session

    def parse_google_saml(self):
        """Load and parse saml from google"""
        parsed = BeautifulSoup(self.session.text, 'html.parser')
        saml_element = (
            parsed
            .find('input', {'name': 'SAMLResponse'})
            .get('value')
        )

        try:
            if not saml_element:
                raise Exception(
                    'Could not get a SAML reponse, check credentials'
                )
        except Exception as e:
            print(e)
            sys.exit(1)

        return saml_element

    @staticmethod
    def login_to_sts(region):
        """Create an STS context via STS"""
        return boto3.client('sts',region_name=region)

    def get_tokens(self, saml, role, principal):
        """Load and parse tokes from AWS STS"""
        token = self.sts.assume_role_with_saml(
            RoleArn=role,
            PrincipalArn=principal,
            SAMLAssertion=saml,
            DurationSeconds=self.duration_seconds
        )
        credentials = token['Credentials']

        return (
            credentials['AccessKeyId'],
            credentials['SecretAccessKey'],
            credentials['SessionToken'],
            credentials['Expiration']
        )
