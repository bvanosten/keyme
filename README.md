# Google SAML STS

This library allows for one to get STS tokens from AWS when you use Google SAML on your G Suite Account.

## To use
Install the PIP package by doing

```
pip install keyme
```

Once that is installed then all you need to do is import KeyMe from keyme. Example of how to use this see below:

```
def generate_keys(event, context):
    username = event.get('username')
    password = event.get('password')
    mfa_code = event.get('mfa_code')

    region = event.get('region', 'us-east-1')

    # The following, we expect, to come from $stageVariables
    idp = event.get('idp', '<idp_google_value>')
    sp  = event.get('sp', '<sp_id_from_aws>')
    role = event.get('role', 'arn:aws:iam::<account_number>:<role>')
    principal = event.get('principal', 'arn:aws:iam::<account_number>:saml-provider/GoogleAppsProvider')

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

```

This function will get return you json value with your STS creds if your login is valid.


# fetch_creds
So we have included a fetch_creds cli tool for you use sts keys with saml much easier and with out pain.
