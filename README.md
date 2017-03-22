# KeyMe, a Google SAML to AWS STS connector.

This library allows Google's SAML based federation to use Amazon Web Services’ Security Token Service (STS) for authorization against AWS resources. 

## To use
Install the PIP package:
```
$ pip install keyme
```

Once installed, import:
```
from keyme import KeyMe
```

Example usage:

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
    # - that's logic we shouldn't be doing there
    return KeyMe(username=username,
                password=password,
                mfa_code=mfa_code,
                idp=idp,
                sp=sp,
                region=region,
                role=role,
                principal=principal).key()

```

The `generate_keys` function above will return a JSON payload containing your temporary AWS access credentials. 


# fetch_creds
We have also included a `fetch_creds` command line tool.

Usage:
```
$ fetch_creds
```

