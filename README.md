## Sensu-Plugins-Vault

## Functionality

Checks for the validity of tokens in vault server through API.

## Files
  * bin/check-vault-tokens.py

## Installation

This plugin make use of vault accessors to get information about indiviual tokens.
In order for this to work a token with following policies applied is required in vault, 

```
path "auth/token/accessors/*"
{
  capabilities = ["sudo", "list"]
}

path "auth/token/lookup-accessor"
{
  capabilities = ["update"]
}
```

Once the token is generated, create a config file in `/etc/sensu/conf.d` with the following content, replacing `token` and `api_address` with your own configuration:

```{
{
  "vault_config": {
    "token": "abcdea4-2543f-b12543-01221-f721fab128cdd",
    "api_address": "https://<vault-api>:8086",
    "verify_ca": "True"
  }
} 
```

`verify_ca` (optional) Either a boolean, in which case it controls whether to verify the server’s TLS certificate, or a string, in which case it must be a path to a CA bundle to use. Defaults to True.


## Usage

Create a check file in `/etc/sensu/conf.d`,

```{
  "checks": {
    "vault_token_expiry": {
      "command": "/opt/sensu/embedded/bin/check-vault-tokens.py -c 15",
      "interval": 5,
      "subscribers": [
        "CentOS"
      ],
      "standalone": true
    }
  }
}
```

`-c` flag is used to set the threshold(in days). It triggers when any token is expiring in that number of days.
