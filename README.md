## Sensu-Plugins-Vault

## Functionality

Checks for the validity of tokens in vault server through API.

## Files
  * bin/check-vault-tokens.py

## Installation

`check-vault-tokens` plugin make use of vault accessors to get information about indiviual tokens.
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

Once the token is generated, create a config file under `/etc/sensu/conf.d` with the following content, replacing `token` and `api_address` with your own configuration:

```{
{
  "vault_config": {
    "token": "abcdea4-2543f-b12543-01221-f721fab128cdd",
    "api_address": "https://<vault-api>:8086",
  }
} 
```


## Usage

Create a check file in `/etc/sensu/conf.d`,

```
{
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


| Flag            | usage          | 
| ---             | ---            |
| -c, --critical     | trigger critical alert when any token is expiring in this number of days. Default is 10 | 
| -v, --verify       | Either a boolean, in which case it controls whether to verify the server's TLS, or a string, in which case it must be a path to a CA bundle in pem format. Defaults to True. |
| -t, --timeout      | seconds to wait for the server to send data before giving up. Default is 30. |  
| -i, --ignore       | token with these prefix will be ignored. For example, for example -i ldap- -i auth- (must include `-`)|                        
