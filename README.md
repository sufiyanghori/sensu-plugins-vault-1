## Sensu-Plugins-Vault

## Functionality

Check for validity of credentials and tokens for HashiCorp Vault's various [Auth Methods](https://www.vaultproject.io/docs/auth/index.html) and [Secret Engines](https://www.vaultproject.io/docs/secrets/index.html).

## Files
  * bin/check-vault-am-tokens.py
  * bin/check-vault-am-tokens.rb
  * bin/check-vault-se-pki.py
  * bin/check-vault-se-pki.rb

## Requirements

  * `sensu_plugin` python package is required to be installed for checks to work.
  * `pyOpenSSL` python package needs to be installed for `check-vault-se-pki` to work.


## Installation

#### check-vault-am-tokens
`check-vault-tokens` plugin make use of vault accessors to get information about indiviual tokens and then check for their expiry.
In order for it to work a token with following policies applied is required in vault, 

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

#### check-vault-se-pki

This check check for the validity of certificates issued by [PKI Secret Engine](https://www.vaultproject.io/docs/secrets/pki/index.html). For it to work, following policy must also be applied to a token,

```
path "<pki-engine-name>/certs/*"
{
  capabilities = ["list"]
}
```

---
Once the token is generated with above policies applied, create a config file under `/etc/sensu/conf.d` with the following content, replacing `token`, `api_address` and `pki_engine` (only required if you are using `check-vault-se-pki`) with your own configuration:

```{
{
  "vault_config": {
    "token": "abcdea4-2543f-b12543-01221-f721fab128cdd",
    "api_address": "https://<vault-api>:8086",
    "pki_engine": "<pki-engine-name>"
  }
} 
```


## Usage

#### check-vault-am-tokens

Create a check file in `/etc/sensu/conf.d`,

```
{
  "checks": {
    "vault_token_expiry": {
      "command": "<path-to-check>",
      "interval": 5,
      "subscribers": [
        "CentOS"
      ],
      "standalone": true
    }
  }
}
```


| Optional Flag            | Usage          | 
| ---             | ---            |
| -c, --critical     | trigger critical alert when any token is expiring in this number of days. Default is 10 | 
| -v, --verify       | Either a boolean, in which case it controls whether to verify the server's TLS, or a string, in which case it must be a path to a CA bundle in pem format. Defaults to True. |
| -t, --timeout      | Seconds to wait for the server to send data before giving up. Default is 30. |  
| -i, --ignore       | Token with these prefix will be ignored, for example `-i ldap- -i auth-` (- suffix required)|                        


#### check-vault-se-pki

Create a check file in `/etc/sensu/conf.d`,

```
{
  "checks": {
    "vault_token_expiry": {
      "command": "<path-to-check>",
      "interval": 5,
      "subscribers": [
        "CentOS"
      ],
      "standalone": true
    }
  }
}
```


| Optional Flag            | Usage          | 
| ---             | ---            |
| -c, --critical     | Critical will be triggered if certificates have been expired + these number of days are left to expire. Default is 5 | 
| -w, --warn         | Warn will be triggered if these number of days are left to expire. |
| -v, --verify       | Either a boolean, in which case it controls whether to verify the server's TLS, or a string, in which case it must be a path to a CA bundle in pem format. Defaults to True. |
| -t, --timeout      | Seconds to wait for the server to send data before giving up. Default is 40. |  
                   
