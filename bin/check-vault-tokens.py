#!/usr/bin/env python 
#   check-vault-tokens
#
# DESCRIPTION:
# Check validity time of tokens using Vault API and report when tokens are expiring
#
# OUTPUT:
#   text
#
# PLATFORMS:
#   Linux, Windows, BSD, Solaris, etc
#
# DEPENDENCIES:
#   gem: sensu_plugin
#
# USAGE:
#
# NOTES:
#
# LICENSE:
#   Sufiyan Ghori  sufiyan@protonmail.com
#   Released under the same terms as Sensu (the MIT license); see LICENSE
#   for details.
#

from __future__ import print_function
from sensu_plugin import SensuPluginCheck
from sensu_plugin import utils
import requests
import sys
import json
import dateutil.parser
import datetime

class VaultTokenExpire(SensuPluginCheck):

  def setup(self):

    self.parser.add_argument(
      "-c",
      "--critical",
      required=False,
      type=int,
      default=10,
      help='trigger critical alert when any token is expiring in this number of days. Default is 10'
      )

    self.parser.add_argument(
      "-v",
      "--verify",
      required=False,
      default="True",
      help='Either a boolean, in which case it controls whether to verify the server\'s TLS, or a string, in which case it must be a path to a CA bundle in pem format. Defaults to True.'
      )

    self.parser.add_argument(
      "-t",
      "--timeout",
      required=False,
      type=float,
      default=30,
      help='seconds to wait for the server to send data before giving up. Default is 30'
      )

    self.parser.add_argument(
      "-i",
      "--ignore",
      required=False,
      action='append',
      default=[''],
      help='token with these prefix will be ignored. For example, -i ldap- -i certs-'
      )


  def run(self): 

    self.check_name('vault_token_expire')

    def verify_flag():
      flag = {'true': True, 'false': False}
      if self.options.verify.lower() in flag:
        return flag[self.options.verify.lower()]
      else:
        return self.options.verify
    
    read_config = utils.get_settings()['vault_config'] 

    """ 
    token must have sudo,list access to auth/token/accessors,
    and update access to auth/token/lookup-accessor
    """
    VAULT_AUTH_TOKEN = read_config['token']
    VAULT_SERVER = read_config['api_address']
    
    """
    number of days before critical is fired
    """
    THRESHOLD_CRITICAL = self.options.critical
    
    API_HEADER = {
        'x-vault-token': VAULT_AUTH_TOKEN, 
        'content-type': "application/json"
      }

    API_ENDPOINT = {
        "list_all_accessors": VAULT_SERVER + "/v1/auth/token/accessors", 
        "accessor_data": VAULT_SERVER + "/v1/auth/token/lookup-accessor"
      }

    """
    use auth/token/accessors endpoint to get a list of all accessors
    """
    read_accessors = requests.request(
        "LIST", 
        API_ENDPOINT['list_all_accessors'], 
        headers=API_HEADER,
        verify=verify_flag(),
        timeout=self.options.timeout
        ).json()
    

    get_accessors_keys = read_accessors['data']['keys']
    
    today = datetime.date.today()
    
    tokens_ok = []
    tokens_critical = []
    tokens_dict = {}
    payload = {}
    
    for accessor in get_accessors_keys:
      
      payload["accessor"] = accessor

      get_accessor_details = requests.request(
          "POST", 
          API_ENDPOINT['accessor_data'], 
          data=json.dumps(payload), 
          headers=API_HEADER,
          verify=verify_flag(),
          timeout=self.options.timeout
        ).json()

      """
      Check for each accessor, ignore token which has no ttl (token with root policy)
      
      """
      accessor_temp = get_accessor_details['data'] 
      if (accessor_temp['expire_time'] is None or
              accessor_temp['display_name'].split('-')[0] in self.options.ignore):
        continue
      else:
        str_to_date = dateutil.parser.parse(accessor_temp['expire_time'])
        days_left = str_to_date.date() - today
        tokens_dict['name'] = accessor_temp['display_name']
        tokens_dict['days_left'] = days_left.days

        """
        append first 7 characters of accessor to the token
        if token has no name. This will help identify the token
        """
        if tokens_dict['name'][:6] in 'token ':
            tokens_dict['name'] = tokens_dict['name'] + "-" + accessor_temp['accessor'][:7]
        
        if days_left.days <= THRESHOLD_CRITICAL:
          tokens_critical.append(tokens_dict.copy())
        else:
          tokens_ok.append(tokens_dict.copy())

    message = [] 
    if tokens_critical:
      for token in tokens_critical:
        message.append(token['name'] + " expiring in " + str(token['days_left']) + " day(s)," )
      self.critical('\n'.join(message))
    else:
      for token in tokens_ok:
        message.append(token['name'] + " expiring in " + str(token['days_left']) + " day(s)," )
      self.ok('\n'.join(message))

if __name__ == "__main__":
  f = VaultTokenExpire()
