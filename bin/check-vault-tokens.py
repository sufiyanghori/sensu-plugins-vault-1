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
#     # RED
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
      required=True,
      type=int,
      help='trigger critical alert when any token is expiring in this number of days'
      )

    self.parser.add_argument(
      "-v",
      "--verify",
      required=False,
      default="True",
      help='Either a boolean, in which case it controls whether to verify the server\'s TLS, or a string, in which case it must be a path to a CA bundle to use. Defaults to True.'
      )

    self.parser.add_argument(
      "-t",
      "--timeout",
      required=False,
      default=None,
      help='How many seconds to wait for the server to send data before giving up'
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
        verify=verify_flag()
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
          verify=verify_flag()
        ).json()

      # ignore tokens that never expires, and those which is issued to ldap users autmatically
      if get_accessor_details['data']['expire_time'] is not None and get_accessor_details['data']['display_name'][:4] != 'ldap' :
        
        str_to_date = dateutil.parser.parse(get_accessor_details['data']['expire_time'])
        days_left = str_to_date.date() - today
        tokens_dict['days_left'] = days_left.days
        tokens_dict['name'] = get_accessor_details['data']['display_name']

        if '-' not in tokens_dict['name']:
          tokens_dict['name'] = tokens_dict['name'] + "-" + get_accessor_details['data']['accessor'][:7]
    
        if days_left.days >= THRESHOLD_CRITICAL:
          tokens_ok.append(tokens_dict.copy())
        else:
          tokens_critical.append(tokens_dict.copy())
    
    if tokens_critical:
      for token in tokens_critical:
        print (token['name'] + " expiring in " + str(token['days_left']) + " day(s)," )
      sys.exit(2)
    else:
      for token in tokens_ok:
        print (token['name'] + " expiring in " + str(token['days_left']) + " day(s)," )
      sys.exit(0)

if __name__ == "__main__":
  f = VaultTokenExpire()
