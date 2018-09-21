#!/usr/bin/env python 

from __future__ import print_function
from sensu_plugin import SensuPluginCheck
from collections import namedtuple
from sensu_plugin import utils
from OpenSSL import crypto
import requests
import json
import argparse
import datetime


class VaultCertExpire(SensuPluginCheck):

  def setup(self):

    self.parser.add_argument(
      "-w",
      "--warn",
      required=False,
      default=10,
      type=int,
      help='warn will be triggered if these number of days are left to expire'
      )

    self.parser.add_argument(
     "-c",
     "--critical",
     required=False,
     default=5,
     type=int,
     help='critical will be triggered if certificates have been expired + these number of days are left to expire. Default is 5'
     )

    self.parser.add_argument(
     "-t",
     "--timeout",
     required=False,
     type=float,
     default=40,
     help='seconds to wait for the server to send data before giving up. Default is 30'
     )
  

    self.parser.add_argument(
      "-v",
      "--verify",
      required=False,
      default="True",
      help='Either a boolean, in which case it controls whether to verify the server\'s TLS, or a string, in which case it must be a path to a CA bundle in pem format. Defaults to True.'
      )
    
  def run(self):

    self.check_name('vault_cert_expire')

    def verify_flag():
      flag = {'true': True, 'false': False}
      if self.options.verify.lower() in flag:
        return flag[self.options.verify.lower()]
      else:
        return self.options.verify

    read_config = utils.get_settings()['vault_config']

    vault_conf = namedtuple('VaultConf', ['url', 'auth_token', 'role'])
    vault_conf.url = read_config['api_address']
    vault_conf.auth_token = read_config['token']
    vault_conf.role = read_config['pki_engine']

    THRESHOLD_CRITICAL = self.options.critical
    THRESHOLD_WARN = self.options.warn
    
    API_HEADER = {
        'x-vault-token': vault_conf.auth_token, 
        'content-type': "application/json"
      }

    certs_api = "{}/v1/{}/certs?list=true".format(vault_conf.url, vault_conf.role)
    cert_serials = requests.request(
        "GET", 
        certs_api, 
        headers=API_HEADER,
        verify=verify_flag(),
        timeout=self.options.timeout
        ).json()

    list_serials = cert_serials['data']['keys']

    def days_left(asn1_time):
      today = datetime.datetime.today()
      date_time = asn1_time
      dformat =  "%Y%m%d%H%M%S"
      date_time = datetime.datetime.strptime(date_time,  dformat)
      days_left = date_time-today
      return days_left.days

    cert_warn = []
    cert_critical = []
    cert_dict = {}

    for serial in list_serials:
      cert_url = "{}/v1/{}/cert/{}".format(vault_conf.url, vault_conf.role, serial)
      
      cert_body = requests.request(
          "GET", 
          cert_url, 
          headers=API_HEADER,
          verify=verify_flag(),
          timeout=self.options.timeout
          ).json()['data']['certificate']

      cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_body)
      cert_dict['days_left'] = days_left(cert.get_notAfter()[:-1])
      cert_dict['name'] = crypto.X509Name(cert.get_subject()).CN

      """
      No point of checking OK certs if critical and warn exist
      """
      if cert_dict['days_left'] <= THRESHOLD_CRITICAL:
        cert_critical.append(cert_dict.copy())
      elif cert_dict['days_left'] > THRESHOLD_CRITICAL and cert_dict['days_left'] <= THRESHOLD_WARN:
        cert_warn.append(cert_dict.copy())

    message = [] 
    if cert_critical:
      for cert in cert_critical:
        if cert['days_left'] < 1:
          message.append("{} expired {} days ago,".format(cert['name'], str(abs(cert['days_left'] ))))
        else:
          message.append("{} expiring in {} days,".format(cert['name'], str(cert['days_left'])))
      self.critical('\n'.join(message))
    elif cert_warn:
      for cert in cert_warn:
          message.append("{} expiring in {} days,".format(cert['name'], str(cert['days_left'])))
      self.warning('\n'.join(message))

    else:
      self.ok("All certs are good!")

    
if __name__ == "__main__":
    f = VaultCertExpire()
