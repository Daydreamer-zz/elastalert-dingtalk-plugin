#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
@author: xuyaoqiang
@contact: xuyaoqiang@gmail.com
@date: 2017-09-14 17:35
@version: 0.0.0
@license:
@copyright:
"""
from os import times
import time
import hmac
import hashlib
import base64
import urllib.parse
import json
import requests
from elastalert.alerts import Alerter, DateTimeEncoder
from requests.exceptions import RequestException
from elastalert.util import EAException


class DingTalkAlerter(Alerter):
    
    required_options = frozenset(['dingtalk_webhook', 'dingtalk_msgtype'])

    def __init__(self, rule):
        super(DingTalkAlerter, self).__init__(rule)
        self.dingtalk_webhook_url = self.rule['dingtalk_webhook']
        self.dingtalk_msgtype = self.rule.get('dingtalk_msgtype', 'text')
        self.dingtalk_isAtAll = self.rule.get('dingtalk_isAtAll', False)
        self.dingtalk_title = self.rule.get('dingtalk_title', '')
        self.dingtalk_secret = self.rule.get('dingtalk_secret', '')

    def format_body(self, body):
        return body.encode('utf8')
    
    def alert(self, matches):
        if len(self.dingtalk_secret) > 10:
            timestamp, sign = self.get_secret()
            fix_dingtalk_webhook_url = self.dingtalk_webhook_url + f"&timestamp={timestamp}&sign={sign}"
        else:
            fix_dingtalk_webhook_url  = self.dingtalk_webhook_url
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json;charset=utf-8"
        }
        body = self.create_alert_body(matches)
        payload = {
            "msgtype": self.dingtalk_msgtype,
            "text": {
                "content": body
            },
            "at": {
                "isAtAll":False
            }
        }
        try:
            response = requests.post(fix_dingtalk_webhook_url, 
                        data=json.dumps(payload, cls=DateTimeEncoder),
                        headers=headers)
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error request to Dingtalk: {0}".format(str(e)))

    def get_info(self):
        return {
            "type": "dingtalk",
            "dingtalk_webhook": self.dingtalk_webhook_url
        }
        pass

    def get_secret(self):
        timestamp = str(round(time.time() * 1000))
        secret = self.dingtalk_secret
        secret_enc = secret.encode('utf-8')
        string_to_sign = '{}\n{}'.format(timestamp, secret)
        string_to_sign_enc = string_to_sign.encode('utf-8')
        hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
        return timestamp, sign
