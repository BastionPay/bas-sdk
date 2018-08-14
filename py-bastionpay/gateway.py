#! /usr/bin/python
# -*- coding: UTF-8 -*-

import time
import base64
import rsa
import hashlib
import OpenSSL
import json
import urllib2
import sys
import chardet

# Copyright (C) 2018-08-15 ......
# Author: pingzilao
# Email: pingzilao@qq.com

userPubPemName = "public_rsa.pem"
userPriPemName = "private_rsa.pem"
BastionpayPubPemName = "bastionpay_public.pem"
httpApi = "api"
RsaBits1024 = 1024
RsaBits2048 = 2048
RsaEncodeLimit1024 = RsaBits1024 / 8 - 11
RsaDecodeLimit1024 = RsaBits1024 / 8
RsaEncodeLimit2048 = RsaBits2048 / 8 - 11
RsaDecodeLimit2048 = RsaBits2048 / 8
 
class BastionpaySdk:
   'host为bastionpay地址，pemPath为秘钥文件路径'
   def __init__(self,userKey, host, pemPath):
       self.userKey = userKey
       self.host = host
       self.pemPath = pemPath
       self._loadPemKeys(pemPath.rstrip("/"))

   def CallApi(self, message, path):
       req = self._encodeReq(message)
       reqJson = json.dumps(req)
       resJson = self._callToHttpServer(path, reqJson)
       res = json.loads(resJson)
       if res["err"] != 0:
           return "", res["err"], res["errmsg"]
       #print res["err"], res["errmsg"]
       resmsg = self._decodeRes(res["value"])
       return resmsg, res["err"], res["errmsg"]
       
       #这里注意RSA PublicKey就用load_pkcs1
   def _loadPemKeys(self, pemPath):
       #f1 = open(pemPath + "/" +userPubPemName, "rb")
       #self.userPubKey = rsa.PublicKey.load_pkcs1_openssl_pem((f1.read()))
       #f1.close()
       #print pemPath + "/" +BastionpayPubPemName
       f2 = open(pemPath + "/" +BastionpayPubPemName, "rb")
       self.bastionpayPubKey = rsa.PublicKey.load_pkcs1_openssl_pem((f2.read()))
       f2.close()
       f3 = open(pemPath + "/" +userPriPemName, "rb")
       self.userPriKey = rsa.PrivateKey.load_pkcs1((f3.read()))
       f3.close()
       print "loadPemKeys ok "
      

   def _callToHttpServer(self, path, body):
       url = self.host + "/"+httpApi + path
       headers = {'contentType' : "application/json;charset=utf-8" } 
       req = urllib2.Request(url, body, headers) 
       response = urllib2.urlopen(req) 
       the_page = response.read() 
       return  the_page

   def _encodeReq(self, message):
       timestamp = str(int(time.time()))
       bencrypted = self._RsaEncrypt(message, self.bastionpayPubKey, RsaEncodeLimit2048)
       base64Msg = base64.b64encode(bencrypted)
       sign = self._RsaSign('SHA-512', bencrypted,timestamp, self.userPriKey)
       base64Sign = base64.b64encode(sign)
       usrData = {"user_key":self.userKey, "message":base64Msg, "signature":base64Sign, "time_stamp":timestamp}
       return usrData

   def _decodeRes(self, usrData):
       base64Msg = usrData["message"]
       base64Sign = usrData["signature"]
       timestamp = usrData["time_stamp"]
       encryptMsg = base64.b64decode(base64Msg)
       sign = base64.b64decode(base64Sign)
       ok = self._SignVerify('SHA-512', encryptMsg,timestamp, sign, self.bastionpayPubKey)
       if not ok:
           return False
       return self._RsaDecrypt(encryptMsg, self.userPriKey, RsaDecodeLimit2048)


   def _RsaEncrypt(self, originData, pubKey, limit):
        list = []
        startIndex = endIndex =0
        length = len(originData)
        while (startIndex < length):
            if startIndex + limit < length:
                endIndex = startIndex + limit
            else:
                endIndex = length       
            list.append(rsa.pkcs1.encrypt(originData[startIndex:endIndex], pubKey))
            startIndex = endIndex
        return "".join(list)

   def _RsaDecrypt(self, cipherData, priKey, limit):
        list = []
        startIndex = endIndex =0
        length = len(cipherData)
        while (startIndex < length):
            if startIndex + limit < length:
                endIndex = startIndex + limit
            else:
                endIndex = length       
            list.append(rsa.pkcs1.decrypt(cipherData[startIndex:endIndex], priKey))
            startIndex = endIndex
        return "".join(list)

   def _RsaSign(self, hashfunc, data,timestamp, priKey):
        dg = data + timestamp
        sign =  rsa.sign(dg, priKey, hashfunc) #这个函数包含 生成摘要的功能
        return sign

   def _SignVerify(self, hashfunc, encryptData,timestamp, signData, pubKey):
        dg = encryptData + timestamp.encode("ascii") 
        return rsa.pkcs1.verify(dg ,signData, pubKey) #内部生成摘要
     
   

if __name__=="__main__":
    sdk = BastionpaySdk("5b695d56-2e84-4456-ac24-cdfe96f646d0", "http://127.0.0.1:8082", "./pem")
    resmsg, err, errmsg = sdk.CallApi("nihao", "/v1/account/getaudite")
    print(resmsg, err, errmsg)