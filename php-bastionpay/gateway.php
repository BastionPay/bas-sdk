<?php

namespace Gateway;

class Gateway {
    const   HOST = 'http://35.173.156.149:8082',
            USERKEY = '5b695d56-2e84-4456-ac24-cdfe96f646d0',
            KEYPATH = './pem',
            RSAENCODELIMITS2048 = 2048 / 8 - 11,
            RSADECODELIMITS2048 = 2048 / 8;

    private $userPubKey = null,
            $userPriKey = null,
            $servPubKey = null;

    public function __construct() {
//        $this->_getPublicKey(self::KEYPATH . '/public_rsa.pem');
        $this->_getPrivateKey(self::KEYPATH . '/private_rsa.pem');
        $this->_getServPublicKey(self::KEYPATH . '/bastionpay_public.pem');
    }

    /**
     * 生成签名
     *
     * @param string 签名材料
     * @param string 签名编码（base64/hex/bin）
     * @param integer $algo 签名算法
     * @return 签名值
     */
    public function sign($data, $code = 'base64', $algo = OPENSSL_ALGO_SHA512) {
        $ret = false;
        
        if (openssl_sign($data, $ret, $this->userPriKey, $algo)) {
            $ret = $this->_encode($ret, $code);
        }
        
        return $ret;
    }

    /**
     * 
     * @param type $data
     * @param type $sign
     * @param type $code
     * @return boolean
     */
    public function verify($data, $sign, $code = 'base64', $algo = OPENSSL_ALGO_SHA512) {
        $ret = false;
        $sign = $this->_decode($sign, $code);
        
        if ($sign !== false) {
            switch (openssl_verify($data, $sign, $this->servPubKey, $algo)) {
                case 1:
                    $ret = true;
                    break;
                case 0:
                case -1:
                default:
                    $ret = false;
            }
        }
        
        return $ret;
    }

    /**
     * 加密
     *
     * @param string 明文
     * @param string 密文编码（base64/hex/bin）
     * @param int 填充方式（貌似php有bug，所以目前仅支持OPENSSL_PKCS1_PADDING）
     * @return string 密文
     */
    public function encrypt($data, $code = 'base64', $padding = OPENSSL_PKCS1_PADDING) {
        $ret = false;
        
        if (!$this->_checkPadding($padding, 'en')) {
            $this->_error('padding error');
        }
        
        $orArr = str_split($data, self::RSAENCODELIMITS2048);
        $enStr = '';
        
        foreach ($orArr as $ov) {
            openssl_public_encrypt($ov, $result, $this->servPubKey, $padding);
            $enStr .= $result;
        }
        
       $ret = $this->_encode($enStr, $code);        
       return $ret;
    }
    
    /**
     * rsa加密签名
     * 
     * @param string $message 明文内容
     * @return json
     */
    public function signEncrypt($message){
        $timestamp = time();
        $enMessage = $this->encrypt($message);
        $enSign    = $this->sign($this->_decode($enMessage) . $timestamp);
        
        return json_encode(array(
            'user_key'      => self::USERKEY,
            'message'       => $enMessage,
            'time_stamp'    => (string)$timestamp,
            'signature'     => $enSign
        ));
    }

    /**
     * 解密
     *
     * @param json $sData signEncrypt加密的密文
     * @param string 密文编码（base64/hex/bin）
     * @param int 填充方式（OPENSSL_PKCS1_PADDING / OPENSSL_NO_PADDING）
     * @param bool 是否翻转明文（When passing Microsoft CryptoAPI-generated RSA cyphertext, revert the bytes in the block）
     * @return string 明文
     */
    public function decrypt($sData, $code = 'base64', $padding = OPENSSL_PKCS1_PADDING, $rev = false) {
        $ret        = false;
        $data       = $sData;
        $rsaData    = $this->_decode($data['message'], $code);
        
        if (!$this->_checkPadding($padding, 'de')) {
            $this->_error('padding error');
        }
        
        if (!$this->verify($rsaData . $data['time_stamp'], $data['signature'])) {
            $this->_error('sign verify error');
        }
        
        if ($rsaData !== false) {
            $orArr = str_split($rsaData, self::RSADECODELIMITS2048);
            $deStr = '';
            
            foreach ($orArr as $ov) {
                openssl_private_decrypt($ov, $result, $this->userPriKey, $padding);
                $deStr .= $result;
                
            }
            
            $ret = $rev ? rtrim(strrev($deStr), "\0") : '' . $deStr;
        }
        
        return $ret;
    }
    
    /**
     * http请求
     * 
     * @param string $url
     * @param array $data
     * @param string $method
     * @return mix
     */
    public function httpRequest($url, $data, $method = 'POST') {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array("Accept:application/json; Content-Type: application/json; charset=utf-8"));
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 3);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        if ($method == 'POST') {
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        } else {
            curl_setopt($ch, CURLOPT_URL, $url . '?' . http_build_query($data));
        }
        
        $ret = curl_exec($ch);
        $curlInfo = curl_getinfo($ch);
        $headerSize = $curlInfo['header_size'];
        curl_close($ch);
        
        return substr($ret, $headerSize);
    }
    
    /**
     * request stream
     * 
     * @param type $url
     * @param type $data
     * @param type $method
     * @return type
     */
    public function httpRequestStream($url, $data, $method = 'POST') {
        $opts = array('http' =>
            array(
                'method' => $method,
                'header' => 'Accept:application/json; Content-Type: application/json; charset=utf-8',
                'content' => $data
            )
        );
        
        $context = stream_context_create($opts);
        return file_get_contents($url, false, $context);
    }

    /**
     * 请求使用加密签名
     * 
     * @param string $message 发送的明文
     * @param string $uri 请求uri
     */
    public function sendData($message, $uri){
        $url = self::HOST . '/api/' . ltrim($uri, '/');
        $enData  = $this->signEncrypt($message);
        $httpRet = $this->httpRequest($url, $enData);
        
        if (!$httpRet) {
            $this->_error('sign http request error');
        }
        
        $httpRet = json_decode($httpRet, true);
        
        if ($httpRet['err'] != 0) {
            $this->_error(sprintf('sign http request error: %d, error message: %s', $httpRet['err'], $httpRet['errmsg']));
        }
        
        $rasDeData = $this->decrypt($httpRet['value']);
        
        return array(
            'response_data' => $httpRet,
            'decrypt_data'  => $rasDeData            
        );
    }

    /**
     * 获取文件内容
     * 
     * @param string $file 文件路径
     * @return mixed
     */
    private function _readFile($file) {
        $ret = false;

        if (!file_exists($file)) {
            $this->_error("The file {$file} is not exists");
        } else {
            $ret = file_get_contents($file);
        }

        return $ret;
    }

    /**
     * 设置用户公钥
     * 
     * @param string $file 文件路径
     */
    private function _getPublicKey($file) {
        $key_content = $this->_readFile($file);

        if ($key_content) {
            $this->userPubKey = openssl_get_publickey($key_content);
        }
    }

    /**
     * 设置用户私钥
     * 
     * @param string $file 文件路径
     */
    private function _getPrivateKey($file) {
        $key_content = $this->_readFile($file);

        if ($key_content) {
            $this->userPriKey = openssl_get_privatekey($key_content);
        }
    }
    
    /**
     * 设置服务端公钥
     * 
     * @param string $file 文件路径
     */    
    private function _getServPublicKey($file) {
        $key_content = $this->_readFile($file);

        if ($key_content) {
            $this->servPubKey = openssl_get_publickey($key_content);
        }
    }    
    
    /**
     * 检测填充类型
     * 加密只支持PKCS1_PADDING
     * 解密支持PKCS1_PADDING和NO_PADDING
     *
     * @param int 填充模式
     * @param string 加密en/解密de
     * @return bool
     */
    private function _checkPadding($padding, $type) {
        if ($type == 'en') {
            switch ($padding) {
                case OPENSSL_PKCS1_PADDING:
                    $ret = true;
                    break;
                default:
                    $ret = false;
            }
        } else {
            switch ($padding) {
                case OPENSSL_PKCS1_PADDING:
                case OPENSSL_NO_PADDING:
                    $ret = true;
                    break;
                default:
                    $ret = false;
            }
        }
        
        return $ret;
    }

    private function _encode($data, $code = 'base64') {
        switch (strtolower($code)) {
            case 'base64':
                $data = base64_encode('' . $data);
                break;
            case 'hex':
                $data = bin2hex($data);
                break;
            case 'bin':
            default:
        }
        
        return $data;
    }

    private function _decode($data, $code = 'base64') {
        switch (strtolower($code)) {
            case 'base64':
                $data = base64_decode($data);
                break;
            case 'hex':
                $data = $this->_hex2bin($data);
                break;
            case 'bin':
            default:
        }
        
        return $data;
    }

    private function _error($msg) {
        exit('RSA Error:' . $msg);
    }
    
    public function __destruct() {
        $this->servPubKey && openssl_free_key($this->servPubKey);
        $this->userPriKey && openssl_free_key($this->userPriKey);
        $this->userPubKey && openssl_free_key($this->userPubKey);
    }

}
