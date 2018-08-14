#include <iostream>
#include <string>
#include <openssl/rsa.h>
#include <memory>
#include <json/json.h>
#include <mutex>

//#pragma GCC diagnostic error "-Wundef -std=c++11"

namespace BastionPay{

const int CONST_ErrCode_OK = 0;              //成功
const int CONST_ErrCode_Err = 1;             //失败，包含业务错误
const int CONST_ErrCode_OpenFile = 2;        //文件打开失败
const int CONST_ErrCode_SHA512 = 3;          //摘要失败
const int CONST_ErrCode_SigVerify = 4;       //签名验证失败
const int CONST_ErrCode_RsaSign = 5;         //生成签名失败
const int CONST_ErrCode_RsaPriDecrypt = 6;   //rsa解密失败
const int CONST_ErrCode_RsaPubEncrypt = 7;   //rsa加密失败
const int CONST_ErrCode_JsonParse = 8;       //json解析失败
const int CONST_ErrCode_CurlInit = 9;        //curl初始化失败
const int CONST_ErrCode_CurlPerform = 10;    //curl网络请求失败
const int CONST_ErrCode_Base64Decode = 11;   //base64解码失败
const int CONST_ErrCode_Base64Encode = 12;   //base64编码失败


class Err {
public:
    Err(const int code, const std::string info):mCode(code),info(info) {}
    Err(const int code, const char* info):mCode(code),info(info) {}
    bool ok(){
        return this->mCode == 0;
    }
    int code(){ //错误码
        return this->mCode;
    }
    std::string what(){ //错误信息
        return info;
    }
private:
    int mCode ;
    std::string info;
};


class BasSdk {
public:
    BasSdk(std::string userKey, std::string host, std::string pemPath);
    std::shared_ptr<Err> Call(std::string input, std::string path, std::string& output);

private:
    //加载密钥文件
    std::shared_ptr<Err> loadPemKeys(std::string pemPath);
    //http请求
    std::shared_ptr<Err> callHttp(std::string& url, std::string& body, std::string& data) ;
    //编码，包括加密、签名和json及base64
    std::shared_ptr<Err> encodeReq(const std::string& fromMsg, std::string& toMsg);
    //解码，包括解密，签名验证，unbase64
    std::shared_ptr<Err> decodeRes(Json::Value &root, std::string& toMsg);
    //加密数据
    std::shared_ptr<Err> rsaEncrypt(const std::string& deMsg, std::string& enMsg, uint limit);
    //解密数据
    std::shared_ptr<Err> rsaDecrypt(std::string& enMsg, std::string& deMsg, uint limit);
    //生成签名
    std::shared_ptr<Err> rsaSign(std::string& msg, std::string& timestamp, std::string& sig);
    //验证签名
    std::shared_ptr<Err> signVerify(std::string& msg, std::string& timestamp, std::string& sig);
    //base64编码
    std::shared_ptr<Err> base64Encode(const std::string& input, bool with_new_line, std::string& output);
    //base64解码
    std::shared_ptr<Err> base64Decode(const std::string& input, bool with_new_line, std::string& output);
    //获取openssl错误
    std::string opensslErrStr();
    //curl回调
    static size_t curlWrite_CallbackFunc_StdString(void *contents, size_t size, size_t nmemb, std::string *s);

private:
    std::string mHost;    //服务端地址
    RSA* mServerPubKey;   //服务端公钥
    std::string mUserKey; //用户唯一userkey
    RSA* mUserPriKey;     //用户端私钥
    std::mutex mLock;
};


};
