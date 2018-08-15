#include "BasSdk.hpp"
#include <openssl/pem.h>
#include <curl/curl.h>
#include <ctime>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <cstdlib>

namespace BastionPay
{

//const std::string CONST_UserPubPemName = "public_rsa.pem";
const std::string CONST_UserPriPemName = "private_rsa.pem";
const std::string CONST_BastionpayPubPemName = "bastionpay_public.pem";
const std::string CONST_HttpApi = "api";
const int CONST_RsaBits1024 = 1024;
const int CONST_RsaBits2048 = 2048;
const int CONST_RsaEncodeLimit1024 = CONST_RsaBits1024 / 8 - 11;
const int CONST_RsaDecodeLimit1024 = CONST_RsaBits1024 / 8;
const int CONST_RsaEncodeLimit2048 = CONST_RsaBits2048 / 8 - 11;
const int CONST_RsaDecodeLimit2048 = CONST_RsaBits2048 / 8;
    
BasSdk::BasSdk(std::string userKey, std::string host, std::string pemPath):mUserKey(userKey),mHost(host) {
   size_t n = this->mHost.find_last_not_of( "/" );
   if( n != std::string::npos ){
        this->mHost.erase( n + 1 , this->mHost.size() - n );
   }
  std::shared_ptr<Err> err = this->loadPemKeys(pemPath);
   if  (err != nullptr ){
       std::cout<<"loadPemKeys fail:"<<err->what()<<std::endl;
       throw err->what();
   } 
}

std::shared_ptr<Err> BasSdk::Call(std::string input, std::string path, std::string& output){
    std::string url = this->mHost +"/" + CONST_HttpApi + path;
    std::string toMsg;
    std::shared_ptr<Err> err = this->encodeReq(input, toMsg);
    if (err != nullptr) {
        return err;
    }
    std::string res;
    this->mLock.lock();
    err = this->callHttp(url, toMsg, res);
    if (err != nullptr) {
        this->mLock.unlock();
        return err;
    }
    this->mLock.unlock();
    Json::Value root;
    Json::CharReaderBuilder builder;
    JSONCPP_STRING errs;
    std::unique_ptr<Json::CharReader> const reader(builder.newCharReader());
    bool ok = reader->parse(res.c_str(), res.c_str() + res.length(), &root, &errs);
    if (!ok) {
        return std::make_shared<Err>(CONST_ErrCode_JsonParse, "json parse err "+errs);
    }
    if ( (!root["err"].isNull()) && (root["err"].asInt() != 0) ){
        std::string errStr = std::to_string(root["err"].asInt());
        return std::make_shared<Err>(CONST_ErrCode_Err, "err("+errStr+") "+root["errmsg"].asString());
    }
    return this->decodeRes(root["value"],  output);
}

std::shared_ptr<Err> BasSdk::loadPemKeys(std::string pemPath){
    std::string userPriPath = pemPath + "/" + CONST_UserPriPemName;
    FILE *fp = fopen(userPriPath.c_str(), "r");
    if (fp  == NULL) {
        return std::make_shared<Err>(CONST_ErrCode_OpenFile, userPriPath+" open err");
    }
    this->mUserPriKey = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    if ( this->mUserPriKey == nullptr) {
        return std::make_shared<Err>(CONST_ErrCode_OpenFile, "null pem_pri_key");
    }
    fclose(fp);
    std::string serverPubPath = pemPath + "/" + CONST_BastionpayPubPemName;
    FILE *fp2 = fopen(serverPubPath.c_str(), "r");
    if (fp2  == NULL) {
        return std::make_shared<Err>(CONST_ErrCode_OpenFile,  serverPubPath+" open err");
    }
    this->mServerPubKey = PEM_read_RSA_PUBKEY(fp2, NULL, NULL, NULL);//PEM_read_RSAPublicKey  PEM_read_RSA_PUBKEY
    if ( this->mServerPubKey == nullptr) {
        return std::make_shared<Err>(CONST_ErrCode_OpenFile, "null pem_pub_key "+ serverPubPath);
    }
    fclose(fp2);
    return nullptr;
}

std::shared_ptr<Err> BasSdk::callHttp(std::string& url, std::string& body, std::string& data) {
    std::string contentType = "application/json;charset=utf-8";

    printf("url: %s\n", url.c_str());

     /* get a curl handle */ 
    CURL* curl = curl_easy_init();
    if(curl == NULL){
        return std::make_shared<Err>(CONST_ErrCode_CurlInit, "curl init fail");
    }

    CURLcode res;
    /* First set the URL that is about to receive our POST. This URL can
       just as well be a https:// URL if that is what should receive the
       data. */ 
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    /* Now specify the POST data */ 
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, this->curlWrite_CallbackFunc_StdString);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
 
    /* Perform the request, res will get the return code */ 
    res = curl_easy_perform(curl);
    /* Check for errors */ 
    if(res != CURLE_OK){
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
        const char *errInfo =curl_easy_strerror(res);
        return std::make_shared<Err>(CONST_ErrCode_CurlPerform, errInfo);
    }

    curl_easy_cleanup(curl);

    return nullptr;
}

std::shared_ptr<Err> BasSdk::encodeReq(const std::string& fromMsg, std::string& toMsg){
    std::time_t timestamp = std::time(0);
    std::string timestampStr = std::to_string((long long)timestamp);
    std::string encrptyMsg;
    std::shared_ptr<Err> err = this->rsaEncrypt(fromMsg, encrptyMsg, CONST_RsaEncodeLimit2048);
    if (err != nullptr) {
        return err;
    }
    std::string sig;
    err = this->rsaSign(encrptyMsg,timestampStr,  sig);
    if (err != nullptr){
        return err;
    }
    std::string toMsgBase64 ,sigBase64;
    err = this->base64Encode(encrptyMsg,  false, toMsgBase64);
    if (err != nullptr) {
        return err;
    }
    err  = this->base64Encode(sig, false, sigBase64);
    if (err != nullptr) {
        return err;
    }
    Json::Value jsonRoot;
    jsonRoot["user_key"] = this->mUserKey;
    jsonRoot["message"] = toMsgBase64;
    jsonRoot["signature"] = sigBase64;
    jsonRoot["time_stamp"] = timestampStr;
    toMsg = jsonRoot.toStyledString();
    return nullptr;
}

std::shared_ptr<Err> BasSdk::decodeRes(Json::Value& root, std::string& toMsg){
    std::string encryptMsgBase64 = root["message"].asCString();
    std::string sigBase64 = root["signature"].asCString();
    std::string timeStamp = root["time_stamp"].asString();

    
    std::string encryptMsg, sig;
    std::shared_ptr<Err>  err = this->base64Decode(encryptMsgBase64, false, encryptMsg);
    if (err != nullptr) {
        return err;
    }
    err = this->base64Decode(sigBase64, false, sig);
    if (err != nullptr) {
        return err;
    }
    err = this->signVerify(encryptMsg, timeStamp, sig);
    if(err != nullptr){
        return err;
    }
   return  this->rsaDecrypt(encryptMsg, toMsg, CONST_RsaDecodeLimit2048);
}

std::shared_ptr<Err> BasSdk::rsaEncrypt(const std::string& deMsg, std::string& enMsg, uint limit){
    uint startIndex, endIndex;
    startIndex = endIndex = 0;
    uint length = deMsg.length();
    unsigned char to[limit];
    enMsg.clear();
    while (startIndex < length){
         if ((startIndex + limit) < length) {
             endIndex = startIndex + limit;
         }else{
             endIndex = length;
         }
         std::string tmpData = deMsg.substr(startIndex,endIndex);
         int ret =  RSA_public_encrypt(limit, (const unsigned char*)tmpData.c_str(), to, this->mServerPubKey, RSA_PKCS1_PADDING);
        if (ret == -1 ){//-1表出错
            return std::make_shared<Err>(CONST_ErrCode_RsaPubEncrypt, this->opensslErrStr());
        }
        enMsg.append((char *)to);
        startIndex = endIndex;
    }
    return nullptr;
}

std::shared_ptr<Err> BasSdk::rsaDecrypt(std::string& enMsg, std::string& deMsg, uint limit){
    uint  startIndex=0, endIndex =0;
    uint  length = enMsg.length();
    unsigned char to[limit];
    deMsg.clear();
    while (startIndex < length){
        if ((startIndex + limit) < length) {
                endIndex = startIndex + limit;
        }else{
                  endIndex = length;
        }
        std::string tmp = enMsg.substr(startIndex, endIndex);
        int ret =  RSA_private_decrypt(limit, (const unsigned char*)tmp.c_str(), to, this->mUserPriKey, RSA_PKCS1_PADDING);
        if(ret == -1) {//-1表出错
            return std::make_shared<Err>(CONST_ErrCode_RsaPriDecrypt, this->opensslErrStr());
        }
        deMsg.append((char*)to);
        startIndex = endIndex;
    }
    return nullptr;
}

std::shared_ptr<Err> BasSdk::rsaSign(std::string& msg, std::string& timestamp, std::string& sig){
    std::string newMsg = msg+ timestamp;
    unsigned char md[512/8], sigret[RSA_size(this->mUserPriKey)];
    memset(sigret, 0, RSA_size(this->mUserPriKey));
    unsigned char* ret = SHA512((const unsigned char*)newMsg.c_str(), (size_t)newMsg.length(), md);
    if (ret == nullptr) {
        return std::make_shared<Err>(CONST_ErrCode_SHA512, "rsaSign SHA512 failed");
    }
    unsigned int siglen;
    int code = RSA_sign(NID_sha512, md, 512/8, sigret, &siglen, this->mUserPriKey);
    if (code != 1 ){ //1表示成功
        return std::make_shared<Err>(CONST_ErrCode_RsaSign, this->opensslErrStr());
    }
    sig.assign((const char*)sigret, siglen);
    return nullptr;
}

std::shared_ptr<Err> BasSdk::signVerify(std::string& msg, std::string& timestamp, std::string& sig){
    std::string newMsg = msg+ timestamp;
    unsigned char md[512/8], sigret[RSA_size(this->mUserPriKey)];
    unsigned char* ret = SHA512((const unsigned char*)newMsg.c_str(), newMsg.length(), md);
    if (ret == nullptr) {
        return std::make_shared<Err>(CONST_ErrCode_SHA512, "signVerify SHA512 failed");
    }
    int code = RSA_verify(NID_sha512, md, 512/8,
                (const unsigned char *)sig.c_str(), sig.length(), this->mServerPubKey);
    if (code != 1 ){//1表示成功
        return std::make_shared<Err>(CONST_ErrCode_SigVerify, this->opensslErrStr());
    }
    return nullptr;
}

std::string BasSdk::opensslErrStr(){
    ERR_load_ERR_strings();
    ERR_load_crypto_strings(); 
    unsigned long ulErr = ERR_get_error(); // 获取错误号
    char szErrMsg[1024] = {0};
    char *pTmp = NULL;
    pTmp = ERR_error_string(ulErr,szErrMsg); // 格式：error:errId:库:函数:原因
    ERR_print_errors_fp(stdout);
    return pTmp;
}

std::shared_ptr<Err> BasSdk::base64Encode(const std::string& input, bool with_new_line, std::string& output){
    if (input.empty()){
        return nullptr;
    }
    BIO * bmem = NULL;
    BIO * b64 = NULL;
    BUF_MEM * bptr = NULL;
 
    b64 = BIO_new(BIO_f_base64());
    if (b64 == nullptr) {
        return std::make_shared<Err>(CONST_ErrCode_Base64Encode, "null BIO_new");
    }
    if(!with_new_line) {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    bmem = BIO_new(BIO_s_mem());
    if (bmem == nullptr) {
        BIO_free_all(b64);
        return std::make_shared<Err>(CONST_ErrCode_Base64Encode, "null BIO_new_mem_buf");
    }
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input.c_str(), input.length());
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
 
    char buff[bptr->length + 1];
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;
    output.assign(buff, bptr->length);
    BIO_free_all(b64);
    return nullptr;
}

std::shared_ptr<Err> BasSdk::base64Decode(const std::string& input, bool with_new_line, std::string& output){
    if (input.empty()){
        return nullptr;
    }
    BIO * b64 = NULL;
    BIO * bmem = NULL;
    char buffer[input.length()];
    memset(buffer, 0, input.length());
 
    b64 = BIO_new(BIO_f_base64());
    if (b64 == nullptr) {
         return std::make_shared<Err>(CONST_ErrCode_Base64Decode, "null BIO_new");
    }
    if(!with_new_line) {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    bmem = BIO_new_mem_buf(input.c_str(), input.length());
    if (bmem == nullptr) {
        BIO_free_all(b64);
        return std::make_shared<Err>(CONST_ErrCode_Base64Decode, "null BIO_new_mem_buf");
    }
    bmem = BIO_push(b64, bmem);
    int size = BIO_read(bmem, buffer, input.length());
    if (size <= -2) {
        BIO_free_all(b64);
        std::string errInfo =  this->opensslErrStr();
        return std::make_shared<Err>(CONST_ErrCode_Base64Decode, errInfo);
    }
    output.assign((const char*)buffer, size);
    BIO_free_all(b64);
    return nullptr;
}

size_t BasSdk::curlWrite_CallbackFunc_StdString(void *contents, size_t size, size_t nmemb, std::string *s)
{
    size_t newLength = size*nmemb;
    size_t oldLength = s->size();
    try
    {
        s->resize(oldLength + newLength);
    }
    catch(std::bad_alloc &e)
    {
        //handle memory problem
        return 0;
    }

    std::copy((char*)contents,(char*)contents+newLength,s->begin()+oldLength);
    return size*nmemb;
}

};

