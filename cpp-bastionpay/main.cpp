#include <iostream>
#include "BasSdk.hpp"

using namespace std;
using namespace BastionPay;

/*
mac 编译
g++ -std=c++11 -I. -I/usr/local/include -I/usr/local/Cellar/jsoncpp/1.8.4/include -L/usr/local/Cellar/jsoncpp/1.8.4/lib -I/usr/local/Cellar/openssl/1.0.2n/include -L/usr/local/Cellar/openssl/1.0.2n/lib  -L. -L/usr/local/lib -I/usr/include -L/usr/lib  -ljsoncpp -lssl -lcrypto -lcurl  *.cpp

参考
https://blog.csdn.net/sinat_14854721/article/details/80310868
http://www.qmailer.net/archives/216.html

注意点：
 这里 只支持 BEGIN PUBLIC KEY格式的key；
 如果生成了BEGIN RSA PUBLIC KEY格式的pem文件，首尾手动删掉‘RSA ‘这四个字符就行
*/

int main(){
    BasSdk sdk("5b695d56-2e84-4456-ac24-cdfe96f646d0", "http:/35.173.156.149:8082", "./pem");
    std::string out;
    std::shared_ptr<Err> err = sdk.Call("", "/v1/bastionpay/support_assets", out);
    if (err != nullptr) {
        std::cout<<(err->code())<<" === "<<err->what()<<std::endl;
        exit(0);
    }
    std:;cout<<"ok  "<<out<<std::endl;
    return 0;
}