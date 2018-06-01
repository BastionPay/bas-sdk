package bastionpay

import (
	"fmt"
	"encoding/json"
	"net/http"
	"io/ioutil"
	"crypto/sha512"
	"crypto"
	"encoding/base64"
	"bytes"
	"strings"
	"github.com/golang/glog"
	"bastionpay/utils"
	"os"
)

// config
type Gateway struct {
	Host    string `yaml:"host"`
	UserKey string `yaml:"userKey"`
	KeyPath string `yaml:"keyPath"`
}

/////////////////////////////////////////////////////
// 网关通用结构
// input/output data/value
// when input data, user encode and sign data, server decode and verify;
// when output value, server encode and sign data, user decode and verify;
type userData struct {
	// user unique key
	UserKey string `json:"user_key"`
	// message = (origin data -> rsa encode) -> base64
	Message string `json:"message"`
	// signature = (origin data -> rsa encode) -> sha512 -> rsa sign -> base64
	Signature string `json:"signature"`
}

// user response/push data
type userResponseData struct {
	Err    int        `json:"err"`    // error code
	ErrMsg string     `json:"errmsg"` // error message
	Value  userData   `json:"value"`  // response data
}

const (
	httpApi 	= "api"
)
var (
	// 钱包后台
	host string

	// uer key
	userKey string

	// 客户私钥
	user_prikey []byte

	// 客户公钥
	user_pubkey []byte

	// 服务公钥
	server_pubkey []byte
)

func Init(config *Gateway) {
	 if err := loadRsaKeys(config); err != nil {
		 glog.Errorf("BastionPay Init: %s", err.Error())
		 os.Exit(1)
	 }
}

func CallApi(message, path string) (*userResponseData, []byte, error) {
	return sendData(message, httpApi, path)
}

// 加载数据
func loadRsaKeys(config *Gateway) error {
	var err error

	host = config.Host
	userKey = config.UserKey

	private := fmt.Sprintf("%s/%s", strings.Trim(config.KeyPath, "/"), "private_administrator.pem")
	user_prikey, err = ioutil.ReadFile(private)
	if err != nil {
		return err
	}

	public := fmt.Sprintf("%s/%s", strings.Trim(config.KeyPath, "/"), "public_administrator.pem")
	user_pubkey, err = ioutil.ReadFile(public)
	if err != nil {
		return err
	}

	bastionpay := fmt.Sprintf("%s/%s", strings.Trim(config.KeyPath, "/"), "bastionpay_public.pem")
	server_pubkey, err = ioutil.ReadFile(bastionpay)
	if err != nil {
		return err
	}

	return nil
}

// 发送http请求
func callToHttpServer(path string, body string, res *string) error {
	url := host + path
	contentType := "application/json;charset=utf-8"

	b := []byte(body)
	b2 := bytes.NewBuffer(b)

	resp, err := http.Post(url, contentType, b2)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	*res = string(content)
	return nil
}

// 加密签名数据
func encryptData(message string) (*userData, error) {
	// 用户数据
	ud := &userData{}
	ud.UserKey = userKey

	bencrypted, err := func() ([]byte, error) {
		bencrypted, err := utils.RsaEncrypt([]byte(message), server_pubkey, utils.RsaEncodeLimit2048)
		if err != nil {
			return nil, err
		}
		return bencrypted, nil
	}()
	if err != nil {
		return nil, err
	}

	ud.Message = base64.StdEncoding.EncodeToString(bencrypted)

	bsignature, err := func() ([]byte, error) {
		var hashData []byte
		hs := sha512.New()
		hs.Write(bencrypted)
		hashData = hs.Sum(nil)

		bsignature, err := utils.RsaSign(crypto.SHA512, hashData, user_prikey)
		if err != nil {
			fmt.Println(err)
			return nil, err
		}

		return bsignature, nil
	}()
	if err != nil {
		return nil, err
	}

	ud.Signature = base64.StdEncoding.EncodeToString(bsignature)

	return ud, nil
}

// 验证解密数据
func decryptData(ud *userData) (string, error) {
	var d2 []byte
	// base64 decode
	bencrypted2, err := base64.StdEncoding.DecodeString(ud.Message)
	if err != nil {
		return "", err
	}

	bsignature2, err := base64.StdEncoding.DecodeString(ud.Signature)
	if err != nil {
		return "", err
	}

	// 验证签名
	var hashData []byte
	hs := sha512.New()
	hs.Write([]byte(bencrypted2))
	hashData = hs.Sum(nil)

	err = utils.RsaVerify(crypto.SHA512, hashData, bsignature2, server_pubkey)
	if err != nil {
		return "", err
	}

	// 解密数据
	d2, err = utils.RsaDecrypt(bencrypted2, user_prikey, utils.RsaDecodeLimit2048)
	if err != nil {
		return "", err
	}

	return string(d2), nil
}

// 请求使用加密签名
func sendData(message, relativePath, path string) (*userResponseData, []byte, error) {
	var(
		resData *userResponseData
		resMsg []byte
		resErr error
	)
	glog.Infof("BastionPay request: %s-%s", "/" + relativePath + path, message)

	resData, resMsg, resErr = func()(*userResponseData, []byte, error){
		ud, err := encryptData(message)
		if err != nil {
			return nil, nil, err
		}

		b, err := json.Marshal(ud)
		if err != nil {
			return nil, nil, err
		}
		body := string(b)

		var res string
		callToHttpServer("/" + relativePath + path, body, &res)

		ackData := &userResponseData{}
		err = json.Unmarshal([]byte(res), &ackData)
		if err != nil {
			return nil, nil, err
		}

		if ackData.Err != 0 {
			return ackData, nil, fmt.Errorf("%d-%s", ackData.Err, ackData.ErrMsg)
		}

		resMessage, err := decryptData(&ackData.Value)
		if err != nil {
			return nil, nil, err
		}

		return ackData, []byte(resMessage), nil
	}()

	if resErr != nil {
		glog.Errorf("BastionPay response err: %s-%s", "/" + relativePath + path, resErr.Error())
	} else if resData.Err != 0 {
		glog.Errorf("BastionPay response errcode: %s-%d-%s", "/" + relativePath + path, resData.Err, resData.ErrMsg)
	} else if resMsg != nil{
		glog.Infof("BastionPay response msg: %s-%s", "/" + relativePath + path, resMsg)
	} else {
		glog.Infof("BastionPay response msg: %s-unknown", "/" + relativePath + path)
	}

	return resData, resMsg, resErr
}
