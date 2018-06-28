package main

import (
	"bas-sdk/go-bastionpay/gateway"
	"fmt"
)

const (
	support_assets = "/v1/bastionpay/support_assets"
)

func main()  {
	ga := gateway.Config{}
	ga.Host = "http://35.173.156.149:8082"
	ga.UserKey = "5b695d56-2e84-4456-ac24-cdfe96f646d0"
	ga.KeyPath = "./pem"

	gateway.Init(&ga)

	// get support assets
	fmt.Println("call ", support_assets)
	res, data, err := gateway.CallApi("", support_assets)

	if err != nil {
		fmt.Errorf("response:\nerr: %%s", err.Error())
	} else if res.Err != 0 {
		fmt.Errorf("response:\nerrcode: %d-%s", res.Err, res.ErrMsg)
	} else if res != nil{
		fmt.Printf("response:\ndata: %s", string(data))
	} else {
		fmt.Printf("response:\nunknown error")
	}
}
