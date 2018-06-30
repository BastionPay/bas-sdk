package com.bastion.gateway.api;

public abstract class BostainConfig {

    private BostainConfig(){

    }

    public static final String CREATE_ADDRESS_URL = "https://api.bastionpay.com/api/v1/bastionpay/new_address";

    public static final String WITHDRAW_URL = "https://api.bastionpay.com/api/v1/bastionpay/withdrawal";

    public static final String BILL_DAILY_URL = "https://api.bastionpay.com/api/v1/bastionpay/transaction_bill_daily";

    public static final String USER_KEY = "";

    public static final String BOSTAIN_PUB_KEY = "";

    public static final String BUSINESS_PUB_KEY = "";

    public static final String BUSINESS_PRIVATE_KEY = "";

}
