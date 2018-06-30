package com.bastion.gateway.api;

import com.alibaba.fastjson.JSON;
import com.bastion.gateway.api.utils.FastJsonUtil;
import com.bastion.gateway.api.utils.HttpClientUtil;
import com.bastion.gateway.api.utils.RSAUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.entity.StringEntity;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BostainApiUtil {


    public static List<String> createAddress(String asset, int count) throws Exception {

        Map<String, Object> businessPara = new HashMap<>();
        businessPara.put("asset_name", asset);
        businessPara.put("count", count);

        String para = buildRequestPara(businessPara);

        String result = requestBostain(BostainConfig.CREATE_ADDRESS_URL, para);

        Map<String, Object> resultMap = FastJsonUtil.jsonToMap(result);

        return (List<String>) resultMap.get("data");
    }

    public static Map<String, Object> transactionBillDaily(String assetName, int maxDispLines, int maxPeriod, int minPeriod, int pageIndex, int totalLines) throws Exception {

        Map<String, Object> para = new HashMap<>();
        para.put("asset_name", assetName);
        para.put("max_disp_lines", maxDispLines);
        para.put("max_period", maxPeriod);
        para.put("min_period", minPeriod);
        para.put("page_index", pageIndex);
        para.put("total_lines", totalLines);

        String paraStr = buildRequestPara(para);

        String result = requestBostain(BostainConfig.BILL_DAILY_URL, paraStr);

        return  FastJsonUtil.jsonToMap(result);
    }

    public static  Map<String, String> withdraw(String address, BigDecimal amount, String asset, String userOrderId ) throws Exception {

        Map<String, Object> businessPara = new HashMap<>();
        businessPara.put("asset_name", asset);
        businessPara.put("user_order_id", userOrderId);
        businessPara.put("address", address);
        businessPara.put("amount", amount);

        String para = buildRequestPara(businessPara);

        String result = requestBostain(BostainConfig.WITHDRAW_URL, para);

        return  FastJsonUtil.jsonToMap(result);
    }

    private static String buildRequestPara(Map<String, Object> businessPara) throws Exception {

        String paraStr = FastJsonUtil.javaBeanToJson(businessPara);

        byte[] paraArr = RSAUtil.encrypt(paraStr, BostainConfig.BOSTAIN_PUB_KEY);
        String encryptMessage = Base64.encodeBase64String(paraArr);
        String timestamp = String.valueOf(System.currentTimeMillis() / 1000);
        byte[] timestampArr = timestamp.getBytes();
        byte[] requestByteArr = new byte[paraArr.length + timestampArr.length];

        System.arraycopy(paraArr, 0, requestByteArr, 0, paraArr.length);
        System.arraycopy(timestampArr, 0, requestByteArr, paraArr.length, timestampArr.length);

        String signature = RSAUtil.signature(requestByteArr, BostainConfig.BUSINESS_PRIVATE_KEY);

        Map<String, Object> paraMap = new HashMap<>();
        paraMap.put("message", encryptMessage);
        paraMap.put("time_stamp", timestamp);
        paraMap.put("signature", signature);
        paraMap.put("user_key", BostainConfig.USER_KEY);

        return FastJsonUtil.javaBeanToJson(paraMap);
    }

    private static String requestBostain(String url, String para) throws Exception {

        StringEntity stringEntity = new StringEntity(para);

        Map header = new HashMap();
        header.put("Content-Type", "application/json;charset=utf-8");

        String result = HttpClientUtil.doPost(url, stringEntity);

        Map<String, Object> resultMap = FastJsonUtil.jsonToMap(result);
        int err = (int) resultMap.get("err");
        if (err != 0) {
            String errMsg = (String) resultMap.get("errmsg");
            throw new BostainException(err, errMsg);
        }

        resultMap = (Map<String, Object>) resultMap.get("value");
        String resultSignature = (String) resultMap.get("signature");
        String resultMsg = (String) resultMap.get("message");
        String timestampStr = (String) resultMap.get("time_stamp");

        byte[] resultMsgArr = Base64.decodeBase64(resultMsg);
        byte[] timestampArr = timestampStr.getBytes();
        byte[] resultNewByte = new byte[resultMsgArr.length + timestampArr.length];

        System.arraycopy(resultMsgArr, 0, resultNewByte, 0, resultMsgArr.length);
        System.arraycopy(timestampArr, 0, resultNewByte, resultMsgArr.length, timestampArr.length);

        boolean verifyResult = RSAUtil.verity(resultNewByte, Base64.decodeBase64(resultSignature), BostainConfig.BOSTAIN_PUB_KEY);
        if (!verifyResult) {
            throw new BostainException("result verify failed");
        }

        byte[] msgByte = RSAUtil.decrypt(resultMsg, BostainConfig.BUSINESS_PRIVATE_KEY);
        return new String(msgByte);
    }

    public static String decrypt(String data) throws Exception {

        Map<String, Object> resultMap = FastJsonUtil.jsonToMap(data);
        int err = (int) resultMap.get("err");
        if (err != 0) {
            String errMsg = (String) resultMap.get("errmsg");
            throw new BostainException(err, errMsg);
        }

        resultMap = (Map<String, Object>) resultMap.get("value");
        String resultSignature = (String) resultMap.get("signature");
        String resultMsg = (String) resultMap.get("message");
        String timestampStr = (String) resultMap.get("time_stamp");

        byte[] resultMsgArr = Base64.decodeBase64(resultMsg);
        byte[] timestampArr = timestampStr.getBytes();
        byte[] resultNewByte = new byte[resultMsgArr.length + timestampArr.length];

        System.arraycopy(resultMsgArr, 0, resultNewByte, 0, resultMsgArr.length);
        System.arraycopy(timestampArr, 0, resultNewByte, resultMsgArr.length, timestampArr.length);

        boolean verifyResult = RSAUtil.verity(resultNewByte, Base64.decodeBase64(resultSignature), BostainConfig.BOSTAIN_PUB_KEY);
        if (!verifyResult) {
            throw new BostainException("result verify failed");
        }

        byte[] msgByte = RSAUtil.decrypt(resultMsg, BostainConfig.BUSINESS_PRIVATE_KEY);
        return new String(msgByte);
    }

}
