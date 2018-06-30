package com.bastion.gateway.api.utils;

import org.apache.http.*;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class HttpClientUtil {

    private static PoolingHttpClientConnectionManager conManager = new PoolingHttpClientConnectionManager();
    private static CloseableHttpClient httpClient;
    private static final String ENCODING = "UTF-8";

    static {
        conManager.setMaxTotal(500);
        conManager.setDefaultMaxPerRoute(500);

        RequestConfig requestConfig = RequestConfig.custom().setSocketTimeout(5000).setConnectTimeout(3000).setConnectionRequestTimeout(5000).build();

        httpClient = HttpClients.custom().setConnectionManager(conManager).setDefaultRequestConfig(requestConfig).setRetryHandler(new DefaultHttpRequestRetryHandler(3, false)).build();
    }

    private HttpClientUtil() {
    }

    public static final String doPost(String url, Map<String, String> params) throws Exception {
        return doPost(url, params, null);
    }

    public static final String doPost(String url, StringEntity paraEntity) throws Exception {
        return doPost(url, paraEntity, null);
    }

    public static final String doPost(String url, StringEntity paraEntity, Map<String, String> headers) throws Exception {
        HttpPost httpost = new HttpPost(url);

        httpost.setEntity(paraEntity);
        return executeRequest(httpost, headers);
    }

    public static final String doPost(String url, Map<String, String> params, Map<String, String> headers) throws Exception {
        HttpPost httpost = new HttpPost(url);

        List<NameValuePair> nvps = new ArrayList<NameValuePair>();
        for (String name : params.keySet()) {
            String value = params.get(name);
            nvps.add(new BasicNameValuePair(name, value));
        }

        httpost.setEntity(new UrlEncodedFormEntity(nvps, ENCODING));
        return executeRequest(httpost, headers);
    }


    private static String executeRequest(HttpRequestBase request, Map<String, String> headers) throws Exception {
        HttpEntity entity = null;
        try {
            if (headers != null) {
                for (Map.Entry<String, String> header : headers.entrySet()) {
                    request.addHeader(header.getKey(), header.getValue());
                }
            }

            HttpResponse response = httpClient.execute(request);
            entity = response.getEntity();
            String content = EntityUtils.toString(entity, ENCODING);
            return content;
        } finally {
            if (entity != null) {
                EntityUtils.consume(entity);
            }
            request.abort();
        }
    }

}
