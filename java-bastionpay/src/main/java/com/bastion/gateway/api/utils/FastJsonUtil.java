package com.bastion.gateway.api.utils;

import com.alibaba.fastjson.JSON;

import java.util.List;
import java.util.Map;

/**
 * json操作类
 *
 * @author pangkc
 */
public class FastJsonUtil {


	/**
	 * object to json
	 *
	 * @param obj
	 * @return
	 */
	public static String javaBeanToJson(Object data) {

		return JSON.toJSONString(data);
	}

	/**
	 * json to map
	 *
	 * @param str
	 * @return 返回map对象
	 */
	@SuppressWarnings("unchecked")
	public static Map jsonToMap(String str) {

		return JSON.parseObject(str, Map.class);
	}

	/**
	 * json to map list
	 *
	 * @param str
	 * @return 返回map集合
	 */
	@SuppressWarnings("unchecked")
	public static List<Map> jsonToMapList(String str) {

		return JSON.parseObject(str, List.class);
	}

	/**
	 * json to object
	 *
	 * @param object
	 * @param clazz
	 * @return
	 */
	public static <T> T jsonToObject(String str, Class<T> clazz) {
		return JSON.parseObject(str, clazz);
	}

	/**
	 * json to object list
	 * @param str
	 * @param clazz
	 * @return
	 * @throws Exception
	 */
	public static <T> List<T> jsonToObjectList(String str, Class<T> clazz){
		return JSON.parseArray(str, clazz);
	}
}
