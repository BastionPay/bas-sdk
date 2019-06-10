<?php

require_once 'gateway.php';

$gateway = new Gateway\Gateway();
$orignStr = 'sign encrypt test';
$enArr = $gateway->sendData($orignStr, '/v1/bastionpay/support_assets');

var_dump($enArr);exit;


