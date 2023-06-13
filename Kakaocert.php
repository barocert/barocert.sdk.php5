<?php

/**
 * =====================================================================================
 * Class for base module for Kakaocert API SDK. It include base functionality for
 * RESTful web service request and parse json result. It uses Linkhub module
 * to accomplish authentication APIs.
 *
 * This module uses curl and openssl for HTTPS Request. So related modules must
 * be installed and enabled.
 *
 * https://www.linkhub.co.kr
 * Author : linkhub dev (dev@linkhubcorp.com)
 * Written : 2023-03-13
 * Updated : 2023-06-13
 *
 * Thanks for your interest.
 * We welcome any suggestions, feedbacks, blames or anythings.
 * ======================================================================================
 */

 require_once 'Linkhub/linkhub.auth.php';

class KakaocertService
{

  const ServiceID = 'BAROCERT';
  const ServiceURL = 'https://barocert.linkhub.co.kr';
  const ServiceURL_Static = 'https://static-barocert.linkhub.co.kr';
  const Version = '2.0';

  private $Token_Table = array();
  private $Linkhub;
  private $IPRestrictOnOff = true;
  private $UseStaticIP = false;
  private $UseLocalTimeYN = true;

  private $scopes = array();
  private $__requestMode = LINKHUB_COMM_MODE;

  public function __construct($LinkID, $SecretKey)
  {
    $this->Linkhub = Linkhub::getInstance($LinkID, $SecretKey);
    $this->scopes[] = 'partner';
    $this->scopes[] = '401';
    $this->scopes[] = '402';
    $this->scopes[] = '403';
    $this->scopes[] = '404';
  }

  protected function AddScope($scope)
  {
    $this->scopes[] = $scope;
  }

  public function IPRestrictOnOff($V)
  {
    $this->IPRestrictOnOff = $V;
  }

  public function UseStaticIP($V)
  {
    $this->UseStaticIP = $V;
  }

  public function UseLocalTimeYN($V)
  {
    $this->UseLocalTimeYN = $V;
  }

  private function getTargetURL()
  {
    if ($this->UseStaticIP) {
      return KakaocertService::ServiceURL_Static;
    }
    return KakaocertService::ServiceURL;
  }

  private function getsession_Token()
  {
    $targetToken = null;

    if (array_key_exists($this->Linkhub->getLinkID(), $this->Token_Table)) {
      $targetToken = $this->Token_Table[$this->Linkhub->getLinkID()];
    }

    $Refresh = false;

    if (is_null($targetToken)) {
      $Refresh = true;
    } else {
      $Expiration = new DateTime($targetToken->expiration, new DateTimeZone("UTC"));

      $now = $this->Linkhub->getTime($this->UseStaticIP, $this->UseLocalTimeYN, false);
      $Refresh = $Expiration < $now;
    }

    if ($Refresh) {
      try {
        $targetToken = $this->Linkhub->getToken(KakaocertService::ServiceID, "", $this->scopes, $this->IPRestrictOnOff ? null : "*", $this->UseStaticIP, $this->UseLocalTimeYN, false);
      } catch (LinkhubException $le) {
        throw new BarocertException($le->getMessage(), $le->getCode());
      }
      $this->Token_Table[$this->Linkhub->getLinkID()] = $targetToken;
    }
    return $targetToken->session_token;
  }

  protected function executeCURL($uri, $isPost = false, $postdata = null)
  {
    if ($this->__requestMode != "STREAM") {

      $targetURL = $this->getTargetURL();

      $http = curl_init($targetURL . $uri);
      $header = array();

      $header[] = 'Authorization: Bearer ' . $this->getsession_Token();
      $header[] = 'Content-Type: Application/json';

      if ($isPost) {
        curl_setopt($http, CURLOPT_POST, 1);
        curl_setopt($http, CURLOPT_POSTFIELDS, $postdata);

        $xDate = $this->Linkhub->getTime($this->UseStaticIP, false, false);

        $digestTarget = 'POST' . chr(10);
        $digestTarget = $digestTarget . $uri . chr(10);
        if($postdata){
          $digestTarget = $digestTarget . base64_encode(hash('sha256', $postdata, true)) . chr(10);
        }
        $digestTarget = $digestTarget . $xDate . chr(10);

        $digest = base64_encode(hash_hmac('sha256', $digestTarget, base64_decode(strtr($this->Linkhub->getSecretKey(), '-_', '+/')), true));

        $header[] = 'x-bc-date: ' . $xDate;
        $header[] = 'x-bc-version: ' . '2.0';
        $header[] = 'x-bc-auth: ' .  $digest;
        $header[] = 'x-bc-encryptionmode: ' . 'CBC';
      }

      curl_setopt($http, CURLOPT_HTTPHEADER, $header);
      curl_setopt($http, CURLOPT_RETURNTRANSFER, TRUE);
      curl_setopt($http, CURLOPT_ENCODING, 'gzip,deflate');

      $responseJson = curl_exec($http);
      $http_status = curl_getinfo($http, CURLINFO_HTTP_CODE);

      $is_gzip = 0 === mb_strpos($responseJson, "\x1f" . "\x8b" . "\x08");

      if ($is_gzip) {
        $responseJson = $this->Linkhub->gzdecode($responseJson);
      }

      $contentType = strtolower(curl_getinfo($http, CURLINFO_CONTENT_TYPE));

      curl_close($http);
      if ($http_status != 200) {
        throw new BarocertException($responseJson);
      }

      return json_decode($responseJson);
    } else {
      $header = array();

      $header[] = 'Accept-Encoding: gzip,deflate';
      $header[] = 'Connection: close';
      $header[] = 'Authorization: Bearer ' . $this->getsession_Token();
      $header[] = 'Content-Type: Application/json';
      $postbody = $postdata;

      $xDate = $this->Linkhub->getTime($this->UseStaticIP, false, false);

      $digestTarget = 'POST' . chr(10);      
      $digestTarget = $digestTarget . $uri . chr(10);
      if($postdata){
        $digestTarget = $digestTarget . base64_encode(hash('sha256', $postdata, true)) . chr(10);
      }
      $digestTarget = $digestTarget . $xDate . chr(10);

      $digest = base64_encode(hash_hmac('sha256', $digestTarget, base64_decode(strtr($this->Linkhub->getSecretKey(), '-_', '+/')), true));

      $header[] = 'x-bc-date: ' . $xDate;
      $header[] = 'x-bc-version: ' . '2.0';
      $header[] = 'x-bc-auth: ' . $digest;
      $header[] = 'x-bc-encryptionmode: ' . 'CBC';

      $params = array(
        'http' => array(
          'ignore_errors' => TRUE,
          'protocol_version' => '1.0',
          'method' => 'GET'
        )
      );

      if ($isPost) {
        $params['http']['method'] = 'POST';
        $params['http']['content'] = $postbody;
      }

      if ($header !== null) {
        $head = "";
        foreach ($header as $h) {
          $head = $head . $h . "\r\n";
        }
        $params['http']['header'] = substr($head, 0, -2);
      }

      $ctx = stream_context_create($params);
      $targetURL = $this->getTargetURL();
      $response = file_get_contents($targetURL . $uri, false, $ctx);

      $is_gzip = 0 === mb_strpos($response, "\x1f" . "\x8b" . "\x08");

      if ($is_gzip) {
        $response = $this->Linkhub->gzdecode($response);
      }

      if ($http_response_header[0] != "HTTP/1.1 200 OK") {
        throw new BarocertException($response);
      }

      return json_decode($response);
    }
  }


  public function encrypt($data){
    return $this->encAES256CBC($data);
  }

  function pkcs7padding($data){
    $padding = 16 - strlen($data) % 16;
    $padding_text = str_repeat(chr($padding),$padding);
    return $data . $padding_text;
  }

  public function encAES256CBC($data){
    $biv = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC), MCRYPT_RAND);
    $enc = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, base64_decode($this->Linkhub->getSecretKey()), $this->pkcs7padding($data), MCRYPT_MODE_CBC, $biv);
    return base64_encode($biv . $enc);
  }

 /**
   * 본인인증 요청
   */
  public function requestIdentity($ClientCode, $KakaoIdentity)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (preg_match("/^[0-9]*$/", $ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($KakaoIdentity) || empty($KakaoIdentity)) {
      throw new BarocertException('본인인증 요청정보가 입력되지 않았습니다.');
    }
    if (is_null($KakaoIdentity->receiverHP) || empty($KakaoIdentity->receiverHP)) {
      throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
    }
    if (is_null($KakaoIdentity->receiverName) || empty($KakaoIdentity->receiverName)) {
      throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
    }
    if (is_null($KakaoIdentity->receiverBirthday) || empty($KakaoIdentity->receiverBirthday)) {
      throw new BarocertException('생년월일이 입력되지 않았습니다.');
    }

    if (is_null($KakaoIdentity->expireIn) || empty($KakaoIdentity->expireIn)) {
      throw new BarocertException('만료시간이 입력되지 않았습니다.');
    }
    if (is_null($KakaoIdentity->reqTitle) || empty($KakaoIdentity->reqTitle)) {
      throw new BarocertException('인증요청 메시지 제목이 입력되지 않았습니다.');
    }
    if (is_null($KakaoIdentity->token) || empty($KakaoIdentity->token)) {
      throw new BarocertException('토큰 원문이 입력되지 않았습니다.');
    }

    $postdata = json_encode($KakaoIdentity);
    
    $result = $this->executeCURL('/KAKAO/Identity/' . $ClientCode, true, $postdata);

    $KakaoIdentityReceipt = new KakaoIdentityReceipt();
    $KakaoIdentityReceipt->fromJsonInfo($result);
    return $KakaoIdentityReceipt;
  }

  /**
   * 본인인증 상태확인
   */
  public function getIdentityStatus($ClientCode, $ReceiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (preg_match("/^[0-9]*$/", $ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($ReceiptID) || empty($ReceiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (preg_match("/^[0-9]*$/", $ReceiptID) == 0) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ReceiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }

    $result = $this->executeCURL('/KAKAO/Identity/' . $ClientCode .'/'. $ReceiptID, false, null);

    $KakaoIdentityStatus = new KakaoIdentityStatus();
    $KakaoIdentityStatus->fromJsonInfo($result);
    return $KakaoIdentityStatus;
  }

  /**
   * 본인인증 검증
   */
  public function verifyIdentity($ClientCode, $ReceiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (preg_match("/^[0-9]*$/", $ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($ReceiptID) || empty($ReceiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (preg_match("/^[0-9]*$/", $ReceiptID) == 0) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ReceiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }

    $result = $this->executeCURL('/KAKAO/Identity/' . $ClientCode .'/'. $ReceiptID, true, null);

    $KakaoIdentityResult = new KakaoIdentityResult();
    $KakaoIdentityResult->fromJsonInfo($result);
    return $KakaoIdentityResult;
  }

  /**
   * 전자서명 요청(단건)
   */
  public function RequestSign($ClientCode, $KakaoSign)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (preg_match("/^[0-9]*$/", $ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($KakaoSign) || empty($KakaoSign)) {
      throw new BarocertException('전자서명 요청정보가 입력되지 않았습니다.');
    }
    if (is_null($KakaoSign->receiverHP) || empty($KakaoSign->receiverHP)) {
      throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
    }
    if (is_null($KakaoSign->receiverName) || empty($KakaoSign->receiverName)) {
      throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
    }
    if (is_null($KakaoSign->receiverBirthday) || empty($KakaoSign->receiverBirthday)) {
      throw new BarocertException('생년월일이 입력되지 않았습니다.');
    }
    if (is_null($KakaoSign->expireIn) || empty($KakaoSign->expireIn)) {
      throw new BarocertException('만료시간이 입력되지 않았습니다.');
    }
    if (is_null($KakaoSign->reqTitle) || empty($KakaoSign->reqTitle)) {
      throw new BarocertException('인증요청 메시지 제목이 입력되지 않았습니다.');
    }
    if (is_null($KakaoSign->token) || empty($KakaoSign->token)) {
      throw new BarocertException('토큰 원문이 입력되지 않았습니다.');
    }
    if (is_null($KakaoSign->tokenType) || empty($KakaoSign->tokenType)) {
      throw new BarocertException('원문 유형이 입력되지 않았습니다.');
    }

    $postdata = json_encode($KakaoSign);

    $result = $this->executeCURL('/KAKAO/Sign/' . $ClientCode, true,  $postdata);

    $KakaoSignReceipt = new KakaoSignReceipt();
    $KakaoSignReceipt->fromJsonInfo($result);
    return $KakaoSignReceipt;
  }


  /**
   * 전자서명 상태 확인(단건)
   */
  public function getSignStatus($ClientCode, $ReceiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (preg_match("/^[0-9]*$/", $ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($ReceiptID) || empty($ReceiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (preg_match("/^[0-9]*$/", $ReceiptID) == 0) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ReceiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }

    $result = $this->executeCURL('/KAKAO/Sign/'. $ClientCode .'/'. $ReceiptID, false, null);

    $KakaoSignStatus = new KakaoSignStatus();
    $KakaoSignStatus->fromJsonInfo($result);
    return $KakaoSignStatus;
  }

  /**
   * 전자서명 검증(단건)
   */
  public function verifySign($ClientCode, $ReceiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (preg_match("/^[0-9]*$/", $ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($ReceiptID) || empty($ReceiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (preg_match("/^[0-9]*$/", $ReceiptID) == 0) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ReceiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }
    
    $result = $this->executeCURL('/KAKAO/Sign/'. $ClientCode .'/'. $ReceiptID, true, null);

    $KakaoSignResult = new KakaoSignResult();
    $KakaoSignResult->fromJsonInfo($result);
    return $KakaoSignResult;
  }

  /**
   * 전자서명 요청(복수)
   */
  public function requestMultiSign($ClientCode, $KakaoMultiSign)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (preg_match("/^[0-9]*$/", $ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($KakaoMultiSign) || empty($KakaoMultiSign)) {
      throw new BarocertException('전자서명 요청정보가 입력되지 않았습니다.');
    }
    if (is_null($KakaoMultiSign->receiverHP) || empty($KakaoMultiSign->receiverHP)) {
      throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
    }
    if (is_null($KakaoMultiSign->receiverName) || empty($KakaoMultiSign->receiverName)) {
      throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
    }
    if (is_null($KakaoMultiSign->receiverBirthday) || empty($KakaoMultiSign->receiverBirthday)) {
      throw new BarocertException('생년월일이 입력되지 않았습니다.');
    }
    if (is_null($KakaoMultiSign->expireIn) || empty($KakaoMultiSign->expireIn)) {
      throw new BarocertException('만료시간이 입력되지 않았습니다.');
    }
    if ($this->isNullorEmptyTitle($KakaoMultiSign->tokens)) {
      throw new BarocertException('인증요청 메시지 제목이 입력되지 않았습니다.');
    }
    if ($this->isNullorEmptyToken($KakaoMultiSign->tokens)) {
      throw new BarocertException('토큰 원문이 입력되지 않았습니다.');
    }
    if (is_null($KakaoMultiSign->tokenType) || empty($KakaoMultiSign->tokenType)) {
      throw new BarocertException('원문 유형이 입력되지 않았습니다.');
    }


    $postdata = json_encode($KakaoMultiSign);
    $result = $this->executeCURL('/KAKAO/MultiSign/' . $ClientCode, true, $postdata);

    $KakaoMultiSignReceipt = new KakaoMultiSignReceipt();
    $KakaoMultiSignReceipt->fromJsonInfo($result);
    return $KakaoMultiSignReceipt;
  }

  /**
   * 전자서명 상태 확인(복수)
   */
  public function getMultiSignStatus($ClientCode, $ReceiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (preg_match("/^[0-9]*$/", $ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($ReceiptID) || empty($ReceiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (preg_match("/^[0-9]*$/", $ReceiptID) == 0) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ReceiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }

    $result = $this->executeCURL('/KAKAO/MultiSign/' . $ClientCode .'/'. $ReceiptID, false , null);

    $KakaoMultiSignStatus = new KakaoMultiSignStatus();
    $KakaoMultiSignStatus->fromJsonInfo($result);
    return $KakaoMultiSignStatus;
  }

  /**
   * 전자서명 검증(복수)
   */
  public function verifyMultiSign($ClientCode, $ReceiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (preg_match("/^[0-9]*$/", $ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($ReceiptID) || empty($ReceiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (preg_match("/^[0-9]*$/", $ReceiptID) == 0) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ReceiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }
    
    $result = $this->executeCURL('/KAKAO/MultiSign/'. $ClientCode .'/'. $ReceiptID, true, null);

    $KakaoMultiSignResult = new KakaoMultiSignResult();
    $KakaoMultiSignResult->fromJsonInfo($result);
    return $KakaoMultiSignResult;
  }

  /**
   * 출금동의 요청
   */
  public function requestCMS($ClientCode, $KakaoCMS)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (preg_match("/^[0-9]*$/", $ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($KakaoCMS) || empty($KakaoCMS)) {
      throw new BarocertException('자동이체 출금동의 요청정보가 입력되지 않았습니다.');
    }
    if (is_null($KakaoCMS->receiverHP) || empty($KakaoCMS->receiverHP)) {
      throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
    }
    if (is_null($KakaoCMS->receiverName) || empty($KakaoCMS->receiverName)) {
      throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
    }
    if (is_null($KakaoCMS->receiverBirthday) || empty($KakaoCMS->receiverBirthday)) {
      throw new BarocertException('생년월일이 입력되지 않았습니다.');
    }
    if (is_null($KakaoCMS->expireIn) || empty($KakaoCMS->expireIn)) {
      throw new BarocertException('만료시간이 입력되지 않았습니다.');
    }
    if (is_null($KakaoCMS->reqTitle) || empty($KakaoCMS->reqTitle)) {
      throw new BarocertException('인증요청 메시지 제목이 입력되지 않았습니다.');
    }
    if (is_null($KakaoCMS->requestCorp) || empty($KakaoCMS->requestCorp)) {
      throw new BarocertException('청구기관명이 입력되지 않았습니다.');
    }
    if (is_null($KakaoCMS->bankName) || empty($KakaoCMS->bankName)) {
      throw new BarocertException('은행명이 입력되지 않았습니다.');
    }
    if (is_null($KakaoCMS->bankAccountNum) || empty($KakaoCMS->bankAccountNum)) {
      throw new BarocertException('계좌번호가 입력되지 않았습니다.');
    }
    if (is_null($KakaoCMS->bankAccountName) || empty($KakaoCMS->bankAccountName)) {
      throw new BarocertException('예금주명이 입력되지 않았습니다.');
    }
    if (is_null($KakaoCMS->bankAccountBirthday) || empty($KakaoCMS->bankAccountBirthday)) {
      throw new BarocertException('예금주 생년월일이 입력되지 않았습니다.');
    }
    if (is_null($KakaoCMS->bankServiceType) || empty($KakaoCMS->bankServiceType)) {
      throw new BarocertException('출금 유형이 입력되지 않았습니다.');
    }

    $postdata = json_encode($KakaoCMS);
    
    $result = $this->executeCURL('/KAKAO/CMS/' . $ClientCode, true, $postdata);

    $KakaoCMSReceipt = new KakaoCMSReceipt();
    $KakaoCMSReceipt->fromJsonInfo($result);
    return $KakaoCMSReceipt;
  }

  /**
   * 출금동의 상태 확인
   */
  public function getCMSStatus($ClientCode, $ReceiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (preg_match("/^[0-9]*$/", $ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($ReceiptID) || empty($ReceiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (preg_match("/^[0-9]*$/", $ReceiptID) == 0) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ReceiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }

    $result = $this->executeCURL('/KAKAO/CMS/' . $ClientCode .'/'. $ReceiptID, false, null);

    $KakaoCMSStatus = new KakaoCMSStatus();
    $KakaoCMSStatus->fromJsonInfo($result);
    return $KakaoCMSStatus;
  }

  /**
   * 출금동의 서명 검증
   */
  public function verifyCMS($ClientCode, $ReceiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (preg_match("/^[0-9]*$/", $ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($ReceiptID) || empty($ReceiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (preg_match("/^[0-9]*$/", $ReceiptID) == 0) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ReceiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }

    $result = $this->executeCURL('/KAKAO/CMS/'. $ClientCode .'/'. $ReceiptID, true, null);

    $KakaoCMSResult = new KakaoCMSResult();
    $KakaoCMSResult->fromJsonInfo($result);
    return $KakaoCMSResult;
  }

  public function isNullorEmptyTitle($multiSignTokens){
    if($multiSignTokens == null) return true;
    foreach($multiSignTokens as $signTokens){
      if($signTokens == null) return true;
      if (is_null($signTokens -> reqTitle) || empty($signTokens -> reqTitle)) {
        return true;
      }
    }
    return false;
  }

  public function isNullorEmptyToken($multiSignTokens){
    if($multiSignTokens == null) return true;
    foreach($multiSignTokens as $signTokens){
      if($signTokens == null) return true;
      if (is_null($signTokens -> token) || empty($signTokens -> token)) {
        return true;
      }
    }
    return false;
  }

}

class KakaoIdentity
{
	public $receiverHP;
	public $receiverName;
	public $receiverBirthday;
	public $reqTitle;
	public $expireIn;
	public $token;
	public $returnURL;
	public $appUseYN;
}

class KakaoIdentityReceipt
{
  public $receiptID;
	public $scheme;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
  }
}

class KakaoIdentityStatus
{
  public $receiptID;
  public $clientCode;
  public $state;
  public $expireIn;
  public $callCenterName;
  public $callCenterNum;
  public $reqTitle;
  public $authCategory;
  public $returnURL;
  public $requestDT;
  public $viewDT;
  public $completeDT;
  public $expireDT;
  public $verifyDT;
  public $scheme;
  public $appUseYN;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->expireIn) ? $this->expireIn = $jsonInfo->expireIn : null;
    isset($jsonInfo->callCenterName) ? $this->callCenterName = $jsonInfo->callCenterName : null;
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;
    isset($jsonInfo->reqTitle) ? $this->reqTitle = $jsonInfo->reqTitle : null;
    isset($jsonInfo->authCategory) ? $this->authCategory = $jsonInfo->authCategory : null;
    isset($jsonInfo->returnURL) ? $this->returnURL = $jsonInfo->returnURL : null;
    isset($jsonInfo->requestDT) ? $this->requestDT = $jsonInfo->requestDT : null;
    isset($jsonInfo->viewDT) ? $this->viewDT = $jsonInfo->viewDT : null;
    isset($jsonInfo->completeDT) ? $this->completeDT = $jsonInfo->completeDT : null;
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->verifyDT) ? $this->verifyDT = $jsonInfo->verifyDT : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
    isset($jsonInfo->appUseYN) ? $this->appUseYN = $jsonInfo->appUseYN : null;
  }
}

class KakaoIdentityResult
{
  public $receiptID;
  public $state;
  public $signedData;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
  }
}



class KakaoSign
{
  public $receiverHP;
  public $receiverName;
  public $receiverBirthday;
  public $reqTitle;
  public $expireIn;
  public $token;
  public $tokenType;
  public $returnURL;
  public $appUseYN;
}

class KakaoSignReceipt
{
  public $receiptID;
  public $scheme;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
  }
}


class KakaoSignStatus
{
  public $receiptID;
  public $clientCode;
  public $state;
  public $expireIn;
  public $callCenterName;
  public $callCenterNum;
  public $reqTitle;
  public $authCategory;
  public $returnURL;
  public $tokenType;
  public $requestDT;
  public $viewDT;
  public $completeDT;
  public $expireDT;
  public $verifyDT;
  public $scheme;
  public $appUseYN;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->expireIn) ? $this->expireIn = $jsonInfo->expireIn : null;
    isset($jsonInfo->callCenterName) ? $this->callCenterName = $jsonInfo->callCenterName : null;
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;
    isset($jsonInfo->reqTitle) ? $this->reqTitle = $jsonInfo->reqTitle : null;
    isset($jsonInfo->authCategory) ? $this->authCategory = $jsonInfo->authCategory : null;
    isset($jsonInfo->returnURL) ? $this->returnURL = $jsonInfo->returnURL : null;
    isset($jsonInfo->tokenType) ? $this->tokenType = $jsonInfo->tokenType : null;
    isset($jsonInfo->requestDT) ? $this->requestDT = $jsonInfo->requestDT : null;
    isset($jsonInfo->viewDT) ? $this->viewDT = $jsonInfo->viewDT : null;
    isset($jsonInfo->completeDT) ? $this->completeDT = $jsonInfo->completeDT : null;
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->verifyDT) ? $this->verifyDT = $jsonInfo->verifyDT : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
    isset($jsonInfo->appUseYN) ? $this->appUseYN = $jsonInfo->appUseYN : null;
  }
}

class KakaoSignResult
{
  public $receiptID;
	public $state;
	public $signedData;
	public $ci;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
  }
}

class KakaoMultiSign
{
  public $receiverHP;
  public $receiverName;
  public $receiverBirthday;
  public $reqTitle;
  public $expireIn;

  public $tokens;

  public $tokenType;
  public $returnURL;
  public $appUseYN;
}

class KakaoMultiSignTokens
{
  public $reqTitle;
  public $token;
}

class KakaoMultiSignReceipt
{
  public $receiptID;
  public $scheme;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
  }
}

class KakaoMultiSignStatus
{
  public $receiptID;
  public $clientCode;
  public $state;
  public $expireIn;
  public $callCenterName;
  public $callCenterNum;
  public $reqTitle;
  public $authCategory;
  public $returnURL;
  public $tokenType;
  public $requestDT;
  public $viewDT;
  public $completeDT;
  public $expireDT;
  public $verifyDT;
  public $scheme;
  public $appUseYN;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->expireIn) ? $this->expireIn = $jsonInfo->expireIn : null;
    isset($jsonInfo->callCenterName) ? $this->callCenterName = $jsonInfo->callCenterName : null;
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;
    isset($jsonInfo->reqTitle) ? $this->reqTitle = $jsonInfo->reqTitle : null;
    isset($jsonInfo->authCategory) ? $this->authCategory = $jsonInfo->authCategory : null;
    isset($jsonInfo->returnURL) ? $this->returnURL = $jsonInfo->returnURL : null;
    isset($jsonInfo->tokenType) ? $this->tokenType = $jsonInfo->tokenType : null;
    isset($jsonInfo->requestDT) ? $this->requestDT = $jsonInfo->requestDT : null;
    isset($jsonInfo->viewDT) ? $this->viewDT = $jsonInfo->viewDT : null;
    isset($jsonInfo->completeDT) ? $this->completeDT = $jsonInfo->completeDT : null;
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->verifyDT) ? $this->verifyDT = $jsonInfo->verifyDT : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
    isset($jsonInfo->appUseYN) ? $this->appUseYN = $jsonInfo->appUseYN : null;
  }
}

class KakaoMultiSignResult
{
  public $receiptID;
	public $state;
	public $multiSignedData;
	public $ci;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->requestID) ? $this->requestID = $jsonInfo->requestID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->multiSignedData) ? $this->multiSignedData = $jsonInfo->multiSignedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
  }
}

class KakaoCMS
{
	public $requestID;
	public $receiverHP;
	public $receiverName;
	public $receiverBirthday;
	public $reqTitle;
	public $expireIn;
	public $returnURL;	
	public $requestCorp;
	public $bankName;
	public $bankAccountNum;
	public $bankAccountName;
	public $bankAccountBirthday;
	public $bankServiceType;
	public $appUseYN;
}


class KakaoCMSReceipt
{
  public $receiptID;
  public $scheme;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
  }
}

class KakaoCMSStatus
{
  public $receiptID;
  public $clientCode;
  public $state;
  public $expireIn;
  public $callCenterName;
  public $callCenterNum;
  public $reqTitle;
  public $authCategory;
  public $returnURL;
  public $tokenType;
  public $requestDT;
  public $viewDT;
  public $completeDT;
  public $expireDT;
  public $verifyDT;
  public $scheme;
  public $appUseYN;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->expireIn) ? $this->expireIn = $jsonInfo->expireIn : null;
    isset($jsonInfo->callCenterName) ? $this->callCenterName = $jsonInfo->callCenterName : null;
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;
    isset($jsonInfo->reqTitle) ? $this->reqTitle = $jsonInfo->reqTitle : null;
    isset($jsonInfo->authCategory) ? $this->authCategory = $jsonInfo->authCategory : null;
    isset($jsonInfo->returnURL) ? $this->returnURL = $jsonInfo->returnURL : null;
    isset($jsonInfo->tokenType) ? $this->tokenType = $jsonInfo->tokenType : null;
    isset($jsonInfo->requestDT) ? $this->requestDT = $jsonInfo->requestDT : null;
    isset($jsonInfo->viewDT) ? $this->viewDT = $jsonInfo->viewDT : null;
    isset($jsonInfo->completeDT) ? $this->completeDT = $jsonInfo->completeDT : null;
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->verifyDT) ? $this->verifyDT = $jsonInfo->verifyDT : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
    isset($jsonInfo->appUseYN) ? $this->appUseYN = $jsonInfo->appUseYN : null;
  }
}

class KakaoCMSResult
{
  public $receiptID;
	public $state;
	public $signedData;
	public $ci;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
  }
}


class BarocertException extends Exception
{
  public function __construct($response, $code = -99999999, Exception $previous = null)
  {
    $Err = json_decode($response);
    if (is_null($Err)) {
      parent::__construct($response, $code);
    } else {
      parent::__construct($Err->message, $Err->code);
    }
  }

  public function __toString()
  {
    return __CLASS__ . ": [{$this->code}]: {$this->message}\n";
  }
}

?>
