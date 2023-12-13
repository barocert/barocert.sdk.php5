<?php

/**
 * =====================================================================================
 * Class for base module for Navercert API SDK. It include base functionality for
 * RESTful web service request and parse json result. It uses Linkhub module
 * to accomplish authentication APIs.
 *
 * This module uses curl and openssl for HTTPS Request. So related modules must
 * be installed and enabled.
 *
 * https://www.linkhub.co.kr
 * Author : csh (code@linkhubcorp.com)
 * Written : 2023-09-01
 * Updated : 2023-12-13
 *
 * Thanks for your interest.
 * We welcome any suggestions, feedbacks, blames or anythings.
 * ======================================================================================
 */

require_once 'Base.php';
require 'Util.php';

class NavercertService extends BaseService
{
  public function __construct($LinkID, $SecretKey)
  {
    $scope = array('421', '422', '423', '424');
    parent::__construct($LinkID, $SecretKey, $scope);
  }

  public function encrypt($data) {
    return parent::encryptTo($data, 'AES');
  }

  public function sha256($data) {
    return parent::sha256URLEncode($data);
  }

  /**
   * 본인인증 요청
   */
  public function requestIdentity($ClientCode, $NaverIdentity)
  {
    if (Stringz::isNullorEmpty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (Stringz::isNullorEmpty($NaverIdentity)) {
      throw new BarocertException('본인인증 요청정보가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverIdentity->receiverHP)) {
      throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverIdentity->receiverName)) {
      throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverIdentity->receiverBirthday)) {
      throw new BarocertException('생년월일이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverIdentity->callCenterNum)) {
      throw new BarocertException('고객센터 연락처가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverIdentity->expireIn)) {
      throw new BarocertException('만료시간이 입력되지 않았습니다.');
    }

    $postdata = json_encode($NaverIdentity);
    
    $result = parent::executeCURL('/NAVER/Identity/' . $ClientCode, true, $postdata);

    $NaverIdentityReceipt = new NaverIdentityReceipt();
    $NaverIdentityReceipt->fromJsonInfo($result);
    return $NaverIdentityReceipt;
  }

  /**
   * 본인인증 상태확인
   */
  public function getIdentityStatus($ClientCode, $ReceiptID)
  {
    if (Stringz::isNullorEmpty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (Stringz::isNullorEmpty($ReceiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ReceiptID) == 0) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ReceiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }

    $result = parent::executeCURL('/NAVER/Identity/' . $ClientCode .'/'. $ReceiptID, false, null);

    $NaverIdentityStatus = new NaverIdentityStatus();
    $NaverIdentityStatus->fromJsonInfo($result);
    return $NaverIdentityStatus;
  }

  /**
   * 본인인증 검증
   */
  public function verifyIdentity($ClientCode, $ReceiptID)
  {
    if (Stringz::isNullorEmpty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (Stringz::isNullorEmpty($ReceiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ReceiptID) == 0) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ReceiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }

    $result = parent::executeCURL('/NAVER/Identity/' . $ClientCode .'/'. $ReceiptID, true, null);

    $NaverIdentityResult = new NaverIdentityResult();
    $NaverIdentityResult->fromJsonInfo($result);
    return $NaverIdentityResult;
  }

  /**
   * 전자서명 요청(단건)
   */
  public function RequestSign($ClientCode, $NaverSign)
  {
    if (Stringz::isNullorEmpty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (Stringz::isNullorEmpty($NaverSign)) {
      throw new BarocertException('전자서명 요청정보가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverSign->receiverHP)) {
      throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverSign->receiverName)) {
      throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverSign->receiverBirthday)) {
      throw new BarocertException('생년월일이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverSign->callCenterNum)) {
      throw new BarocertException('고객센터 연락처가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverSign->expireIn)) {
      throw new BarocertException('만료시간이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverSign->reqTitle)) {
      throw new BarocertException('인증요청 메시지 제목이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverSign->token)) {
      throw new BarocertException('토큰 원문이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverSign->tokenType)) {
      throw new BarocertException('원문 유형이 입력되지 않았습니다.');
    }

    $postdata = json_encode($NaverSign);

    $result = parent::executeCURL('/NAVER/Sign/' . $ClientCode, true,  $postdata);

    $NaverSignReceipt = new NaverSignReceipt();
    $NaverSignReceipt->fromJsonInfo($result);
    return $NaverSignReceipt;
  }


  /**
   * 전자서명 상태 확인(단건)
   */
  public function getSignStatus($ClientCode, $ReceiptID)
  {
    if (Stringz::isNullorEmpty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (Stringz::isNullorEmpty($ReceiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ReceiptID) == 0) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ReceiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }

    $result = parent::executeCURL('/NAVER/Sign/'. $ClientCode .'/'. $ReceiptID, false, null);

    $NaverSignStatus = new NaverSignStatus();
    $NaverSignStatus->fromJsonInfo($result);
    return $NaverSignStatus;
  }

  /**
   * 전자서명 검증(단건)
   */
  public function verifySign($ClientCode, $ReceiptID)
  {
    if (Stringz::isNullorEmpty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (Stringz::isNullorEmpty($ReceiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ReceiptID) == 0) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ReceiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }
    
    $result = parent::executeCURL('/NAVER/Sign/'. $ClientCode .'/'. $ReceiptID, true, null);

    $NaverSignResult = new NaverSignResult();
    $NaverSignResult->fromJsonInfo($result);
    return $NaverSignResult;
  }

  /**
   * 전자서명 요청(복수)
   */
  public function requestMultiSign($ClientCode, $NaverMultiSign)
  {
    if (Stringz::isNullorEmpty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (Stringz::isNullorEmpty($NaverMultiSign)) {
      throw new BarocertException('전자서명 요청정보가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverMultiSign->receiverHP)) {
      throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverMultiSign->receiverName)) {
      throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverMultiSign->receiverBirthday)) {
      throw new BarocertException('생년월일이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverMultiSign->callCenterNum)) {
      throw new BarocertException('고객센터 연락처가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverMultiSign->expireIn)) {
      throw new BarocertException('만료시간이 입력되지 않았습니다.');
    }
    if ($this->isNullorEmptyToken($NaverMultiSign->tokens)) {
      throw new BarocertException('토큰 원문이 입력되지 않았습니다.');
    }
    if ($this->isNullorEmptyTokenType($NaverMultiSign->tokens)) {
      throw new BarocertException('원문 유형이 입력되지 않았습니다.');
    }

    $postdata = json_encode($NaverMultiSign);
    $result = parent::executeCURL('/NAVER/MultiSign/' . $ClientCode, true, $postdata);

    $NaverMultiSignReceipt = new NaverMultiSignReceipt();
    $NaverMultiSignReceipt->fromJsonInfo($result);
    return $NaverMultiSignReceipt;
  }

  /**
   * 전자서명 상태 확인(복수)
   */
  public function getMultiSignStatus($ClientCode, $ReceiptID)
  {
    if (Stringz::isNullorEmpty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (Stringz::isNullorEmpty($ReceiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ReceiptID) == 0) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ReceiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }

    $result = parent::executeCURL('/NAVER/MultiSign/' . $ClientCode .'/'. $ReceiptID, false , null);

    $NaverMultiSignStatus = new NaverMultiSignStatus();
    $NaverMultiSignStatus->fromJsonInfo($result);
    return $NaverMultiSignStatus;
  }

  /**
   * 전자서명 검증(복수)
   */
  public function verifyMultiSign($ClientCode, $ReceiptID)
  {
    if (Stringz::isNullorEmpty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (Stringz::isNullorEmpty($ReceiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ReceiptID) == 0) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ReceiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }
    
    $result = parent::executeCURL('/NAVER/MultiSign/'. $ClientCode .'/'. $ReceiptID, true, null);

    $NaverMultiSignResult = new NaverMultiSignResult();
    $NaverMultiSignResult->fromJsonInfo($result);
    return $NaverMultiSignResult;
  }

  /**
   * 출금동의 요청
   */
  public function requestCMS($ClientCode, $NaverCMS)
  {
    if (Stringz::isNullorEmpty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (Stringz::isNullorEmpty($NaverCMS)) {
      throw new BarocertException('출금동의 요청정보가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverCMS->receiverHP)) {
      throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverCMS->receiverName)) {
      throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverCMS->receiverBirthday)) {
      throw new BarocertException('생년월일이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverCMS->callCenterNum)) {
      throw new BarocertException('고객센터 연락처가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverCMS->expireIn)) {
      throw new BarocertException('만료시간이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverCMS->requestCorp)) {
      throw new BarocertException('청구기관명이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverCMS->bankName)) {
      throw new BarocertException('은행명이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverCMS->bankAccountNum)) {
      throw new BarocertException('계좌번호가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverCMS->bankAccountName)) {
      throw new BarocertException('예금주명이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($NaverCMS->bankAccountBirthday)) {
      throw new BarocertException('예금주 생년월일이 입력되지 않았습니다.');
    }

    $postdata = json_encode($NaverCMS);
    
    $result = parent::executeCURL('/NAVER/CMS/' . $ClientCode, true, $postdata);

    $NaverCMSReceipt = new NaverCMSReceipt();
    $NaverCMSReceipt->fromJsonInfo($result);
    return $NaverCMSReceipt;
  }

  /**
   * 출금동의 상태확인
   */
  public function getCMSStatus($ClientCode, $ReceiptID)
  {
    if (Stringz::isNullorEmpty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (Stringz::isNullorEmpty($ReceiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ReceiptID) == 0) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ReceiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }

    $result = parent::executeCURL('/NAVER/CMS/' . $ClientCode .'/'. $ReceiptID, false, null);

    $NaverCMSStatus = new NaverCMSStatus();
    $NaverCMSStatus->fromJsonInfo($result);
    return $NaverCMSStatus;
  }

  /**
   * 출금동의 검증
   */
  public function verifyCMS($ClientCode, $ReceiptID)
  {
    if (Stringz::isNullorEmpty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (Stringz::isNullorEmpty($ReceiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ReceiptID) == 0) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ReceiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }

    $result = parent::executeCURL('/NAVER/CMS/' . $ClientCode .'/'. $ReceiptID, true, null);

    $NaverCMSResult = new NaverCMSResult();
    $NaverCMSResult->fromJsonInfo($result);
    return $NaverCMSResult;
  }
  
  public function isNullorEmptyTokenType($multiSignTokens){
    if($multiSignTokens == null) return true;
    foreach($multiSignTokens as $signTokens){
      if($signTokens == null) return true;
      if (is_null($signTokens -> tokenType) || empty($signTokens -> tokenType)) {
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

class NaverIdentity
{
  public $receiverHP;
  public $receiverName;
  public $receiverBirthday;
  public $callCenterNum;
  public $expireIn;
  public $returnURL;
  public $deviceOSType;
  public $appUseYN;
}

class NaverIdentityReceipt
{
  public $receiptID;
  public $scheme;
  public $marketUrl;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
    isset($jsonInfo->marketUrl) ? $this->marketUrl = $jsonInfo->marketUrl : null;
  }
}

class NaverIdentityStatus
{
  public $receiptID;
  public $clientCode;
  public $state;
  public $expireIn; 
  public $callCenterName;
  public $callCenterNum;
  public $returnURL;
  public $expireDT;
  public $scheme;
  public $deviceOSType;
  public $appUseYN;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->expireIn) ? $this->expireIn = $jsonInfo->expireIn : null;                    // deprecated
    isset($jsonInfo->callCenterName) ? $this->callCenterName = $jsonInfo->callCenterName : null;  // deprecated
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;     // deprecated
    isset($jsonInfo->returnURL) ? $this->returnURL = $jsonInfo->returnURL : null;                 // deprecated
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;                          // deprecated
    isset($jsonInfo->deviceOSType) ? $this->deviceOSType = $jsonInfo->deviceOSType : null;        // deprecated
    isset($jsonInfo->appUseYN) ? $this->appUseYN = $jsonInfo->appUseYN : null;                    // deprecated
  }
}

class NaverIdentityResult
{
  public $receiptID;
  public $state;
  public $receiverName;
  public $receiverYear;
  public $receiverDay;
  public $receiverHP;
  public $receiverGender;
  public $receiverEmail;
  public $receiverForeign;
  public $signedData;
  public $ci;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
    isset($jsonInfo->receiverYear) ? $this->receiverYear = $jsonInfo->receiverYear : null;
    isset($jsonInfo->receiverDay) ? $this->receiverDay = $jsonInfo->receiverDay : null;
    isset($jsonInfo->receiverHP) ? $this->receiverHP = $jsonInfo->receiverHP : null;
    isset($jsonInfo->receiverGender) ? $this->receiverGender = $jsonInfo->receiverGender : null;
    isset($jsonInfo->receiverEmail) ? $this->receiverEmail = $jsonInfo->receiverEmail : null;
    isset($jsonInfo->receiverForeign) ? $this->receiverForeign = $jsonInfo->receiverForeign : null;
    isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
  }
}

class NaverSign
{
  public $receiverHP;
  public $receiverName;
  public $receiverBirthday;
  public $reqTitle;
  public $reqMessage;
  public $callCenterNum;
  public $expireIn;
  public $token;
  public $tokenType;
  public $returnURL;
  public $deviceOSType;
  public $appUseYN;
}

class NaverSignReceipt
{
  public $receiptID;
  public $scheme;
  public $marketUrl;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
    isset($jsonInfo->marketUrl) ? $this->marketUrl = $jsonInfo->marketUrl : null;
  }
}

class NaverSignStatus
{
  public $receiptID;
  public $clientCode;
  public $state;
  public $expireIn;
  public $callCenterName;
  public $callCenterNum;
  public $reqTitle;
  public $returnURL;
  public $tokenType;
  public $expireDT;
  public $scheme;
  public $deviceOSType;
  public $appUseYN;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->expireIn) ? $this->expireIn = $jsonInfo->expireIn : null;                    // deprecated
    isset($jsonInfo->callCenterName) ? $this->callCenterName = $jsonInfo->callCenterName : null;  // deprecated
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;     // deprecated
    isset($jsonInfo->reqTitle) ? $this->reqTitle = $jsonInfo->reqTitle : null;                    // deprecated
    isset($jsonInfo->returnURL) ? $this->returnURL = $jsonInfo->returnURL : null;                 // deprecated
    isset($jsonInfo->tokenType) ? $this->tokenType = $jsonInfo->tokenType : null;                 // deprecated
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;                          // deprecated
    isset($jsonInfo->deviceOSType) ? $this->deviceOSType = $jsonInfo->deviceOSType : null;        // deprecated
    isset($jsonInfo->appUseYN) ? $this->appUseYN = $jsonInfo->appUseYN : null;                    // deprecated
  }
}

class NaverSignResult
{
  public $receiptID;
  public $state;
  public $receiverName;
  public $receiverYear;
  public $receiverDay;
  public $receiverHP;
  public $receiverGender;
  public $receiverEmail;
  public $receiverForeign;
  public $signedData;
  public $ci;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
    isset($jsonInfo->receiverYear) ? $this->receiverYear = $jsonInfo->receiverYear : null;
    isset($jsonInfo->receiverDay) ? $this->receiverDay = $jsonInfo->receiverDay : null;
    isset($jsonInfo->receiverHP) ? $this->receiverHP = $jsonInfo->receiverHP : null;
    isset($jsonInfo->receiverGender) ? $this->receiverGender = $jsonInfo->receiverGender : null;
    isset($jsonInfo->receiverEmail) ? $this->receiverEmail = $jsonInfo->receiverEmail : null;
    isset($jsonInfo->receiverForeign) ? $this->receiverForeign = $jsonInfo->receiverForeign : null;
    isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
  }
}

class NaverMultiSign
{
  public $receiverHP;
  public $receiverName;
  public $receiverBirthday;
  public $reqTitle;
  public $reqMessage;
  public $callCenterNum;
  public $expireIn;
  public $tokens;
  public $returnURL;
  public $deviceOSType;
  public $appUseYN;
}

class NaverMultiSignTokens
{
  public $tokenType;
  public $token;
}

class NaverMultiSignReceipt
{
  public $receiptID;
  public $scheme;
  public $marketUrl;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
    isset($jsonInfo->marketUrl) ? $this->marketUrl = $jsonInfo->marketUrl : null;
  }
}

class NaverMultiSignStatus
{
  public $receiptID;
  public $clientCode;
  public $state;
  public $expireIn;
  public $callCenterName;
  public $callCenterNum;
  public $reqTitle;
  public $returnURL;
  public $tokenTypes;
  public $expireDT;
  public $scheme;
  public $deviceOSType;
  public $appUseYN;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->expireIn) ? $this->expireIn = $jsonInfo->expireIn : null;                    // deprecated
    isset($jsonInfo->callCenterName) ? $this->callCenterName = $jsonInfo->callCenterName : null;  // deprecated
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;     // deprecated
    isset($jsonInfo->reqTitle) ? $this->reqTitle = $jsonInfo->reqTitle : null;                    // deprecated
    isset($jsonInfo->returnURL) ? $this->returnURL = $jsonInfo->returnURL : null;                 // deprecated
    isset($jsonInfo->tokenTypes) ? $this->tokenTypes = $jsonInfo->tokenTypes : null;              // deprecated
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;                          // deprecated
    isset($jsonInfo->deviceOSType) ? $this->deviceOSType = $jsonInfo->deviceOSType : null;        // deprecated
    isset($jsonInfo->appUseYN) ? $this->appUseYN = $jsonInfo->appUseYN : null;                    // deprecated
  }
}

class NaverMultiSignResult
{
  public $receiptID;
  public $state;
  public $receiverName;
  public $receiverYear;
  public $receiverDay;
  public $receiverHP;
  public $receiverGender;
  public $receiverEmail;
  public $receiverForeign;
  public $multiSignedData;
  public $ci;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
    isset($jsonInfo->receiverYear) ? $this->receiverYear = $jsonInfo->receiverYear : null;
    isset($jsonInfo->receiverDay) ? $this->receiverDay = $jsonInfo->receiverDay : null;
    isset($jsonInfo->receiverHP) ? $this->receiverHP = $jsonInfo->receiverHP : null;
    isset($jsonInfo->receiverGender) ? $this->receiverGender = $jsonInfo->receiverGender : null;
    isset($jsonInfo->receiverEmail) ? $this->receiverEmail = $jsonInfo->receiverEmail : null;
    isset($jsonInfo->receiverForeign) ? $this->receiverForeign = $jsonInfo->receiverForeign : null;
    isset($jsonInfo->multiSignedData) ? $this->multiSignedData = $jsonInfo->multiSignedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
  }
}

class NaverCMS
{
  public $receiverHP;
  public $receiverName;
  public $receiverBirthday;
  public $callCenterNum;
  public $reqTitle;
  public $reqMessage;
  public $expireIn;
  public $requestCorp;
  public $bankName;
  public $bankAccountNum;
  public $bankAccountName;
  public $bankAccountBirthday;
  public $returnURL;
  public $deviceOSType;
  public $appUseYN;
}

class NaverCMSReceipt
{
  public $receiptID;
  public $scheme;
  public $marketUrl;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
    isset($jsonInfo->marketUrl) ? $this->marketUrl = $jsonInfo->marketUrl : null;
  }
}

class NaverCMSStatus
{
  public $receiptID;
  public $clientCode;
  public $state;
  public $expireDT;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
  }
}

class NaverCMSResult
{
  public $receiptID;
  public $state;
  public $receiverName;
  public $receiverYear;
  public $receiverDay;
  public $receiverHP;
  public $receiverGender;
  public $receiverEmail;
  public $receiverForeign;
  public $signedData;
  public $ci;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
    isset($jsonInfo->receiverYear) ? $this->receiverYear = $jsonInfo->receiverYear : null;
    isset($jsonInfo->receiverDay) ? $this->receiverDay = $jsonInfo->receiverDay : null;
    isset($jsonInfo->receiverHP) ? $this->receiverHP = $jsonInfo->receiverHP : null;
    isset($jsonInfo->receiverGender) ? $this->receiverGender = $jsonInfo->receiverGender : null;
    isset($jsonInfo->receiverEmail) ? $this->receiverEmail = $jsonInfo->receiverEmail : null;
    isset($jsonInfo->receiverForeign) ? $this->receiverForeign = $jsonInfo->receiverForeign : null;
    isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
  }
}

?>
