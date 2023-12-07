<?php

/**
 * =====================================================================================
 * Class for base module for passcert API SDK. It include base functionality for
 * RESTful web service request and parse json result. It uses Linkhub module
 * to accomplish authentication APIs.
 *
 * This module uses curl and openssl for HTTPS Request. So related modules must
 * be installed and enabled.
 *
 * https://www.linkhub.co.kr
 * Author : lsh (code@linkhubcorp.com)
 * Contributor : jws (code@linkhubcorp.com)
 * Written : 2023-03-13
 * Updated : 2023-11-29
 *
 * Thanks for your interest.
 * We welcome any suggestions, feedbacks, blames or anythings.
 * ======================================================================================
 */

require_once 'Base.php';
require 'Util.php';

class PasscertService extends BaseService
{
  public function __construct($LinkID, $SecretKey)
  {
    $scope = array('441', '442', '443', '444');
    parent::__construct($LinkID, $SecretKey, $scope);
  }

  public function encrypt($data) {
    return parent::encryptTo($data, 'AES');
  }
  
  /**
   * 본인인증 요청
   */
  public function requestIdentity($ClientCode, $PassIdentity)
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
    if (Stringz::isNullorEmpty($PassIdentity)) {
      throw new BarocertException('본인인증 요청정보가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassIdentity->receiverHP)) {
      throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassIdentity->receiverName)) {
      throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassIdentity->reqTitle)) {
      throw new BarocertException('인증요청 메시지 제목이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassIdentity->callCenterNum)) {
      throw new BarocertException('고객센터 연락처가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassIdentity->expireIn)) {
      throw new BarocertException('만료시간이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassIdentity->token)) {
      throw new BarocertException('토큰 원문이 입력되지 않았습니다.');
    }

    $postdata = json_encode($PassIdentity);
    
    $result = parent::executeCURL('/PASS/Identity/' . $ClientCode, true, $postdata);

    $PassIdentityReceipt = new PassIdentityReceipt();
    $PassIdentityReceipt->fromJsonInfo($result);
    return $PassIdentityReceipt;
  }
  
  /**
   * 본인인증 상태확인
   */
  public function getIdentityStatus($ClientCode, $ReceiptID)
  {
    if (Stringz::isNullorEmpty($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (Stringz::isNullorEmpty($ReceiptID) || empty($ReceiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ReceiptID) == 0) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ReceiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }

    $result = parent::executeCURL('/PASS/Identity/' . $ClientCode .'/'. $ReceiptID, false, null);

    $PassIdentityStatus = new PassIdentityStatus();
    $PassIdentityStatus->fromJsonInfo($result);
    return $PassIdentityStatus;
  }

  /**
   * 본인인증 검증
   */
  public function verifyIdentity($ClientCode, $ReceiptID, $PassIdentityVerify)
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
    if (Stringz::isNullorEmpty($PassIdentityVerify)) {
      throw new BarocertException('본인인증 검증 요청 정보가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassIdentityVerify->receiverHP)) {
      throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassIdentityVerify->receiverName)) {
      throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
    }

    $postdata = json_encode($PassIdentityVerify);

    $result = parent::executeCURL('/PASS/Identity/' . $ClientCode .'/'. $ReceiptID, true, $postdata);

    $PassIdentityResult = new PassIdentityResult();
    $PassIdentityResult->fromJsonInfo($result);
    return $PassIdentityResult;
  }

  /**
   * 전자서명 요청
   */
  public function RequestSign($ClientCode, $PassSign)
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
    if (Stringz::isNullorEmpty($PassSign)) {
      throw new BarocertException('전자서명 요청정보가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassSign->receiverHP)) {
      throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassSign->receiverName)) {
      throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassSign->reqTitle)) {
      throw new BarocertException('인증요청 메시지 제목이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassSign->callCenterNum)) {
      throw new BarocertException('고객센터 연락처가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassSign->expireIn)) {
      throw new BarocertException('만료시간이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassSign->token)) {
      throw new BarocertException('토큰 원문이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassSign->tokenType)) {
      throw new BarocertException('원문 유형이 입력되지 않았습니다.');
    }

    $postdata = json_encode($PassSign);

    $result = parent::executeCURL('/PASS/Sign/' . $ClientCode, true,  $postdata);
    $PassSignReceipt = new PassSignReceipt();
    $PassSignReceipt->fromJsonInfo($result);
    return $PassSignReceipt;
  }


  /**
   * 전자서명 상태 확인
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

    $result = parent::executeCURL('/PASS/Sign/'. $ClientCode .'/'. $ReceiptID, false, null);

    $PassSignStatus = new PassSignStatus();
    $PassSignStatus->fromJsonInfo($result);
    return $PassSignStatus;
  }

  /**
   * 전자서명 검증
   */
  public function verifySign($ClientCode, $ReceiptID, $PassSignVerify)
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
    if (Stringz::isNullorEmpty($PassSignVerify)) {
      throw new BarocertException('전자서명 검증 요청 정보가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassSignVerify->receiverHP)) {
      throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassSignVerify->receiverName)) {
      throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
    }
    
    $postdata = json_encode($PassSignVerify);

    $result = parent::executeCURL('/PASS/Sign/'. $ClientCode .'/'. $ReceiptID, true, $postdata);

    $PassSignResult = new PassSignResult();
    $PassSignResult->fromJsonInfo($result);
    return $PassSignResult;
  }

  /**
   * 출금동의 요청
   */
  public function requestCMS($ClientCode, $PassCMS)
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
    if (Stringz::isNullorEmpty($PassCMS)) {
      throw new BarocertException('자동이체 출금동의 요청정보가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassCMS->receiverHP)) {
      throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassCMS->receiverName)) {
      throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassCMS->reqTitle)) {
      throw new BarocertException('인증요청 메시지 제목이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassCMS->callCenterNum)) {
      throw new BarocertException('고객센터 연락처가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassCMS->expireIn)) {
      throw new BarocertException('만료시간이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassCMS->bankName)) {
      throw new BarocertException('출금은행명이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassCMS->bankAccountNum)) {
      throw new BarocertException('출금계좌번호가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassCMS->bankAccountName)) {
      throw new BarocertException('출금계좌 예금주명이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassCMS->bankServiceType)) {
      throw new BarocertException('출금 유형이 입력되지 않았습니다.');
    }

    $postdata = json_encode($PassCMS);
    
    $result = parent::executeCURL('/PASS/CMS/' . $ClientCode, true, $postdata);

    $PassCMSReceipt = new PassCMSReceipt();
    $PassCMSReceipt->fromJsonInfo($result);
    return $PassCMSReceipt;
  }

  /**
   * 출금동의 상태 확인
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

    $result = parent::executeCURL('/PASS/CMS/' . $ClientCode .'/'. $ReceiptID, false, null);

    $PassCMSStatus = new PassCMSStatus();
    $PassCMSStatus->fromJsonInfo($result);
    return $PassCMSStatus;
  }

  /**
   * 출금동의 서명 검증
   */
  public function verifyCMS($ClientCode, $ReceiptID, $PassCMSVerify)
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
    if (Stringz::isNullorEmpty($PassCMSVerify)) {
      throw new BarocertException('출금동의 검증 요청 정보가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassCMSVerify->receiverHP)) {
      throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassCMSVerify->receiverName)) {
      throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
    }

    $postdata = json_encode($PassCMSVerify);

    $result = parent::executeCURL('/PASS/CMS/'. $ClientCode .'/'. $ReceiptID, true, $postdata);

    $PassCMSResult = new PassCMSResult();
    $PassCMSResult->fromJsonInfo($result);
    return $PassCMSResult;
  }

  /**
   * 간편로그인 요청
   */
  public function requestLogin($ClientCode, $PassLogin)
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
    if (Stringz::isNullorEmpty($PassLogin)) {
      throw new BarocertException('간편로그인 요청정보가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassLogin->receiverHP)) {
      throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassLogin->receiverName)) {
      throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassLogin->reqTitle)) {
      throw new BarocertException('인증요청 메시지 제목이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassLogin->callCenterNum)) {
      throw new BarocertException('고객센터 연락처가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassLogin->expireIn)) {
      throw new BarocertException('만료시간이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassLogin->token)) {
      throw new BarocertException('토큰 원문이 입력되지 않았습니다.');
    }

    $postdata = json_encode($PassLogin);
    
    $result = parent::executeCURL('/PASS/Login/' . $ClientCode, true, $postdata);

    $PassLoginReceipt = new PassLoginReceipt();
    $PassLoginReceipt->fromJsonInfo($result);
    return $PassLoginReceipt;
  }

  /**
   * 간편로그인 상태확인
   */
  public function getLoginStatus($ClientCode, $ReceiptID)
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

    $result = parent::executeCURL('/PASS/Login/' . $ClientCode .'/'. $ReceiptID, false, null);

    $PassLoginStatus = new PassLoginStatus();
    $PassLoginStatus->fromJsonInfo($result);
    return $PassLoginStatus;
  }

  /**
   * 간편로그인 검증
   */
  public function verifyLogin($ClientCode, $ReceiptID, $PassLoginVerify)
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
    if (Stringz::isNullorEmpty($PassLoginVerify)) {
      throw new BarocertException('간편로그인 검증 요청 정보가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassLoginVerify->receiverHP)) {
      throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($PassLoginVerify->receiverName)) {
      throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
    }

    $postdata = json_encode($PassLoginVerify);

    $result = parent::executeCURL('/PASS/Login/' . $ClientCode .'/'. $ReceiptID, true, $postdata);

    $PassLoginResult = new PassLoginResult();
    $PassLoginResult->fromJsonInfo($result);
    return $PassLoginResult;
  }

}

class PassIdentity
{
  public $receiverHP;
  public $receiverName;
  public $receiverBirthday;
  public $reqTitle;
  public $reqMessage;
  public $callCenterNum;
  public $expireIn;
  public $token;
  public $userAgreementYN;
  public $receiverInfoYN;
  public $telcoType;
  public $deviceOSType;
  public $appUseYN;
  public $useTssYN;
}

class PassIdentityReceipt
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

class PassIdentityStatus
{
  public $clientCode;
  public $receiptID;
  public $state;
  public $expireIn;
  public $callCenterName;
  public $callCenterNum;
  public $reqTitle;
  public $reqMessage;
  public $requestDT;
  public $completeDT;
  public $expireDT;
  public $rejectDT;
  public $tokenType;
  public $userAgreementYN;
  public $receiverInfoYN;
  public $telcoType;
  public $deviceOSType;
  public $scheme;
  public $appUseYN;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->expireIn) ? $this->expireIn = $jsonInfo->expireIn : null;
    isset($jsonInfo->callCenterName) ? $this->callCenterName = $jsonInfo->callCenterName : null;
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;
    isset($jsonInfo->reqTitle) ? $this->reqTitle = $jsonInfo->reqTitle : null;
    isset($jsonInfo->reqMessage) ? $this->reqMessage = $jsonInfo->reqMessage : null;
    isset($jsonInfo->requestDT) ? $this->requestDT = $jsonInfo->requestDT : null;
    isset($jsonInfo->completeDT) ? $this->completeDT = $jsonInfo->completeDT : null;
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->rejectDT) ? $this->rejectDT = $jsonInfo->rejectDT : null;
    isset($jsonInfo->tokenType) ? $this->tokenType = $jsonInfo->tokenType : null;
    isset($jsonInfo->userAgreementYN) ? $this->userAgreementYN = $jsonInfo->userAgreementYN : null;
    isset($jsonInfo->receiverInfoYN) ? $this->receiverInfoYN = $jsonInfo->receiverInfoYN : null;
    isset($jsonInfo->telcoType) ? $this->telcoType = $jsonInfo->telcoType : null;
    isset($jsonInfo->deviceOSType) ? $this->deviceOSType = $jsonInfo->deviceOSType : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
    isset($jsonInfo->appUseYN) ? $this->appUseYN = $jsonInfo->appUseYN : null;
  }
}

class PassIdentityVerify
{
  public $receiverHP;
  public $receiverName;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiverHP) ? $this->receiverHP = $jsonInfo->receiverHP : null;
    isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
  }
}

class PassIdentityResult
{
  public $receiptID;
  public $state;
  public $receiverName;
  public $receiverYear;
  public $receiverDay;
  public $receiverGender;
  public $receiverForeign;
  public $receiverTelcoType;
  public $signedData;
  public $ci;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
    isset($jsonInfo->receiverYear) ? $this->receiverYear = $jsonInfo->receiverYear : null;
    isset($jsonInfo->receiverDay) ? $this->receiverDay = $jsonInfo->receiverDay : null;
    isset($jsonInfo->receiverGender) ? $this->receiverGender = $jsonInfo->receiverGender : null;
    isset($jsonInfo->receiverForeign) ? $this->receiverForeign = $jsonInfo->receiverForeign : null;
    isset($jsonInfo->receiverTelcoType) ? $this->receiverTelcoType = $jsonInfo->receiverTelcoType : null;
    isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
  }
}

class PassSign
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
  public $userAgreementYN;
  public $receiverInfoYN;
  public $originalTypeCode;
  public $originalURL;
  public $originalFormatCode;
  public $telcoType;
  public $deviceOSType;
  public $appUseYN;
  public $useTssYN;
}

class PassSignReceipt
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

class PassSignStatus
{
  public $clientCode;
  public $receiptID;
  public $state;
  public $expireIn;
  public $callCenterName;
  public $callCenterNum;
  public $reqTitle;
  public $reqMessage;
  public $requestDT;
  public $completeDT;
  public $expireDT;
  public $rejectDT;
  public $tokenType;
  public $userAgreementYN;
  public $receiverInfoYN;
  public $telcoType;
  public $deviceOSType;
  public $originalTypeCode;
  public $originalURL;
  public $originalFormatCode;
  public $scheme;
  public $appUseYN;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->expireIn) ? $this->expireIn = $jsonInfo->expireIn : null;
    isset($jsonInfo->callCenterName) ? $this->callCenterName = $jsonInfo->callCenterName : null;
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;
    isset($jsonInfo->reqTitle) ? $this->reqTitle = $jsonInfo->reqTitle : null;
    isset($jsonInfo->reqMessage) ? $this->reqMessage = $jsonInfo->reqMessage : null;
    isset($jsonInfo->requestDT) ? $this->requestDT = $jsonInfo->requestDT : null;
    isset($jsonInfo->completeDT) ? $this->completeDT = $jsonInfo->completeDT : null;
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->rejectDT) ? $this->rejectDT = $jsonInfo->rejectDT : null;
    isset($jsonInfo->tokenType) ? $this->tokenType = $jsonInfo->tokenType : null;
    isset($jsonInfo->userAgreementYN) ? $this->userAgreementYN = $jsonInfo->userAgreementYN : null;
    isset($jsonInfo->receiverInfoYN) ? $this->receiverInfoYN = $jsonInfo->receiverInfoYN : null;
    isset($jsonInfo->telcoType) ? $this->telcoType = $jsonInfo->telcoType : null;
    isset($jsonInfo->deviceOSType) ? $this->deviceOSType = $jsonInfo->deviceOSType : null;
    isset($jsonInfo->originalTypeCode) ? $this->originalTypeCode = $jsonInfo->originalTypeCode : null;
    isset($jsonInfo->originalURL) ? $this->originalURL = $jsonInfo->originalURL : null;
    isset($jsonInfo->originalFormatCode) ? $this->originalFormatCode = $jsonInfo->originalFormatCode : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
    isset($jsonInfo->appUseYN) ? $this->appUseYN = $jsonInfo->appUseYN : null;
  }
}

class PassSignVerify
{
  public $receiverHP;
  public $receiverName;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiverHP) ? $this->receiverHP = $jsonInfo->receiverHP : null;
    isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
  }
}

class PassSignResult
{
  public $receiptID;
  public $state;
  public $receiverHP;
  public $receiverName;
  public $receiverYear;
  public $receiverDay;
  public $receiverGender;
  public $receiverForeign;
  public $receiverTelcoType;
  public $signedData;
  public $ci;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->receiverHP) ? $this->receiverHP = $jsonInfo->receiverHP : null;
    isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
    isset($jsonInfo->receiverYear) ? $this->receiverYear = $jsonInfo->receiverYear : null;
    isset($jsonInfo->receiverDay) ? $this->receiverDay = $jsonInfo->receiverDay : null;
    isset($jsonInfo->receiverGender) ? $this->receiverGender = $jsonInfo->receiverGender : null;
    isset($jsonInfo->receiverForeign) ? $this->receiverForeign = $jsonInfo->receiverForeign : null;
    isset($jsonInfo->receiverTelcoType) ? $this->receiverTelcoType = $jsonInfo->receiverTelcoType : null;
    isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
  }
}

class PassCMS
{
  public $receiverHP;
  public $receiverName;
  public $receiverBirthday;
  public $reqTitle;
  public $reqMessage;
  public $callCenterNum;
  public $expireIn;
  public $userAgreementYN;	
  public $receiverInfoYN;	
  public $bankName;	
  public $bankAccountNum;
  public $bankAccountName;
  public $bankWithdraw;
  public $bankServiceType;
  public $telcoType;
  public $deviceOSType;
  public $appUseYN;
  public $useTssYN;
}

class PassCMSReceipt
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

class PassCMSStatus
{
  public $clientCode;
  public $receiptID;
  public $state;
  public $expireIn;
  public $callCenterName;
  public $callCenterNum;
  public $reqTitle;
  public $reqMessage;
  public $requestDT;
  public $completeDT;
  public $expireDT;
  public $rejectDT;
  public $tokenType;
  public $userAgreementYN;
  public $receiverInfoYN;
  public $telcoType;
  public $deviceOSType;
  public $scheme;
  public $appUseYN;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->expireIn) ? $this->expireIn = $jsonInfo->expireIn : null;
    isset($jsonInfo->callCenterName) ? $this->callCenterName = $jsonInfo->callCenterName : null;
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;
    isset($jsonInfo->reqTitle) ? $this->reqTitle = $jsonInfo->reqTitle : null;
    isset($jsonInfo->reqMessage) ? $this->reqMessage = $jsonInfo->reqMessage : null;
    isset($jsonInfo->requestDT) ? $this->requestDT = $jsonInfo->requestDT : null;
    isset($jsonInfo->completeDT) ? $this->completeDT = $jsonInfo->completeDT : null;
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->rejectDT) ? $this->rejectDT = $jsonInfo->rejectDT : null;
    isset($jsonInfo->tokenType) ? $this->tokenType = $jsonInfo->tokenType : null;
    isset($jsonInfo->userAgreementYN) ? $this->userAgreementYN = $jsonInfo->userAgreementYN : null;
    isset($jsonInfo->receiverInfoYN) ? $this->receiverInfoYN = $jsonInfo->receiverInfoYN : null;
    isset($jsonInfo->telcoType) ? $this->telcoType = $jsonInfo->telcoType : null;
    isset($jsonInfo->deviceOSType) ? $this->deviceOSType = $jsonInfo->deviceOSType : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
    isset($jsonInfo->appUseYN) ? $this->appUseYN = $jsonInfo->appUseYN : null;
  }
}

class PassCMSVerify
{
  public $receiverHP;
  public $receiverName;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiverHP) ? $this->receiverHP = $jsonInfo->receiverHP : null;
    isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
  }
}

class PassCMSResult
{
  public $receiptID;
  public $state;
  public $receiverHP;
  public $receiverName;
  public $receiverYear;
  public $receiverDay;
  public $receiverGender;
  public $receiverForeign;
  public $receiverTelcoType;
  public $signedData;
  public $ci;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->receiverHP) ? $this->receiverHP = $jsonInfo->receiverHP : null;
    isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
    isset($jsonInfo->receiverYear) ? $this->receiverYear = $jsonInfo->receiverYear : null;
    isset($jsonInfo->receiverDay) ? $this->receiverDay = $jsonInfo->receiverDay : null;
    isset($jsonInfo->receiverGender) ? $this->receiverGender = $jsonInfo->receiverGender : null;
    isset($jsonInfo->receiverForeign) ? $this->receiverForeign = $jsonInfo->receiverForeign : null;
    isset($jsonInfo->receiverTelcoType) ? $this->receiverTelcoType = $jsonInfo->receiverTelcoType : null;
    isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
  }
}

class PassLogin
{
  public $receiverHP;
  public $receiverName;
  public $receiverBirthday;
  public $reqTitle;
  public $reqMessage;
  public $callCenterNum;
  public $expireIn;
  public $token;
  public $userAgreementYN;
  public $receiverInfoYN;
  public $telcoType;
  public $deviceOSType;
  public $appUseYN;
  public $useTssYN;
}

class PassLoginReceipt
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

class PassLoginStatus
{
  public $clientCode;
  public $receiptID;
  public $state;
  public $expireIn;
  public $callCenterName;
  public $callCenterNum;
  public $reqTitle;
  public $reqMessage;
  public $requestDT;
  public $completeDT;
  public $expireDT;
  public $rejectDT;
  public $tokenType;
  public $userAgreementYN;
  public $receiverInfoYN;
  public $telcoType;
  public $deviceOSType;
  public $scheme;
  public $appUseYN;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->expireIn) ? $this->expireIn = $jsonInfo->expireIn : null;
    isset($jsonInfo->callCenterName) ? $this->callCenterName = $jsonInfo->callCenterName : null;
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;
    isset($jsonInfo->reqTitle) ? $this->reqTitle = $jsonInfo->reqTitle : null;
    isset($jsonInfo->reqMessage) ? $this->reqMessage = $jsonInfo->reqMessage : null;
    isset($jsonInfo->requestDT) ? $this->requestDT = $jsonInfo->requestDT : null;
    isset($jsonInfo->completeDT) ? $this->completeDT = $jsonInfo->completeDT : null;
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->rejectDT) ? $this->rejectDT = $jsonInfo->rejectDT : null;
    isset($jsonInfo->tokenType) ? $this->tokenType = $jsonInfo->tokenType : null;
    isset($jsonInfo->userAgreementYN) ? $this->userAgreementYN = $jsonInfo->userAgreementYN : null;
    isset($jsonInfo->receiverInfoYN) ? $this->receiverInfoYN = $jsonInfo->receiverInfoYN : null;
    isset($jsonInfo->telcoType) ? $this->telcoType = $jsonInfo->telcoType : null;
    isset($jsonInfo->deviceOSType) ? $this->deviceOSType = $jsonInfo->deviceOSType : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
    isset($jsonInfo->appUseYN) ? $this->appUseYN = $jsonInfo->appUseYN : null;
  }
}

class PassLoginVerify
{
  public $receiverHP;
  public $receiverName;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiverHP) ? $this->receiverHP = $jsonInfo->receiverHP : null;
    isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
  }
}

class PassLoginResult
{
  public $receiptID;
  public $state;
  public $receiverName;
  public $receiverYear;
  public $receiverDay;
  public $receiverGender;
  public $receiverForeign;
  public $receiverTelcoType;
  public $signedData;
  public $ci;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
    isset($jsonInfo->receiverYear) ? $this->receiverYear = $jsonInfo->receiverYear : null;
    isset($jsonInfo->receiverDay) ? $this->receiverDay = $jsonInfo->receiverDay : null;
    isset($jsonInfo->receiverGender) ? $this->receiverGender = $jsonInfo->receiverGender : null;
    isset($jsonInfo->receiverForeign) ? $this->receiverForeign = $jsonInfo->receiverForeign : null;
    isset($jsonInfo->receiverTelcoType) ? $this->receiverTelcoType = $jsonInfo->receiverTelcoType : null;
    isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
  }
}

?>
