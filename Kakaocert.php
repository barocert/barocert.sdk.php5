<?php

require_once 'Base.php';
require 'Util.php';

class KakaocertService extends BaseService
{
  public function __construct($LinkID, $SecretKey)
  {
    $scope = array('401', '402', '403', '404', '405');
    parent::__construct($LinkID, $SecretKey, $scope);
  }

  public function encrypt($data) {
    return parent::encryptTo($data, 'AES');
  }
  
  // deprecated
  public function sha256_base64url($data) {
    return parent::sha256ToBase64url($data);
  }

  public function sha256_base64url_file($data) {
    return parent::sha256ToBase64urlFile($data);
  }

  /**
   * 본인인증 요청
   */
  public function requestIdentity($ClientCode, $KakaoIdentity)
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
    if (Stringz::isNullorEmpty($KakaoIdentity)) {
      throw new BarocertException('본인인증 요청정보가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoIdentity->receiverHP)) {
      throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoIdentity->receiverName)) {
      throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoIdentity->receiverBirthday)) {
      throw new BarocertException('생년월일이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoIdentity->expireIn)) {
      throw new BarocertException('만료시간이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoIdentity->reqTitle)) {
      throw new BarocertException('인증요청 메시지 제목이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoIdentity->token)) {
      throw new BarocertException('토큰 원문이 입력되지 않았습니다.');
    }

    $postdata = json_encode($KakaoIdentity);
    
    $result = parent::executeCURL('/KAKAO/Identity/' . $ClientCode, true, $postdata);

    $KakaoIdentityReceipt = new KakaoIdentityReceipt();
    $KakaoIdentityReceipt->fromJsonInfo($result);
    return $KakaoIdentityReceipt;
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

    $result = parent::executeCURL('/KAKAO/Identity/' . $ClientCode .'/'. $ReceiptID, false, null);

    $KakaoIdentityStatus = new KakaoIdentityStatus();
    $KakaoIdentityStatus->fromJsonInfo($result);
    return $KakaoIdentityStatus;
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

    $result = parent::executeCURL('/KAKAO/Identity/' . $ClientCode .'/'. $ReceiptID, true, null);

    $KakaoIdentityResult = new KakaoIdentityResult();
    $KakaoIdentityResult->fromJsonInfo($result);
    return $KakaoIdentityResult;
  }

  /**
   * 전자서명 요청(단건)
   */
  public function RequestSign($ClientCode, $KakaoSign)
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
    if (Stringz::isNullorEmpty($KakaoSign)) {
      throw new BarocertException('전자서명 요청정보가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoSign->receiverHP)) {
      throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoSign->receiverName)) {
      throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoSign->receiverBirthday)) {
      throw new BarocertException('생년월일이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoSign->expireIn)) {
      throw new BarocertException('만료시간이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoSign->signTitle) && Stringz::isNullorEmpty($KakaoSign->reqTitle)) {
      throw new BarocertException('서명 요청 제목이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoSign->token)) {
      throw new BarocertException('토큰 원문이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoSign->tokenType)) {
      throw new BarocertException('원문 유형이 입력되지 않았습니다.');
    }

    $postdata = json_encode($KakaoSign);

    $result = parent::executeCURL('/KAKAO/Sign/' . $ClientCode, true,  $postdata);

    $KakaoSignReceipt = new KakaoSignReceipt();
    $KakaoSignReceipt->fromJsonInfo($result);
    return $KakaoSignReceipt;
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

    $result = parent::executeCURL('/KAKAO/Sign/'. $ClientCode .'/'. $ReceiptID, false, null);

    $KakaoSignStatus = new KakaoSignStatus();
    $KakaoSignStatus->fromJsonInfo($result);
    return $KakaoSignStatus;
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
    
    $result = parent::executeCURL('/KAKAO/Sign/'. $ClientCode .'/'. $ReceiptID, true, null);

    $KakaoSignResult = new KakaoSignResult();
    $KakaoSignResult->fromJsonInfo($result);
    return $KakaoSignResult;
  }

  /**
   * 전자서명 요청(복수)
   */
  public function requestMultiSign($ClientCode, $KakaoMultiSign)
  {
    if (Stringz::isNullorEmpty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (Stringz::isNumber($ClientCode) == 0) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (Stringz::isNullorEmpty($KakaoMultiSign)) {
      throw new BarocertException('전자서명 요청정보가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoMultiSign->receiverHP)) {
      throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoMultiSign->receiverName)) {
      throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoMultiSign->receiverBirthday)) {
      throw new BarocertException('생년월일이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoMultiSign->expireIn)) {
      throw new BarocertException('만료시간이 입력되지 않았습니다.');
    }
    if ($this->isNullorEmptyTitle($KakaoMultiSign->tokens)) {
      throw new BarocertException('서명 요청 제목이 입력되지 않았습니다.');
    }
    if ($this->isNullorEmptyToken($KakaoMultiSign->tokens)) {
      throw new BarocertException('토큰 원문이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoMultiSign->tokenType)) {
      throw new BarocertException('원문 유형이 입력되지 않았습니다.');
    }

    $postdata = json_encode($KakaoMultiSign);
    $result = parent::executeCURL('/KAKAO/MultiSign/' . $ClientCode, true, $postdata);

    $KakaoMultiSignReceipt = new KakaoMultiSignReceipt();
    $KakaoMultiSignReceipt->fromJsonInfo($result);
    return $KakaoMultiSignReceipt;
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

    $result = parent::executeCURL('/KAKAO/MultiSign/' . $ClientCode .'/'. $ReceiptID, false , null);

    $KakaoMultiSignStatus = new KakaoMultiSignStatus();
    $KakaoMultiSignStatus->fromJsonInfo($result);
    return $KakaoMultiSignStatus;
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
    
    $result = parent::executeCURL('/KAKAO/MultiSign/'. $ClientCode .'/'. $ReceiptID, true, null);

    $KakaoMultiSignResult = new KakaoMultiSignResult();
    $KakaoMultiSignResult->fromJsonInfo($result);
    return $KakaoMultiSignResult;
  }

  /**
   * 출금동의 요청
   */
  public function requestCMS($ClientCode, $KakaoCMS)
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
    if (Stringz::isNullorEmpty($KakaoCMS)) {
      throw new BarocertException('자동이체 출금동의 요청정보가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoCMS->receiverHP)) {
      throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoCMS->receiverName)) {
      throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoCMS->receiverBirthday)) {
      throw new BarocertException('생년월일이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoCMS->expireIn)) {
      throw new BarocertException('만료시간이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoCMS->reqTitle)) {
      throw new BarocertException('인증요청 메시지 제목이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoCMS->requestCorp)) {
      throw new BarocertException('청구기관명이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoCMS->bankName)) {
      throw new BarocertException('은행명이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoCMS->bankAccountNum)) {
      throw new BarocertException('계좌번호가 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoCMS->bankAccountName)) {
      throw new BarocertException('예금주명이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoCMS->bankAccountBirthday)) {
      throw new BarocertException('예금주 생년월일이 입력되지 않았습니다.');
    }
    if (Stringz::isNullorEmpty($KakaoCMS->bankServiceType)) {
      throw new BarocertException('출금 유형이 입력되지 않았습니다.');
    }

    $postdata = json_encode($KakaoCMS);
    
    $result = parent::executeCURL('/KAKAO/CMS/' . $ClientCode, true, $postdata);

    $KakaoCMSReceipt = new KakaoCMSReceipt();
    $KakaoCMSReceipt->fromJsonInfo($result);
    return $KakaoCMSReceipt;
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

    $result = parent::executeCURL('/KAKAO/CMS/' . $ClientCode .'/'. $ReceiptID, false, null);

    $KakaoCMSStatus = new KakaoCMSStatus();
    $KakaoCMSStatus->fromJsonInfo($result);
    return $KakaoCMSStatus;
  }

  /**
   * 출금동의 서명 검증
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

    $result = parent::executeCURL('/KAKAO/CMS/'. $ClientCode .'/'. $ReceiptID, true, null);

    $KakaoCMSResult = new KakaoCMSResult();
    $KakaoCMSResult->fromJsonInfo($result);
    return $KakaoCMSResult;
  }

  /**
   * 간편로그인 검증
   */
  public function verifyLogin($ClientCode, $TxID)
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
    if (Stringz::isNullorEmpty($TxID)) {
      throw new BarocertException('트랜잭션 아이디가 입력되지 않았습니다.');
    }

    $result = parent::executeCURL('/KAKAO/Login/' . $ClientCode .'/'. $TxID, true, null);

    $KakaoLoginResult = new KakaoLoginResult();
    $KakaoLoginResult->fromJsonInfo($result);
    return $KakaoLoginResult;
  }

  public function isNullorEmptyTitle($multiSignTokens){
    if($multiSignTokens == null) return true;
    foreach($multiSignTokens as $signTokens){
      if($signTokens == null) return true;
      if(Stringz::isNullorEmpty($signTokens->signTitle) && Stringz::isNullorEmpty($signTokens->reqTitle)) return true;
    }
    return false;
  }

  public function isNullorEmptyToken($multiSignTokens){
    if($multiSignTokens == null) return true;
    foreach($multiSignTokens as $signTokens){
      if($signTokens == null) return true;
      if (Stringz::isNullorEmpty($signTokens -> token)) return true;
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
  public $extraMessage;
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
    isset($jsonInfo->expireIn) ? $this->expireIn = $jsonInfo->expireIn : null;                    // deprecated
    isset($jsonInfo->callCenterName) ? $this->callCenterName = $jsonInfo->callCenterName : null;  // deprecated
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;     // deprecated
    isset($jsonInfo->reqTitle) ? $this->reqTitle = $jsonInfo->reqTitle : null;                    // deprecated
    isset($jsonInfo->authCategory) ? $this->authCategory = $jsonInfo->authCategory : null;        // deprecated
    isset($jsonInfo->returnURL) ? $this->returnURL = $jsonInfo->returnURL : null;                 // deprecated
    isset($jsonInfo->requestDT) ? $this->requestDT = $jsonInfo->requestDT : null;
    isset($jsonInfo->viewDT) ? $this->viewDT = $jsonInfo->viewDT : null;
    isset($jsonInfo->completeDT) ? $this->completeDT = $jsonInfo->completeDT : null;
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->verifyDT) ? $this->verifyDT = $jsonInfo->verifyDT : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;                          // deprecated
    isset($jsonInfo->appUseYN) ? $this->appUseYN = $jsonInfo->appUseYN : null;                    // deprecated
  }
}

class KakaoIdentityResult
{
  public $receiptID;
  public $state;
  public $signedData;
  public $ci;
  public $receiverName;
  public $receiverYear;
  public $receiverDay;
  public $receiverHP;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
    isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
    isset($jsonInfo->receiverYear) ? $this->receiverYear = $jsonInfo->receiverYear : null;
    isset($jsonInfo->receiverDay) ? $this->receiverDay = $jsonInfo->receiverDay : null;
    isset($jsonInfo->receiverHP) ? $this->receiverHP = $jsonInfo->receiverHP : null;
  }
}



class KakaoSign
{
  public $receiverHP;
  public $receiverName;
  public $receiverBirthday;
  public $reqTitle;
  public $signTitle;
  public $extraMessage;
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
    isset($jsonInfo->expireIn) ? $this->expireIn = $jsonInfo->expireIn : null;                    // deprecated
    isset($jsonInfo->callCenterName) ? $this->callCenterName = $jsonInfo->callCenterName : null;  // deprecated
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;     // deprecated
    isset($jsonInfo->reqTitle) ? $this->reqTitle = $jsonInfo->reqTitle : null;                    // deprecated
    isset($jsonInfo->authCategory) ? $this->authCategory = $jsonInfo->authCategory : null;        // deprecated
    isset($jsonInfo->returnURL) ? $this->returnURL = $jsonInfo->returnURL : null;                 // deprecated
    isset($jsonInfo->tokenType) ? $this->tokenType = $jsonInfo->tokenType : null;                 // deprecated
    isset($jsonInfo->requestDT) ? $this->requestDT = $jsonInfo->requestDT : null;
    isset($jsonInfo->viewDT) ? $this->viewDT = $jsonInfo->viewDT : null;
    isset($jsonInfo->completeDT) ? $this->completeDT = $jsonInfo->completeDT : null;
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->verifyDT) ? $this->verifyDT = $jsonInfo->verifyDT : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;                          // deprecated
    isset($jsonInfo->appUseYN) ? $this->appUseYN = $jsonInfo->appUseYN : null;                    // deprecated
  }
}

class KakaoSignResult
{
  public $receiptID;
  public $state;
  public $signedData;
  public $ci;
  public $receiverName;
  public $receiverYear;
  public $receiverDay;
  public $receiverHP;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
    isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
    isset($jsonInfo->receiverYear) ? $this->receiverYear = $jsonInfo->receiverYear : null;
    isset($jsonInfo->receiverDay) ? $this->receiverDay = $jsonInfo->receiverDay : null;
    isset($jsonInfo->receiverHP) ? $this->receiverHP = $jsonInfo->receiverHP : null;
  }
}

class KakaoMultiSign
{
  public $receiverHP;
  public $receiverName;
  public $receiverBirthday;
  public $reqTitle;
  public $extraMessage;
  public $expireIn;
  public $tokens;
  public $tokenType;
  public $returnURL;
  public $appUseYN;
}

class KakaoMultiSignTokens
{
  public $reqTitle;
  public $signTitle;
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
    isset($jsonInfo->expireIn) ? $this->expireIn = $jsonInfo->expireIn : null;                    // deprecated
    isset($jsonInfo->callCenterName) ? $this->callCenterName = $jsonInfo->callCenterName : null;  // deprecated
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;     // deprecated
    isset($jsonInfo->reqTitle) ? $this->reqTitle = $jsonInfo->reqTitle : null;                    // deprecated
    isset($jsonInfo->authCategory) ? $this->authCategory = $jsonInfo->authCategory : null;        // deprecated
    isset($jsonInfo->returnURL) ? $this->returnURL = $jsonInfo->returnURL : null;                 // deprecated
    isset($jsonInfo->tokenType) ? $this->tokenType = $jsonInfo->tokenType : null;                 // deprecated
    isset($jsonInfo->requestDT) ? $this->requestDT = $jsonInfo->requestDT : null;
    isset($jsonInfo->viewDT) ? $this->viewDT = $jsonInfo->viewDT : null;
    isset($jsonInfo->completeDT) ? $this->completeDT = $jsonInfo->completeDT : null;
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->verifyDT) ? $this->verifyDT = $jsonInfo->verifyDT : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;                          // deprecated
    isset($jsonInfo->appUseYN) ? $this->appUseYN = $jsonInfo->appUseYN : null;                    // deprecated
  }
}

class KakaoMultiSignResult
{
  public $receiptID;
  public $state;
  public $multiSignedData;
  public $ci;
  public $receiverName;
  public $receiverYear;
  public $receiverDay;
  public $receiverHP;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->requestID) ? $this->requestID = $jsonInfo->requestID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->multiSignedData) ? $this->multiSignedData = $jsonInfo->multiSignedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
    isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
    isset($jsonInfo->receiverYear) ? $this->receiverYear = $jsonInfo->receiverYear : null;
    isset($jsonInfo->receiverDay) ? $this->receiverDay = $jsonInfo->receiverDay : null;
    isset($jsonInfo->receiverHP) ? $this->receiverHP = $jsonInfo->receiverHP : null;
  }
}

class KakaoCMS
{
  public $requestID;
  public $receiverHP;
  public $receiverName;
  public $receiverBirthday;
  public $reqTitle;
  public $extraMessage;
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
    isset($jsonInfo->expireIn) ? $this->expireIn = $jsonInfo->expireIn : null;                    // deprecated
    isset($jsonInfo->callCenterName) ? $this->callCenterName = $jsonInfo->callCenterName : null;  // deprecated
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;     // deprecated
    isset($jsonInfo->reqTitle) ? $this->reqTitle = $jsonInfo->reqTitle : null;                    // deprecated
    isset($jsonInfo->authCategory) ? $this->authCategory = $jsonInfo->authCategory : null;        // deprecated
    isset($jsonInfo->returnURL) ? $this->returnURL = $jsonInfo->returnURL : null;                 // deprecated
    isset($jsonInfo->tokenType) ? $this->tokenType = $jsonInfo->tokenType : null;                 // deprecated
    isset($jsonInfo->requestDT) ? $this->requestDT = $jsonInfo->requestDT : null;
    isset($jsonInfo->viewDT) ? $this->viewDT = $jsonInfo->viewDT : null;
    isset($jsonInfo->completeDT) ? $this->completeDT = $jsonInfo->completeDT : null;
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->verifyDT) ? $this->verifyDT = $jsonInfo->verifyDT : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;                          // deprecated
    isset($jsonInfo->appUseYN) ? $this->appUseYN = $jsonInfo->appUseYN : null;                    // deprecated
  }
}

class KakaoCMSResult
{
  public $receiptID;
  public $state;
  public $signedData;
  public $ci;
  public $receiverName;
  public $receiverYear;
  public $receiverDay;
  public $receiverHP;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
    isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
    isset($jsonInfo->receiverYear) ? $this->receiverYear = $jsonInfo->receiverYear : null;
    isset($jsonInfo->receiverDay) ? $this->receiverDay = $jsonInfo->receiverDay : null;
    isset($jsonInfo->receiverHP) ? $this->receiverHP = $jsonInfo->receiverHP : null;
  }
}

class KakaoLoginResult
{
  public $txID;
  public $state;
  public $signedData;
  public $ci;
  public $receiverName;
  public $receiverYear;
  public $receiverDay;
  public $receiverHP;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->txID) ? $this->txID = $jsonInfo->txID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
    isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
    isset($jsonInfo->receiverYear) ? $this->receiverYear = $jsonInfo->receiverYear : null;
    isset($jsonInfo->receiverDay) ? $this->receiverDay = $jsonInfo->receiverDay : null;
    isset($jsonInfo->receiverHP) ? $this->receiverHP = $jsonInfo->receiverHP : null;
  }
}

?>
