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
 * Author : lsh (code@linkhubcorp.com)
 * Written : 2023-03-13
 * Updated : 2023-03-13
 *
 * Thanks for your interest.
 * We welcome any suggestions, feedbacks, blames or anythings.
 * ======================================================================================
 */

 require_once 'Linkhub/linkhub.auth.php';

class KakaocertService
{

  const ServiceID = 'BAROCERT';
  const ServiceURL = 'https://bc-api.linkhub.kr'; // TODO :: 나중에 바꿔야 함.
  const ServiceURL_Static = 'https://static-barocert.linkhub.co.kr';
  const ServiceURL_GA = 'https://ga-barocert.linkhub.co.kr';
  const Version = '2.0';

  private $Token_Table = array();
  private $Linkhub;
  private $IPRestrictOnOff = true;
  private $UseStaticIP = false;
  private $UseGAIP = false;
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

  public function UseGAIP($V)
  {
    $this->UseGAIP = $V;
  }

  public function UseLocalTimeYN($V)
  {
    $this->UseLocalTimeYN = $V;
  }

  private function getTargetURL()
  {
    if ($this->UseGAIP) {
      return KakaocertService::ServiceURL_GA;
    } else if ($this->UseStaticIP) {
      return KakaocertService::ServiceURL_Static;
    }
    return KakaocertService::ServiceURL;
  }

  private function getsession_Token($CorpNum)
  {
    $targetToken = null;

    if (array_key_exists($CorpNum, $this->Token_Table)) {
      $targetToken = $this->Token_Table[$CorpNum];
    }

    $Refresh = false;

    if (is_null($targetToken)) {
      $Refresh = true;
    } else {
      $Expiration = new DateTime($targetToken->expiration, new DateTimeZone("UTC"));

      $now = $this->Linkhub->getTime($this->UseStaticIP, $this->UseLocalTimeYN, $this->UseGAIP);
      $Refresh = $Expiration < $now;
    }

    if ($Refresh) {
      try {
        $targetToken = $this->Linkhub->getToken(KakaocertService::ServiceID, $CorpNum, $this->scopes, $this->IPRestrictOnOff ? null : "*", $this->UseStaticIP, $this->UseLocalTimeYN, $this->UseGAIP);
      } catch (LinkhubException $le) {
        throw new BarocertException($le->getMessage(), $le->getCode());
      }
      $this->Token_Table[$CorpNum] = $targetToken;
    }
    return $targetToken->session_token;
  }

  protected function executeCURL($uri, $ClientCode = null, $userID = null, $isPost = false, $action = null, $postdata = null, $isMultiPart = false, $contentsType = null)
  {
    if ($this->__requestMode != "STREAM") {

      $targetURL = $this->getTargetURL();

      $http = curl_init($targetURL . $uri);
      $header = array();

      if (is_null($ClientCode) == false) {
        $header[] = 'Authorization: Bearer ' . $this->getsession_Token($ClientCode);
      }

      $header[] = 'Content-Type: Application/json';

      if ($isPost) {
        curl_setopt($http, CURLOPT_POST, 1);
        curl_setopt($http, CURLOPT_POSTFIELDS, $postdata);

        $xDate = $this->Linkhub->getTime($this->UseStaticIP, false, $this->UseGAIP);

        $digestTarget = 'POST' . chr(10);
        $digestTarget = $digestTarget . base64_encode(hash('sha256', $postdata, true)) . chr(10);

        $digestTarget = $digestTarget . $xDate . chr(10);

        $digestTarget = $digestTarget . Linkhub::VERSION . chr(10);

        $digest = base64_encode(hash_hmac('sha256', $digestTarget, base64_decode(strtr($this->Linkhub->getSecretKey(), '-_', '+/')), true));

        $header[] = 'x-lh-date: ' . $xDate;
        $header[] = 'x-lh-version: ' . Linkhub::VERSION;
        $header[] = 'x-bc-auth: ' . $this->Linkhub->getLinkID() . ' ' . $digest;
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

      if (0 === mb_strpos($contentType, 'application/pdf')) {
        return $responseJson;
      }

      return json_decode($responseJson);
    } else {
      $header = array();

      $header[] = 'Accept-Encoding: gzip,deflate';
      $header[] = 'Connection: close';
      if (is_null($ClientCode) == false) {
        $header[] = 'Authorization: Bearer ' . $this->getsession_Token($ClientCode);
      }

      if ($isMultiPart == false) {
        $header[] = 'Content-Type: Application/json';
        $postbody = $postdata;

        $xDate = $this->Linkhub->getTime($this->UseStaticIP, false, $this->UseGAIP);

        $digestTarget = 'POST' . chr(10);
        $digestTarget = $digestTarget . base64_encode(hash('sha256', $postdata, true)) . chr(10);
        $digestTarget = $digestTarget . $xDate . chr(10);

        $digestTarget = $digestTarget . Linkhub::VERSION . chr(10);

        $digest = base64_encode(hash_hmac('sha256', $digestTarget, base64_decode(strtr($this->Linkhub->getSecretKey(), '-_', '+/')), true));

        $header[] = 'x-lh-date: ' . $xDate;
        $header[] = 'x-lh-version: ' . Linkhub::VERSION;
        $header[] = 'x-bc-auth: ' . $this->Linkhub->getLinkID() . ' ' . $digest;
      }

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

      foreach ($http_response_header as $k => $v) {
        $t = explode(':', $v, 2);
        if (preg_match('/^Content-Type:/i', $v, $out)) {
          $contentType = trim($t[1]);
          if (0 === mb_strpos($contentType, 'application/pdf')) {
            return $response;
          }
        }
      }

      return json_decode($response);
    }
  }

  /**
   * 전자서명 요청(단건)
   */
  public function requestESign($ClientCode, $RequestESign, $appUseYN = false)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (is_null($RequestESign) || empty($RequestESign)) {
      throw new BarocertException('전자서명 요청정보가 입력되지 않았습니다.');
    }

    $RequestESign->clientCode = $ClientCode;
    $RequestESign->appUseYN = $appUseYN;

    $postdata = json_encode($RequestESign);

    $result = $this->executeCURL('/KAKAO/ESign/Request', $ClientCode, null, true, null, $postdata);

    $ResponseESign = new ResponseESign();
    $ResponseESign->fromJsonInfo($result);
    return $ResponseESign;
  }

  /**
   * 전자서명 요청(다건)
   */
  public function bulkRequestESign($ClientCode, $RequestESign, $appUseYN = false)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (is_null($RequestESign) || empty($RequestESign)) {
      throw new BarocertException('전자서명 요청정보가 입력되지 않았습니다.');
    }

    $RequestESign->clientCode = $ClientCode;
    $RequestESign->appUseYN = $appUseYN;

    $postdata = json_encode($RequestESign);

    $result = $this->executeCURL('/KAKAO/ESign/BulkRequest', $ClientCode, null, true, null, $postdata);

    $ResponseESign = new ResponseESign();
    $ResponseESign->fromJsonInfo($result);
    return $ResponseESign;
  }

  /**
   * 전자서명 상태 확인(단건)
   */
  public function getESignState($ClientCode, $receiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (is_null($receiptID) || empty($receiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }

    $result = $this->executeCURL('/KAKAO/ESign/Status/'. $ClientCode .'/'. $receiptID, $ClientCode);

    $ResultESign = new ResultESign();
    $ResultESign->fromJsonInfo($result);
    return $ResultESign;
  }

  /**
   * 전자서명 상태 확인(다건)
   */
  public function getBulkESignState($ClientCode, $receiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (is_null($receiptID) || empty($receiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }

    $result = $this->executeCURL('/KAKAO/ESign/BulkStatus/' . $ClientCode .'/'. $receiptID, $ClientCode);

    $BulkResultESign = new BulkResultESign();
    $BulkResultESign->fromJsonInfo($result);
    return $BulkResultESign;
  }

  /**
   * 전자서명 검증(단건)
   */
  public function verifyESign($ClientCode, $receiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (is_null($receiptID) || empty($receiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }

    $RequestVerify = new RequestVerify();
    $RequestVerify->clientCode = $ClientCode;
    $RequestVerify->receiptID = $receiptID;

    $postdata = json_encode($RequestVerify);
    
    $result = $this->executeCURL('/KAKAO/ESign/Verify', $ClientCode, null, true, null, $postdata);

    $ResultVerifyEsign = new ResultVerifyEsign();
    $ResultVerifyEsign->fromJsonInfo($result);
    return $ResultVerifyEsign;
  }

  /**
   * 전자서명 검증(다건)
   */
  public function bulkVerifyESign($ClientCode, $receiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (is_null($receiptID) || empty($receiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }

    $RequestVerify = new RequestVerify();
    $RequestVerify->clientCode = $ClientCode;
    $RequestVerify->receiptID = $receiptID;

    $postdata = json_encode($RequestVerify);
    
    $result = $this->executeCURL('/KAKAO/ESign/BulkVerify', $ClientCode, null, true, null, $postdata);

    $BulkVerifyResult = new BulkVerifyResult();
    $BulkVerifyResult->fromJsonInfo($result);
    return $BulkVerifyResult;
  }

  /**
   * 본인인증 요청
   */
  public function requestVerifyAuth($ClientCode, $RequestVerifyAuth, $appUseYN = false)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (is_null($RequestVerifyAuth) || empty($RequestVerifyAuth)) {
      throw new BarocertException('본인인증 요청정보가 입력되지 않았습니다.');
    }

    $RequestVerifyAuth->clientCode = $ClientCode;
    $RequestVerifyAuth->appUseYN = $appUseYN;

    $postdata = json_encode($RequestVerifyAuth);
    
    $result = $this->executeCURL('/KAKAO/VerifyAuth/Request', $ClientCode, null, true, null, $postdata);

    $ResultReqVerifyAuth = new ResultReqVerifyAuth();
    $ResultReqVerifyAuth->fromJsonInfo($result);
    return $ResultReqVerifyAuth;
  }

  /**
   * 본인인증 상태확인
   */
  public function getVerifyAuthState($ClientCode, $receiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (is_null($receiptID) || empty($receiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }

    $result = $this->executeCURL('/KAKAO/VerifyAuth/Status/' . $ClientCode .'/'. $receiptID, $ClientCode);

    $ResultVerifyAuthState = new ResultVerifyAuthState();
    $ResultVerifyAuthState->fromJsonInfo($result);
    return $ResultVerifyAuthState;
  }

  /**
   * 본인인증 검증
   */
  public function verifyAuth($ClientCode, $receiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (is_null($receiptID) || empty($receiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }

    $result = $this->executeCURL('/KAKAO/VerifyAuth/Verify' . $receiptID, $ClientCode);

    $ResultVerifyAuth = new ResultVerifyAuth();
    $ResultVerifyAuth->fromJsonInfo($result);
    return $ResultVerifyAuth;
  }

  /**
   * 출금동의 요청
   */
  public function requestCMS($ClientCode, $RequestCMS, $appUseYN = false)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (is_null($RequestCMS) || empty($RequestCMS)) {
      throw new BarocertException('자동이체 출금동의 요청정보가 입력되지 않았습니다.');
    }

    $RequestCMS->clientCode = $ClientCode;
    $RequestCMS->appUseYN = $appUseYN;

    $postdata = json_encode($RequestCMS);
    
    $result = $this->executeCURL('/KAKAO/CMS/Request', $ClientCode, null, true, null, $postdata);

    $ResponseCMS = new ResponseCMS();
    $ResponseCMS->fromJsonInfo($result);
    return $ResponseCMS;
  }

  /**
   * 출금동의 상태 확인
   */
  public function getCMSState($ClientCode, $receiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (is_null($receiptID) || empty($receiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }

    $result = $this->executeCURL('/KAKAO/CMS/Status/' . $ClientCode .'/'. $receiptID, $ClientCode);

    $ResultCMS = new ResultCMS();
    $ResultCMS->fromJsonInfo($result);
    return $ResultCMS;
  }

  /**
   * 출금동의 서명 검증
   */
  public function verifyCMS($ClientCode, $receiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (is_null($receiptID) || empty($receiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }

    $result = $this->executeCURL('/KAKAO/CMS/Verify', $ClientCode);

    $ResultVerifyCMS = new ResultVerifyCMS();
    $ResultVerifyCMS->fromJsonInfo($result);
    return $ResultVerifyCMS;
  }

}

class RequestCMS
{
  public $clientCode;
	public $requestID;
	public $receiverHP;
	public $receiverName;
	public $receiverBirthday;
	public $ci;
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

class ResultCMS
{
  public $receiptID;
  public $requestID;
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
    isset($jsonInfo->requestID) ? $this->requestID = $jsonInfo->requestID : null;
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

class ResultVerifyAuthState
{
  public $receiptId;
  public $requestId;
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
    isset($jsonInfo->receiptId) ? $this->receiptId = $jsonInfo->receiptId : null;
    isset($jsonInfo->requestId) ? $this->requestId = $jsonInfo->requestId : null;
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

class ResultVerifyAuth
{
  public $receiptId;
  public $requestId;
  public $state;
  public $token;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptId) ? $this->receiptId = $jsonInfo->receiptId : null;
    isset($jsonInfo->requestId) ? $this->requestId = $jsonInfo->requestId : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->token) ? $this->token = $jsonInfo->token : null;
  }
}

class ResponseCMS
{
  public $receiptId;
  public $scheme;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptId) ? $this->receiptId = $jsonInfo->receiptId : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
  }
}

class RequestESign
{
  public $clientCode;
  public $requestID;
  public $receiverHP;
  public $receiverName;
  public $receiverBirthday;
  public $ci;
  public $reqTitle;
  public $expireIn;
  public $token;
  public $tokenType;
  public $returnURL;
  public $appUseYN;
}

class ResponseESign
{
  public $receiptId;
  public $scheme;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptId) ? $this->receiptId = $jsonInfo->receiptId : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
  }
}

class ResultESign
{
  public $receiptID;
  public $requestID;
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
    isset($jsonInfo->requestID) ? $this->requestID = $jsonInfo->requestID : null;
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

class BulkRequestESign
{
  public $clientCode;
  public $requestID;
  public $receiverHP;
  public $receiverName;
  public $receiverBirthday;
  public $ci;
  public $reqTitle;
  public $expireIn;

  public $tokens;

  public $tokenType;
  public $returnURL;
  public $appUseYN;
}

class Tokens
{
  public $reqTitle;
  public $token;
}

class BulkResultESign
{
  public $receiptID;
  public $requestID;
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
    isset($jsonInfo->requestID) ? $this->requestID = $jsonInfo->requestID : null;
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

class RequestVerify 
{
  public $clientCode;
  public $receiptID;
}

class ResultVerifyCMS
{
  public $receiptID;
	public $requestID;
	public $state;
	public $signedData;
	public $ci;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->requestID) ? $this->requestID = $jsonInfo->requestID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
  }
}

class ResultVerifyEsign
{
  public $receiptID;
	public $requestID;
	public $state;
	public $signedData;
	public $ci;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->requestID) ? $this->requestID = $jsonInfo->requestID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
  }
}

class BulkVerifyResult
{
  public $receiptID;
	public $requestID;
	public $state;
	public $bulkSignedData;
	public $ci;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->requestID) ? $this->requestID = $jsonInfo->requestID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->bulkSignedData) ? $this->bulkSignedData = $jsonInfo->bulkSignedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
  }
}

class ResultReqVerifyAuth
{
  public $receiptId;
	public $scheme;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptId) ? $this->receiptId = $jsonInfo->receiptId : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
  }
}

class RequestVerifyAuth
{
  public $clientCode;
	public $requestID;
	public $receiverHP;
	public $receiverName;
	public $receiverBirthday;
	public $ci;
	
	public $reqTitle;
	public $expireIn;
	
	public $token;
	public $returnURL;

	public $appUseYN;
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