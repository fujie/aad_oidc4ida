<?php

// パラメータ類
$client_id = '{client_id}';
$client_secret = '{client_secret}';
$redirect_uri = 'https://{client}/testclient.php';
$authorization_endpoint = 'https://{idp}/ida/authorize';
$token_endpoint = 'https://{idp}/ida/token';
$response_type = 'code';
$state =  md5(microtime() . mt_rand());

// codeの取得(codeがパラメータについてなければ初回アクセスとしてみなしています。手抜きです)
$req_code = $_GET['code'];
if(!$req_code){
	// 初回アクセスなのでログインプロセス開始
	// session生成
	session_start();
	$_SESSION['nonce'] = md5(microtime() . mt_rand());
	// claims生成
	$verificationArray = array(
		'trust_framework'=>'null'
	);
	$claimsArray = array(
		'given_name'=>'null',
		'family_name'=>'null'
	);
	$verified_claimsArray = array(
		'verification'=>$verificationArray,
		'claims'=>$claimsArray
	);
	$id_tokenArray = array(
		'email'=>'null',
		'verified_claims'=>$verified_claimsArray
	);
	$claimsArray = array(
		'id_token'=>$id_tokenArray
	);
	
	// GETパラメータ関係
	$query = http_build_query(array(
		'client_id'=>$client_id,
		'response_type'=>$response_type,
		'redirect_uri'=> $redirect_uri,
		'scope'=>'openid User.Read',
		'state'=>$state,
		'nonce'=>$_SESSION['nonce'],
		'claims'=>json_encode($claimsArray)
	));
	// リクエスト
	header('Location: ' . $authorization_endpoint . '?' . $query );
	exit();
}

// sessionよりnonceの取得
session_start();
$nonce = $_SESSION['nonce'];

// POSTデータの作成
$postdata = array(
	'grant_type'=>'authorization_code',
	'client_id'=>$client_id,
	'code'=>$req_code,
	'client_secret'=>$client_secret,
	'redirect_uri'=>$redirect_uri
);

// TokenエンドポイントへPOST
$ch = curl_init($token_endpoint);
curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt( $ch, CURLOPT_POSTFIELDS, http_build_query($postdata));
curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
$response = json_decode(curl_exec($ch));
curl_close($ch);

//print $response->id_token . '\n';
// id_tokenの取り出しとdecode
$id_token = explode('.', $response->id_token);
$payload = base64_decode(str_pad(strtr($id_token[1], '-_', '+/'), strlen($id_token[1]) % 4, '=', STR_PAD_RIGHT));
$payload_json = json_decode($payload, true);

// 整形と表示
print<<<EOF
	<html>
	<head>
	<meta http-equiv='Content-Type' content='text/html; charset=utf-8' />
	<title>Obtained claims</title>
	</head>
	<body>
EOF;
print<<<EOF
	<table border=1>
	<tr><th>Claim</th><th>Value</th></tr>
EOF;
	// id_tokenの中身の表示
	foreach($payload_json as $key => $value){
		if($key == 'verified_claims'){
			$verified_claims = json_encode($value);
			print('<tr><td>'.$key.'</td><td>' . $verified_claims . '</td></tr>');			
		}else{
			print('<tr><td>'.$key.'</td><td>'.$value.'</td></tr>');			
		}
	}
print<<<EOF
	</table>
	</body>
	</html>
EOF;

?>
