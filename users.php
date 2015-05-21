<?php

// Allow from any origin
if (isset($_SERVER['HTTP_ORIGIN'])) {
    header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Max-Age: 86400');    // cache for 1 day
}

// Access-Control headers are received during OPTIONS requests
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {

    if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD']))
        header("Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE");

    if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']))
        header("Access-Control-Allow-Headers: {$_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']}");

    exit(0);
}



include 'Slim/Slim.php';

require 'ProtectedDocs/connection.php';

$app = new Slim();

$app->post('/client', 'clientStuff');

$app->run();

function userLogin() {
    $request = Slim::getInstance()->request();
    $user = json_decode($request->getBody());

    //Get Salt
    $sql = "SELECT

        salt

        FROM users WHERE username=:username LIMIT 1";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("username", $user->username);
        $stmt->execute();
        $response = $stmt->fetchObject();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    //If user does not exist
    if(!isset($response->salt)){
        echo '{"error":{"text":"Username' . $user->username . ' does not exist","errorid":"23"}}';
        exit;
    }

    //Crypt salt and password
    $passwordcrypt = crypt($user->password, $response->salt);

    //Get ID
    $sql = "SELECT

        id

        FROM users WHERE username=:username AND password=:password LIMIT 1";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("username", $user->username);
        $stmt->bindParam("password", $passwordcrypt);
        $stmt->execute();
        $response = $stmt->fetchObject();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    //If password is incorrect
    if(!isset($response->id)){
        echo '{"error":{"text":"Password is incorrect","errorid":"24"}}';
        exit;
    }

    //Generate a session token
    $length = 24;
    $randomstring = bin2hex(openssl_random_pseudo_bytes($length, $strong));
    if(!($strong = true)){
        echo '{"error":{"text":"Did not generate secure random session token"}}';
        exit;
    }

    //Insert session token
    $sql = "INSERT INTO sessions

        (user_id, token)

        VALUES

        (:user_id, :token)";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("user_id", $response->id);
        $stmt->bindParam("token", $randomstring);
        $stmt->execute();
        $response->session_token = $randomstring;
        $session_token = $randomstring;
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    //Echo session token
    echo '{"result":{"session_token":"'. $session_token .'"}}';
}

function setPassword() {
    $request = Slim::getInstance()->request();
    $user = json_decode($request->getBody());

    //Check to see if username exists and is not set up
    $sql = "SELECT
        id
        FROM users
        WHERE username=:username AND password=NULL AND salt=NULL
        LIMIT 1";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("username", $user->username);
        //$stmt->bindParam("password", $user->password);
        $stmt->execute();
        $userid = $stmt->fetchObject();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    //Fail if username doesnt exist, or if it is already set up
    if(!isset($userid->id)){
        echo '{"error":{"text":"Username Does Not Exist OR Already Has A Password Set","errorid":"22"}}';
        exit;
    }

    //Generate a salt
    $length = 24;
    $salt = bin2hex(openssl_random_pseudo_bytes($length));

    //Crypt salt and password
    $passwordcrypt = crypt($user->password, $salt);

    //Update user with new password and salt
    $sql = "UPDATE users

    SET password=:password, salt=:salt

    WHERE username=:username AND id=:id";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("username", $user->username);
        $stmt->bindParam("id", $userid->id);
        $stmt->bindParam("password", $passwordcrypt);
        $stmt->bindParam("salt", $salt);
        $stmt->execute();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    //Generate a session token
    $length = 24;
    $session_token = bin2hex(openssl_random_pseudo_bytes($length, $strong));
    if(!$strong){
        echo '{"error":{"text":"Did not generate secure random session token"}}';
        exit;
    }

    //Create session token
    $sql = "INSERT INTO sessions

        (user_id, token)

        VALUES

        (:user_id, :token)";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("user_id", $userid->id);
        $stmt->bindParam("token", $session_token);
        $stmt->execute();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    //Spit out results
    echo '{"result":{ "session_token":"'. $session_token .'"}}';
}

function utf8ize($mixed) {
    if (is_array($mixed)) {
        foreach ($mixed as $key => $value) {
            $mixed[$key] = utf8ize($value);
        }
    } else if (is_string ($mixed)) {
        return utf8_encode($mixed);
    }
    return $mixed;
}

function userAdd() {
    $request = Slim::getInstance()->request();
    $user = json_decode($request->getBody());

    //Check to see if username exists and is not set up
    $sql = "SELECT
        id
        FROM users
        WHERE username=:username AND password=NULL AND salt=NULL
        LIMIT 1";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("username", $user->username);
        //$stmt->bindParam("password", $user->password);
        $stmt->execute();
        $userid = $stmt->fetchObject();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    //Fail if username doesnt exist, or if it is already set up
    if(!isset($userid->id)){
        echo '{"error":{"text":"Username Does Not Exist OR Already Has A Password Set","errorid":"22"}}';
        exit;
    }

    //Generate a salt
    $length = 24;
    $salt = bin2hex(openssl_random_pseudo_bytes($length));

    //Crypt salt and password
    $passwordcrypt = crypt($user->password, $salt);

    //Update user with new password and salt
    $sql = "UPDATE users

    SET password=:password, salt=:salt

    WHERE username=:username AND id=:id";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("username", $user->username);
        $stmt->bindParam("id", $userid->id);
        $stmt->bindParam("password", $passwordcrypt);
        $stmt->bindParam("salt", $salt);
        $stmt->execute();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    //Generate a session token
    $length = 24;
    $session_token = bin2hex(openssl_random_pseudo_bytes($length, $strong));
    if(!$strong){
        echo '{"error":{"text":"Did not generate secure random session token"}}';
        exit;
    }

    //Create session token
    $sql = "INSERT INTO sessions

        (user_id, token)

        VALUES

        (:user_id, :token)";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("user_id", $userid->id);
        $stmt->bindParam("token", $session_token);
        $stmt->execute();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    //Spit out results
    echo '{"result":{ "session_token":"'. $session_token .'"}}';
}

function utf8ize($mixed) {
    if (is_array($mixed)) {
        foreach ($mixed as $key => $value) {
            $mixed[$key] = utf8ize($value);
        }
    } else if (is_string ($mixed)) {
        return utf8_encode($mixed);
    }
    return $mixed;
}

?>
