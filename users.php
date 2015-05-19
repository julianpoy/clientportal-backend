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

function userJoin() {
    $request = Slim::getInstance()->request();
    $user = json_decode($request->getBody());

    //Check if username exists
    $sql = "SELECT

        username

        FROM users WHERE username=:username LIMIT 1";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("username", $user->username);
        //$stmt->bindParam("password", $user->password);
        $stmt->execute();
        $usercheck = $stmt->fetchObject();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    //If exists echo error and cancel
    if(!isset($usercheck->username)){
        echo '{"error":{"text":"Username Does Not Exist","errorid":"22"}}';
        exit;
    }

    //Generate a salt
    $length = 24;
    $salt = bin2hex(openssl_random_pseudo_bytes($length));

    //Crypt salt and password
    $passwordcrypt = crypt($user->password, $salt);

    //Create user
    $sql = "INSERT INTO users

    (username, password, salt, name,
        phone, address1, address2,
        city, state, zip, profile)

    VALUES

    (:username, :password, :salt, :name,
        :phone, :address1, :address2,
        :city, :state, :zip, :profile)";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("username", $user->username);
        $stmt->bindParam("password", $passwordcrypt);
        $stmt->bindParam("salt", $salt);
        $stmt->bindParam("name", $user->name);
        $stmt->bindParam("phone", $user->phone);
        $stmt->bindParam("address1", $user->address1);
        $stmt->bindParam("address2", $user->address2);
        $stmt->bindParam("city", $user->city);
        $stmt->bindParam("state", $user->state);
        $stmt->bindParam("zip", $user->zip);
        $stmt->bindParam("profile", $user->profile);
        $stmt->execute();
        $newusrid = $db->lastInsertId();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
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
        $stmt->bindParam("user_id", $newusrid);
        $stmt->bindParam("token", $randomstring);
        $stmt->execute();
        $session_token = $randomstring;
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    echo '{"result":{ "session_token":"'. $randomstring .'"}}';
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
