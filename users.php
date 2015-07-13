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

$app->post('/login', 'userLogin');
$app->post('/join', 'userJoin');
$app->post('/twiliojoin', 'twilioJoin');

$app->delete('/user', 'deleteUser');
$app->put('/user', 'updateUser');
$app->get('/user/:id', 'getUser');

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
    if(isset($usercheck->username)){
        echo '{"error":{"text":"Username Already Exists","errorid":"22"}}';
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

function twilioJoin() {
    $request = Slim::getInstance()->request();
    $request = $request->getBody();
    parse_str($request, $user);

    if($user['Body'] == "Gift"){
        //Check if username exists
        $sql = "SELECT

            username, id

            FROM users WHERE username=:username LIMIT 1";

        try {
            $db = getConnection();
            $stmt = $db->prepare($sql);
            $stmt->bindParam("username", $user['username']);
            //$stmt->bindParam("password", $user->password);
            $stmt->execute();
            $usercheck = $stmt->fetchObject();
            $db = null;
        } catch(PDOException $e) {
            echo '{"error":{"text":'. $e->getMessage() .'}}';
            exit;
        }

        //If exists echo error and cancel
        if(isset($usercheck->username)){

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
                $stmt->bindParam("user_id", $usercheck->id);
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
            header("content-type: text/xml");
            echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
            echo '<Response><Message>' . $randomstring .'</Message></Response>';
            exit;
        }

        //Create user
        $sql = "INSERT INTO users

        (username)

        VALUES

        (:username)";

        try {
            $db = getConnection();
            $stmt = $db->prepare($sql);
            $stmt->bindParam("username", $user['From']);
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

        header("content-type: text/xml");
        echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        echo '<Response><Message>' . $randomstring .'</Message></Response>';
    }
}

function getUser($id) {
    $request = Slim::getInstance()->request();
    $user = $request->get();

    $sql = "SELECT

        user_id

        FROM sessions WHERE token=:token LIMIT 1";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("token", $user['session_token']);
        $stmt->execute();
        $session = $stmt->fetchObject();
        $db = null;
        //echo json_encode($user);
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
    }

    if(!isset($session->user_id)){
        echo '{"error":{"text":"Token is not valid","errorid":"12"}}';
        exit;
    }

    if($id == $session->user_id || $id == "me"){
        $id = $session->user_id;
        $friend_status = 5;
    } else {

        $sql = "SELECT status FROM user_friends

        WHERE (fromfriend=:myuserid AND tofriend=:friendid)

        ";

        try {
            $db = getConnection();
            $stmt = $db->prepare($sql);

            $stmt->bindParam("myuserid", $session->user_id);
            $stmt->bindParam("friendid", $id);

            $stmt->execute();
            $db = null;
            $friend_status = $stmt->fetchObject();
        } catch(PDOException $e) {
            echo '{"error":{"text":'. $e->getMessage() .'}}';
        }

        if($friend_status != false){
            $friend_status_return = $friend_status->status;
        }

        //If current user didnt request friendship, check if vice versa
        if($friend_status == false){
            $sql = "SELECT status FROM user_friends

            WHERE (tofriend=:myuserid AND fromfriend=:friendid)

            ";

            try {
                $db = getConnection();
                $stmt = $db->prepare($sql);

                $stmt->bindParam("myuserid", $session->user_id);
                $stmt->bindParam("friendid", $id);

                $stmt->execute();
                $db = null;
                $friend_status = $stmt->fetchObject();
            } catch(PDOException $e) {
                echo '{"error":{"text":'. $e->getMessage() .'}}';
            }
            if($friend_status == false){
                $friend_status_return = "0";
            } else if($friend_status->status == "1") {
                $friend_status_return = "2";
            } else {
                $friend_status_return = $friend_status->status;
            }
        }
    }

    //Friend status is for what info to get
    //Friend status return is what relationship
    //The user actually has. 0 = none 1 = requested 2 = requestme 5 = friends

    if($friend_status == false){
        $friend_status = 1;
    }

    if(is_object($friend_status)){
        $friend_status = $friend_status->status;
        //$friend_status_return = $friend_status;
    }

    if($friend_status == 1){

        $sql = "SELECT

        name, city, state, profile

        FROM users WHERE id=:id";

    } else if($friend_status == 5){

        $sql = "SELECT

        username, name, phone,
        address1, address2, city,
        state, zip, profile

        FROM users WHERE id=:id";

    } else {
        echo "FRIENDCHECK ERROR";
        var_dump($friend_status);
        break;
    }

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("id", $id);
        $stmt->execute();
        $user = $stmt->fetchObject();
        $db = null;
        $user->friend_status = $friend_status_return;
        echo json_encode($user);
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
    }
}

function updateUser() {
	$request = Slim::getInstance()->request();
    $body = $request->getBody();
    $user = json_decode($body);

    $sql = "SELECT

        user_id

        FROM sessions WHERE token=:token LIMIT 1";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("token", $user->session_token);
        $stmt->execute();
        $session = $stmt->fetchObject();
        $db = null;
        echo json_encode($user);
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
    }

    if(!isset($session->id)){
        echo '{"error":{"text":"Token is not valid","errorid":"12"}}';
        exit;
    }

    $sql = "UPDATE users
    SET

    username=:username,
    name=:name,
    phone=:phone,
    address1=:address1,
    address2=:address2,
    city=:city,
    state=:state,
    zip=:zip,
    profile=:profile

    WHERE id=:id";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);

        $stmt->bindParam("id", $session->user_id);
        $stmt->bindParam("username", $user->username);
        $stmt->bindParam("name", $user->name);
        $stmt->bindParam("phone", $user->phone);
        $stmt->bindParam("address1", $user->address1);
        $stmt->bindParam("address2", $user->address2);
        $stmt->bindParam("city", $user->city);
        $stmt->bindParam("state", $user->state);
        $stmt->bindParam("zip", $user->zip);
        $stmt->bindParam("profile", $user->profile);

        $stmt->execute();
        $db = null;
        echo json_encode($user);
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
    }
}

function deleteUser() {
    $request = Slim::getInstance()->request();
    $body = $request->getBody();
    $user = json_decode($body);

    $sql = "SELECT

        user_id

        FROM sessions WHERE token=:token LIMIT 1";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("token", $user->session_token);
        $stmt->execute();
        $session = $stmt->fetchObject();
        $db = null;
        echo json_encode($user);
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
    }

    if(!isset($session->id)){
        echo '{"error":{"text":"Token is not valid","errorid":"12"}}';
        exit;
    }

	$sql = "DELETE FROM users WHERE id=:id";
    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("id", $session->user_id);
        $stmt->execute();
        $db = null;
        echo json_encode($user);
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
    }

    $sql = "DELETE FROM sessions WHERE user_id=:user_id";
    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("user_id", $session->user_id);
        $stmt->execute();
        $db = null;
        echo json_encode($user);
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
    }

    $sql = "DELETE FROM events WHERE host_id=:host_id";
    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("host_id", $session->user_id);
        $stmt->execute();
        $db = null;
        echo json_encode($user);
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
    }
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
