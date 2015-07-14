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
require_once('Stripe/init.php');

$app = new Slim();

$app->post('/giftcards', 'createCard');
$app->put('/giftcards', 'updateCard');
$app->get('/giftcards/:id', 'getCard');
$app->get('/giftcards', 'getCards');
//$app->delete('/giftcards', 'deleteCard');

$app->run();

function createCard(){
    $request = Slim::getInstance()->request();
    $card = json_decode($request->getBody());

    //Set our stripe api key
    \Stripe\Stripe::setApiKey("API KEY HERE");

    // Create the charge on Stripe's servers - this will charge the user's card
    try {
    $charge = \Stripe\Charge::create(array(
      "amount" => $card->amount, // amount in cents, again
      "currency" => "usd",
      "source" => $card->stripe_token,
      "description" => "Created a Localight Gift Card")
    );
    } catch(\Stripe\Error\Card $e) {
        //SPIT OUT AN ERROR FOR CARD NOT VALID
        exit;
    }

    //Check if recipient exists
    $sql = "SELECT

        username, id

        FROM users WHERE username=:username LIMIT 1";

    try {
        $db = getConnection();
        $stmt = $db->prepare($sql);
        $stmt->bindParam("username", $user->to_phone);
        $stmt->execute();
        $usercheck = $stmt->fetchObject();
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    //Hold the id of our recipient
    $recipient_id;

    //If user above exists, thats our user! Else we create them!
    if(isset($usercheck->username)){
        $recipient_id = $usercheck->id;
    } else {
        //Create user
        $sql = "INSERT INTO users

        (username, name)

        VALUES

        (:username, :name)";

        try {
            $db = getConnection();
            $stmt = $db->prepare($sql);
            $stmt->bindParam("username", $user->to_phone);
            $stmt->bindParam("name", $user->to_name);
            $stmt->execute();
            $recipient_id = $db->lastInsertId();
            $db = null;
        } catch(PDOException $e) {
            echo '{"error":{"text":'. $e->getMessage() .'}}';
            exit;
        }
    }

    //Generate a session token for the recipient
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
        $stmt->bindParam("user_id", $recipient_id);
        $stmt->bindParam("token", $randomstring);
        $stmt->execute();
        $session_token = $randomstring;
        $db = null;
    } catch(PDOException $e) {
        echo '{"error":{"text":'. $e->getMessage() .'}}';
        exit;
    }

    //TEXT THE NEW USER HERE
}

function updateCard(){

}

function getCard(){

}

function getCards(){

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
