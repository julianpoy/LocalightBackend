<?php
function getConnection() {
    $dbhost="localhost";
    $dbuser="root";
    $dbpass="<j<}6GxgKRn3?q";
    $dbname="nudgeit";
    $dbh = new PDO("mysql:host=$dbhost;dbname=$dbname", $dbuser, $dbpass);  
    $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    return $dbh;
}
?>
