<?php


function Enhanced_Trim($inp) {
    $trimmed = array("\r", "\n", "\t", "/", " ");
    return str_replace($trimmed, "", $inp);
}


if(isset($_GET['name']))
{
    $name=substr($_GET['name'],0,23);
    echo "Hello, ".Enhanced_Trim($_GET['name']);
}

?>