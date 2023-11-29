<?php

class String
{
    public function isNumber($str) 
    {
        return preg_match("/^[0-9]*$/", $str);
    }

    public function isNullorEmpty($str)
    {
        return (is_null($str) || empty($str));
    }
}

?>