<?php
namespace Faforty\FwEncrypt;


class FwEncrypt
{

    public static $conf;
    private static $crypt;

    public static function start($opt)
    {
        self::$crypt = isset($opt['crypt']) ? TRUE : FALSE;

        return new self;
    }

    public function config($conf = array())
    {
        self::$conf = $conf;
    }

    public static function get($data, $key = null)
    {
        $data = self::unqz($data);

        if(self::$crypt)
        {
            $data = self::mc_decrypt($data);
        }

        return $data;
    }

    public static function set($data, $key = null)
    {
        if(self::$crypt)
        {
            $data = self::mc_encrypt($data);
        }

        return self::gz($data);
    }

    private static function gz($a)
    {
        return addslashes(gzdeflate(var_export(serialize($a), true), 9));
    }

    private static function unqz($a)
    {
        eval('$array=' . gzinflate(stripslashes($a)) . ';');
        return unserialize($array);
    }


    private static function strcode($str, $key="")
    {
        $len = strlen($str);
        $gamma = '';
        $n = $len>100 ? 8 : 2;
        while( strlen($gamma)<$len )
        {
            $gamma .= substr(pack('H*', sha1($key . $gamma . self::$conf['salt'])), 0, $n);
        }
        return $str^$gamma;
    }

    public static function mc_encrypt($encrypt){
        $encrypt = serialize($encrypt);
        $iv = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC), MCRYPT_DEV_URANDOM);
        $key = pack('H*', self::$conf['key']);
        $mac = hash_hmac('sha256', $encrypt, substr(bin2hex($key), -32));
        $passcrypt = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $encrypt.$mac, MCRYPT_MODE_CBC, $iv);
        $encoded = base64_encode($passcrypt).'|'.base64_encode($iv);

        return $encoded;
    }

    public static function mc_decrypt($decrypt){
        $decrypt = explode('|', $decrypt.'|');
        $decoded = base64_decode($decrypt[0]);
        $iv = base64_decode($decrypt[1]);

        if(strlen($iv)!==mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC))
        {
            return false;
        }

        $key = pack('H*',  self::$conf['key']);
        $decrypted = trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, $decoded, MCRYPT_MODE_CBC, $iv));
        $mac = substr($decrypted, -64);
        $decrypted = substr($decrypted, 0, -64);
        $calcmac = hash_hmac('sha256', $decrypted, substr(self::$conf['key'], -32));

        if($calcmac !== $mac)
        {
            return false;
        }

        $decrypted = unserialize($decrypted);

        return $decrypted;
    }

    public static function genKey($salt = '')
    {
        return hash('sha256', $salt);
    }
}
