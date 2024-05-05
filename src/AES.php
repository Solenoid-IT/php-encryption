<?php



namespace Solenoid\Encryption;



class AES
{
    const HASH_ALGO = 'sha256';
    const ENC_ALGO  = 'AES-256-GCM';



    public string $value;



    # Returns [self]
    public function __construct (string $value)
    {
        // (Getting the value)
        $this->value = $value;
    }

    # Returns [AES]
    public static function select (string $value)
    {
        // Returning the value
        return new AES( $value );
    }



    # Returns [AES|false] | Throws [Exception]
    public function encrypt (string $key)
    {
        // (Getting the value)
        $key = hash( self::HASH_ALGO, $key, true );



        // (Getting the value)
        $iv = openssl_random_pseudo_bytes( 16 );

        if ( $iv === false )
        {// (Unable to generate the IV)
            // (Setting the value)
            $message = "Unable to generate the IV";

            // Throwing an exception
            throw new \Exception($message);

            // Returning the value
            return false;
        }



        // (Getting the value)
        $ciphertext = openssl_encrypt( $this->value, self::ENC_ALGO, $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16 );

        if ( $ciphertext === false )
        {// (Unable to encrypt the value)
            // (Setting the value)
            $message = "Unable to encrypt the value";

            // Throwing an exception
            throw new \Exception($message);

            // Returning the value
            return false;
        }



        // (Getting the value)
        $signature = hash_hmac( self::HASH_ALGO, $ciphertext . $iv . $tag, $key, true );



        // Returning the value
        return AES::select( $iv . $tag . $signature . $ciphertext );
    }

    # Returns [AES|false] | Throws [Exception]
    public function decrypt (string $key)
    {
        // (Getting the value)
        $key = hash( self::HASH_ALGO, $key, true );



        // (Getting the values)
        $iv         = substr( $this->value, 0, 16 );
        $tag        = substr( $this->value, 16, 16 );
        $signature  = substr( $this->value, 32, 32 );
        $ciphertext = substr( $this->value, 64 );



        // (Getting the value)
        $current_signature = hash_hmac( self::HASH_ALGO, $ciphertext . $iv . $tag, $key, true );

        if ( !hash_equals( $current_signature, $signature ) )
        {// Match failed
            // Returning the value
            return false;
        }



        // (Getting the value)
        $cleartext = openssl_decrypt( $ciphertext, self::ENC_ALGO, $key, OPENSSL_RAW_DATA, $iv, $tag );

        if ( $cleartext === false )
        {// (Key is not valid)
            // Returning the value
            return false;
        }



        // Returning the value
        return AES::select( $cleartext );
    }



    # Returns [string]
    public function __toString ()
    {
        // Returning the value
        return $this->value;
    }
}



?>