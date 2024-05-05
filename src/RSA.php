<?php



namespace Solenoid\Encryption;



class RSA
{
    public string $value;



    # Returns [self]
    public function __construct (string $value)
    {
        // (Getting the value)
        $this->value = $value;
    }

    # Returns [RSA]
    public static function select (string $value)
    {
        // Returning the value
        return new RSA( $value );
    }



    # Returns [RSA|false] | Throws [Exception]
    public function encrypt (string $public_key)
    {
        if ( !openssl_public_encrypt( $this->value, $ciphertext, $public_key ) )
        {// (Unable to encrypt the value)
            // (Setting the value)
            $message = "Unable to encrypt the value";

            // Throwing an exception
            throw new \Exception($message);

            // Returning the value
            return false;
        }



        // Returning the value
        return RSA::select( $ciphertext );
    }

    # Returns [RSA|false] | Throws [Exception]
    public function decrypt (string $private_key)
    {
        if ( !openssl_private_decrypt( $this->value, $cleartext, $private_key ) )
        {// (Unable to decrypt the bytes)
            // Returning the value
            return false;
        }



        // Returning the value
        return RSA::select( $cleartext );
    }



    # Returns [string]
    public function __toString ()
    {
        // Returning the value
        return $this->value;
    }
}



?>