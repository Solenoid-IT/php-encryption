<?php



namespace Solenoid\Encryption;



class KeyPair
{
    public string $private_key;
    public string $public_key;



    # Returns [self]
    public function __construct (string $private_key, string $public_key)
    {
        // (Getting the values)
        $this->private_key = $private_key;
        $this->public_key  = $public_key;
    }

    # Returns [KeyPair]
    public static function create (string $private_key, string $public_key)
    {
        // Returning the value
        return new KeyPair( $private_key, $public_key );
    }



    # Returns [KeyPair|false] | Throws [Exception]
    public static function generate (int $bits = 4096)
    {
        // (Generating a key)
        $key = openssl_pkey_new
        (
            [
                'digest_alg'       => 'sha512',

                'private_key_bits' => $bits,
                'private_key_type' => OPENSSL_KEYTYPE_RSA
            ]
        )
        ;

        if ( $key === false )
        {// (Unable to generate a key)
            // (Setting the value)
            $message = "Unable to generate a key";

            // Throwing an exception
            throw new \Exception($message);

            // Returning the value
            return false;
        }



        if ( !openssl_pkey_export( $key, $private_key ) )
        {// (Unable to get the private key)
            // (Setting the value)
            $message = "Unable to get the private key";

            // Throwing an exception
            throw new \Exception($message);

            // Returning the value
            return false;
        }



        // (Getting the key details)
        $details = openssl_pkey_get_details( $key );

        if ( $details === false )
        {// (Unable to get the key details)
            // (Setting the value)
            $message = "Unable to get the key details";

            // Throwing an exception
            throw new \Exception($message);

            // Returning the value
            return false;
        }



        // (Getting the value)
        $public_key = $details['key'];



        // Returning the value
        return KeyPair::create( $private_key, $public_key );
    }
}



?>