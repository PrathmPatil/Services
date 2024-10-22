1) openssl
<?php
    $cipher = "aes-128-gcm";
    $key = 'encryptionKey123';  // Encryption key
    $ivlen = openssl_cipher_iv_length($cipher);
    $iv = openssl_random_pseudo_bytes($ivlen);

    // Encryption function
    function encrypt($data) {        
        global $cipher, $key, $iv; 

        if (in_array($cipher, openssl_get_cipher_methods())) {            
            $tag = null;  
            $encrypted_data = openssl_encrypt($data, $cipher, $key, $options=0, $iv, $tag);

            $data_arr = [
                'encrypted_data' => base64_encode($encrypted_data), 
                'iv' => base64_encode($iv),  
                'tag' => base64_encode($tag)  
            ];
            return $data_arr;            
        }
        return false;  
    }

    // Decryption function
    function decrypt($encrypted_data, $iv, $tag) {
        global $cipher, $key;

        $iv = base64_decode($iv);
        $encrypted_data = base64_decode($encrypted_data);
        $tag = base64_decode($tag);

        $original_plaintext = openssl_decrypt($encrypted_data, $cipher, $key, $options=0, $iv, $tag);

        if ($original_plaintext === false) {
            return "Decryption failed";
        }

        return $original_plaintext;
    }

?>

2) sodium
<?php
// Key generation
$key = sodium_crypto_secretbox_keygen(); // Generate a random key

// Encryption
function encrypt($data, $key) {
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES); // Generate nonce
    $encrypted = sodium_crypto_secretbox($data, $nonce, $key);
    return [
        'encrypted_data' => base64_encode($encrypted),
        'nonce' => base64_encode($nonce)
    ];
}

// Decryption
function decrypt($encrypted_data, $nonce, $key) {
    $encrypted_data = base64_decode($encrypted_data);
    $nonce = base64_decode($nonce);
    return sodium_crypto_secretbox_open($encrypted_data, $nonce, $key);
}

// Example usage
$data = "Sensitive Data";

// Encrypt
$encrypted = encrypt($data, $key);
print_r($encrypted['encrypted_data']);

// Decrypt
$decrypted = decrypt($encrypted['encrypted_data'], $encrypted['nonce'], $key);
echo "\nDecrypted Data: " . $decrypted;

?>

3)
