<?php

declare(strict_types=1);

namespace Chiron;

use InvalidArgumentException;
use RuntimeException;

/**
 * Encrypter.
 *
 * This class encrypts and decrypts the given value using a password.
 * It uses OpenSSL extension with AES-256 cipher for encryption and HMAC-SHA-256 for hash.
 * The encryption key and authentification key are both derivated from the original key.
 */
class CryptEngine
{
    public const CIPHER_METHOD = 'aes-256-ctr';
    public const HASH_FUNCTION_NAME = 'sha256';
    public const KEY_BYTE_SIZE = 32;
    public const ENCRYPTION_INFO_STRING = 'CryptEngine|KeyForEncryption';
    public const AUTHENTICATION_INFO_STRING = 'CryptEngine|KeyForAuthentication';
    public const MINIMUM_CIPHERTEXT_SIZE = 80;
    public const MAC_BYTE_SIZE = 32;
    public const SALT_BYTE_SIZE = 32;
    public const IV_BYTE_SIZE = 16;

    /**
     * Encrypt the given data.
     *
     * Format : HMAC (32 bytes) || SALT (32 bytes) || IV (16 bytes) || CIPHERTEXT (varies).
     *
     * @param string $plaintext The data to encrypt
     * @param string $key       Binary key used to encrypt data.
     *
     * @return string
     */
    public static function encrypt(string $plaintext, string $key): string
    {
        self::assertKeyLength($key);

        // Generate a random value used as 'salt'.
        $salt = random_bytes(self::SALT_BYTE_SIZE);
        // Derive the separate encryption/authentication keys from the original key.
        [$ekey, $akey] = self::derivateKeys($key, $salt);

        // Generate initialization vector.
        $iv = random_bytes(self::IV_BYTE_SIZE);
        // Encrypt the given data using the default cipher.
        $ciphertext = self::plainEncrypt($plaintext, $ekey, $iv);

        // Prepare the encrypted result and calculate the checksum.
        $encrypted = $salt . $iv . $ciphertext;
        $hmac = self::hash($encrypted, $akey);

        return $hmac . $encrypted;
    }

    /**
     * Decrypt the given data.
     *
     * Format : HMAC (32 bytes) || SALT (32 bytes) || IV (16 bytes) || CIPHERTEXT (varies).
     *
     * @param string $ciphertext The Data to decrypt
     * @param string $key        Binary key that should be used to decrypt input data
     *
     * @return string
     */
    public static function decrypt(string $ciphertext, string $key): string
    {
        self::assertKeyLength($key);

        if (self::strlen($ciphertext) < self::MINIMUM_CIPHERTEXT_SIZE) {
            throw new InvalidArgumentException('Decryption can not proceed due to invalid ciphertext length.');
        }

        // Split the header to get all the parts (salt, iv...etc)
        $hmac = self::substr($ciphertext, 0, self::MAC_BYTE_SIZE);
        $salt = self::substr($ciphertext, self::MAC_BYTE_SIZE, self::SALT_BYTE_SIZE);
        $iv = self::substr($ciphertext, self::MAC_BYTE_SIZE + self::SALT_BYTE_SIZE, self::IV_BYTE_SIZE);
        $encrypted = self::substr($ciphertext, self::MAC_BYTE_SIZE + self::SALT_BYTE_SIZE + self::IV_BYTE_SIZE, null);

        // Derive the separate encryption/authentication keys from the original key.
        [$ekey, $akey] = self::derivateKeys($key, $salt);

        // Calculate a fresh hash and compare it with the hmac to enforce integrity.
        $hash = self::hash($salt . $iv . $encrypted, $akey);
        if (! hash_equals($hmac, $hash)) {
            throw new InvalidArgumentException('Decryption can not proceed due to invalid ciphertext integrity.');
        }

        return self::plainDecrypt($encrypted, $ekey, $iv);
    }

    /**
     * Derives encryption and authentication keys from the secret key.
     *
     * @param string $key
     * @param string $salt
     *
     * @return array<string>
     */
    private static function derivateKeys(string $key, string $salt): array
    {
        // Encryption key.
        $ekey = hash_hkdf(
            self::HASH_FUNCTION_NAME,
            $key,
            self::KEY_BYTE_SIZE,
            self::ENCRYPTION_INFO_STRING,
            $salt
        );
        // Authentication key.
        $akey = hash_hkdf(
            self::HASH_FUNCTION_NAME,
            $key,
            self::KEY_BYTE_SIZE,
            self::AUTHENTICATION_INFO_STRING,
            $salt
        );

        return [$ekey, $akey];
    }

    /**
     * Raw encryption.
     *
     * @param string $plaintext
     * @param string $key
     * @param string $iv
     *
     * @throws \RuntimeException
     *
     * @return string
     */
    private static function plainEncrypt(string $plaintext, string $key, string $iv): string
    {
        // Encrypt the given data
        $ciphertext = openssl_encrypt($plaintext, self::CIPHER_METHOD, $key, OPENSSL_RAW_DATA, $iv);

        if ($ciphertext === false) {
            // @codeCoverageIgnoreStart
            throw new RuntimeException(sprintf('Encryption of content failed [%s].', openssl_error_string()));
            // @codeCoverageIgnoreEnd
        }

        return $ciphertext;
    }

    /**
     * Raw decryption.
     *
     * @param string $ciphertext
     * @param string $key
     * @param string $iv
     *
     * @throws \RuntimeException
     *
     * @return string
     */
    private static function plainDecrypt(string $ciphertext, string $key, string $iv): string
    {
        // Decrypt the given data
        $plaintext = openssl_decrypt($ciphertext, self::CIPHER_METHOD, $key, OPENSSL_RAW_DATA, $iv);

        if ($plaintext === false) {
            // @codeCoverageIgnoreStart
            throw new RuntimeException(sprintf('Decryption of content failed [%s].', openssl_error_string()));
            // @codeCoverageIgnoreEnd
        }

        return $plaintext;
    }

    /**
     * Assert the binary key has a 32 bytes length.
     *
     * @param string $key
     *
     * @throws \InvalidArgumentException
     */
    private static function assertKeyLength(string $key): void
    {
        if (self::strlen($key) !== self::KEY_BYTE_SIZE) {
            throw new InvalidArgumentException(sprintf('Bad key length [expecting %d bytes].', self::KEY_BYTE_SIZE));
        }
    }

    /**
     * Generate a keyed hash value using the HMAC method.
     *
     * @param string $data Data to hash
     * @param string $key  Key to use to authenticate the hash.
     *
     * @return string
     */
    private static function hash(string $data, string $key): string
    {
        return hash_hmac(self::HASH_FUNCTION_NAME, $data, $key, true);
    }

    /**
     * Returns part of a string.
     *
     * @param string $string The string whose length we wish to obtain
     * @param int    $start
     * @param int    $length
     *
     * @return string
     */
    private static function substr(string $string, int $start, ?int $length = null): string
    {
        return mb_substr($string, $start, $length, '8bit');
    }

    /**
     * Returns length of a string.
     *
     * @param string $string The string whose length we wish to obtain
     *
     * @return int
     */
    private static function strlen(string $string): int
    {
        return mb_strlen($string, '8bit');
    }
}
