<?php
/**
 * Simple PHP Encrypter/Decrypter.
 *
 * @author  ncou
 *
 * @see    https://github.com/ncou/CryptEngine
 *
 * @license https://github.com/ncou/CryptEngine/blob/master/LICENSE (MIT License)
 */

namespace Chiron;

use InvalidArgumentException;
use RuntimeException;

/**
 * Encrypter.
 *
 * This class encrypts and decrypts the given value. It uses OpenSSL extension
 * with AES-256 cipher for encryption and HMAC-SHA-256 for hash.
 * The encryption and hash use the same key (derivated from the password).
 */
class CryptEngine
{
    /**
     * @var string AES-256 cipher identifier that will be passed to openssl
     */
    private const CIPHER = 'AES-256-CTR';

    /**
     * @var int Size of initialization vector in bytes
     */
    private const IVSIZE = 16;

    /**
     * @var string Hardcoded hashing algo string.
     */
    private const ALGO = 'sha256';

    /**
     * @var int Size of checksum in bytes
     */
    private const CKSIZE = 32;

    /**
     * Encrypt the given data.
     *
     * @param string $data     The data to encrypt
     * @param string $password Password used to encrypt data.
     *
     * @return string
     */
    public static function encrypt(string $data, string $password): string
    {
        // Generate IV of appropriate size.
        $iv = self::generateIv();
        // Derive key from password
        $key = self::hash($iv, $password);
        // Encrypt the given data
        $cyphertext = openssl_encrypt($data, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv);

        if ($cyphertext === false) {
            // @codeCoverageIgnoreStart
            throw new RuntimeException('Encryption library: Encryption (symmetric) of content failed: ' . openssl_error_string());
            // @codeCoverageIgnoreEnd
        }
        // Checksum : Create a keyed hash for the encrypted data
        $checksum = self::hash($iv . $cyphertext, $key);
        // concat all the elements in the final encrypted string
        $encrypted = $iv . $checksum . $cyphertext;

        return $encrypted;
    }

    /**
     * Decrypt the given data.
     *
     * @param string $data     The Data to decrypt
     * @param string $password Password that should be used to decrypt input data
     *
     * @return string
     */
    public static function decrypt(string $data, string $password): string
    {
        // Find the IV at the beginning of the cypher text
        $iv = self::substr($data, 0, self::IVSIZE);
        // Gather the checksum portion of the encrypted text
        $checksum = self::substr($data, self::IVSIZE, self::CKSIZE);
        // Gather message portion of encrypted text after iv and checksum
        $cyphertext = self::substr($data, self::IVSIZE + self::CKSIZE, null);

        // Derive key from password
        $key = self::hash($iv, $password);
        // Checksum : Create a keyed hash for the decrypted data
        $sum = self::hash($iv . $cyphertext, $key);

        if (! hash_equals($checksum, $sum)) {
            throw new InvalidArgumentException('Decryption can not proceed due to invalid cyphertext checksum.');
        }
        // Decrypt the given data
        $decrypted = openssl_decrypt($cyphertext, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv);
        if ($decrypted === false) {
            // @codeCoverageIgnoreStart
            throw new RuntimeException('Encryption library: Decryption (symmetric) of content failed: ' . openssl_error_string());
            // @codeCoverageIgnoreEnd
        }

        return $decrypted;
    }

    /**
     * generate initialization vector.
     *
     * @throws GenericEncryptionException
     *
     * @return string
     */
    private static function generateIv(): string
    {
        return random_bytes(self::IVSIZE);
    }

    /**
     * Perform a single hmac iteration. This adds an extra layer of safety because hash_hmac can return false if algo
     * is not valid. Return type hint will throw an exception if this happens.
     *
     *
     * @param string $data Data to hash
     * @param string $key  Key to use to authenticate the hash.
     *
     * @return string
     */
    private static function hash(string $data, string $key): string
    {
        return hash_hmac(self::ALGO, $data, $key, true);
    }

    /**
     * Returns part of a string.
     *
     * @param string $string The string whose length we wish to obtain
     * @param int    $start
     * @param int    $length
     *
     * @return string the extracted part of string; or FALSE on failure, or an empty string.
     */
    private static function substr(string $string, int $start, int $length = null): string
    {
        return mb_substr($string, $start, $length, '8bit');
    }
}
