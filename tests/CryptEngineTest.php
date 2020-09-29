<?php

declare(strict_types=1);

namespace Chiron\Tests;

use Chiron\CryptEngine;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Chiron\CryptEngine
 */
class CryptEngineTest extends TestCase
{
    public function testWithEmptyString()
    {
        $str = '';
        $key = random_bytes(32);

        $ciphertext = CryptEngine::encrypt($str, $key);

        $this->assertSame($str, CryptEngine::decrypt($ciphertext, $key));
    }

    public function testSuccessEncryptAndDecrypt()
    {
        $str = 'MySecretMessageToCrypt';
        $key = random_bytes(32);

        $ciphertext = CryptEngine::encrypt($str, $key);

        $this->assertSame($str, CryptEngine::decrypt($ciphertext, $key));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Decryption can not proceed due to invalid ciphertext integrity.
     */
    public function testExceptionDecryptWithBadKey()
    {
        $str = 'MySecretMessageToCrypt';
        $key = random_bytes(32);
        $badKey = random_bytes(32);

        $ciphertext = CryptEngine::encrypt($str, $key);

        $this->assertSame($str, CryptEngine::decrypt($ciphertext, $badKey));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Bad key length [expect a 32 bytes length]
     */
    public function testExceptionDecryptWithKeyTooShort()
    {
        $str = 'MySecretMessageToCrypt';
        $key = random_bytes(30);

        $ciphertext = CryptEngine::encrypt($str, $key);

        $this->assertSame($str, CryptEngine::decrypt($ciphertext, $key));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Bad key length [expect a 32 bytes length]
     */
    public function testExceptionDecryptWithKeyTooLong()
    {
        $str = 'MySecretMessageToCrypt';
        $key = random_bytes(34);

        $ciphertext = CryptEngine::encrypt($str, $key);

        $this->assertSame($str, CryptEngine::decrypt($ciphertext, $key));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Decryption can not proceed due to invalid ciphertext integrity.
     */
    public function testExceptionDecryptWithBadCipherText()
    {
        $str = 'MySecretMessageToCrypt';
        $key = random_bytes(32);

        $ciphertext = CryptEngine::encrypt($str, $key);

        $this->assertSame($str, CryptEngine::decrypt($ciphertext . 'a', $key));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Decryption can not proceed due to invalid ciphertext length.
     */
    public function testExceptionDecryptWithCipherTooSmall()
    {
        $str = 'MySecretMessageToCrypt';
        $key = random_bytes(32);

        $ciphertext = str_repeat('A', CryptEngine::MINIMUM_CIPHERTEXT_SIZE - 1);

        $this->assertSame($str, CryptEngine::decrypt($ciphertext, $key));
    }

    /**
     * @dataProvider headerPositions
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Decryption can not proceed due to invalid ciphertext integrity.
     */
    public function testExceptionDecryptWithBadCipherHeader(int $index)
    {
        $str = 'MySecretMessageToCrypt';
        $key = random_bytes(32);

        $ciphertext = CryptEngine::encrypt($str, $key);
        $ciphertext[$index] = chr((ord($ciphertext[$index]) + 1) % 256);

        $this->assertSame($str, CryptEngine::decrypt($ciphertext, $key));
    }

    public function headerPositions(): array
    {
        return [
            [0], // the hmac.
            [CryptEngine::MAC_BYTE_SIZE + 1], // the salt
            [CryptEngine::MAC_BYTE_SIZE + CryptEngine::SALT_BYTE_SIZE + 1], // the IV
            [CryptEngine::MAC_BYTE_SIZE + CryptEngine::SALT_BYTE_SIZE + CryptEngine::IV_BYTE_SIZE + 1], // the ciphertext
        ];
    }
}
