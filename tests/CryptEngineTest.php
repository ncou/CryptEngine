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

    public function testExceptionDecryptWithBadKey()
    {
        $str = 'MySecretMessageToCrypt';
        $key = random_bytes(32);
        $badKey = random_bytes(32);

        $ciphertext = CryptEngine::encrypt($str, $key);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Decryption can not proceed due to invalid ciphertext integrity.');

        CryptEngine::decrypt($ciphertext, $badKey);
    }

    public function testExceptionEncryptWithKeyTooShort()
    {
        $str = 'MySecretMessageToCrypt';

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Bad key length [expecting 32 bytes].');

        $ciphertext = CryptEngine::encrypt($str, random_bytes(30));
    }

    public function testExceptionDecryptWithKeyTooShort()
    {
        $str = 'MySecretMessageToCrypt';

        $ciphertext = CryptEngine::encrypt($str, random_bytes(32));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Bad key length [expecting 32 bytes].');

        CryptEngine::decrypt($ciphertext, random_bytes(30));
    }

    public function testExceptionEncryptWithKeyTooLong()
    {
        $str = 'MySecretMessageToCrypt';

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Bad key length [expecting 32 bytes].');

        $ciphertext = CryptEngine::encrypt($str, random_bytes(34));
    }

    public function testExceptionDecryptWithKeyTooLong()
    {
        $str = 'MySecretMessageToCrypt';

        $ciphertext = CryptEngine::encrypt($str, random_bytes(32));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Bad key length [expecting 32 bytes].');

        CryptEngine::decrypt($ciphertext, random_bytes(34));
    }

    public function testExceptionDecryptWithBadCipherText()
    {
        $str = 'MySecretMessageToCrypt';
        $key = random_bytes(32);

        $ciphertext = CryptEngine::encrypt($str, $key);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Decryption can not proceed due to invalid ciphertext integrity.');

        CryptEngine::decrypt($ciphertext . 'a', $key);
    }

    public function testExceptionDecryptWithCipherTooSmall()
    {
        $str = 'MySecretMessageToCrypt';
        $key = random_bytes(32);

        $ciphertext = str_repeat('A', CryptEngine::MINIMUM_CIPHERTEXT_SIZE - 1);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Decryption can not proceed due to invalid ciphertext length.');

        CryptEngine::decrypt($ciphertext, $key);
    }

    /**
     * @dataProvider headerPositions
     */
    public function testExceptionDecryptWithBadCipherHeader(int $index)
    {
        $str = 'MySecretMessageToCrypt';
        $key = random_bytes(32);

        $ciphertext = CryptEngine::encrypt($str, $key);
        $ciphertext[$index] = chr((ord($ciphertext[$index]) + 1) % 256);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Decryption can not proceed due to invalid ciphertext integrity.');

        CryptEngine::decrypt($ciphertext, $key);
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
