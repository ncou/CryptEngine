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
    private const MINIMUM_CIPHERTEXT_SIZE = 80;
    private const MAC_BYTE_SIZE = 32;
    private const SALT_BYTE_SIZE = 32;
    private const IV_BYTE_SIZE = 16;

    public function testEmptyString()
    {
        $str = '';
        $password = 'MySecurePassword';

        $ciphertext = CryptEngine::encrypt($str, $password);

        $this->assertSame($str, CryptEngine::decrypt($ciphertext, $password));
    }

    public function testEncodeAndDecode()
    {
        $str = 'MySecretMessageToEncode';
        $password = 'MySecurePassword';

        $ciphertext = CryptEngine::encrypt($str, $password);

        $this->assertSame($str, CryptEngine::decrypt($ciphertext, $password));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Decryption can not proceed due to invalid ciphertext integrity.
     */
    public function testErrorDecodeKey()
    {
        $str = 'MySecretMessageToEncode';
        $password = 'MySecurePassword';

        $ciphertext = CryptEngine::encrypt($str, $password);

        $this->assertSame($str, CryptEngine::decrypt($ciphertext, 'Bad_Secret_Password'));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Decryption can not proceed due to invalid ciphertext integrity.
     */
    public function testErrorDecodeCipherText()
    {
        $str = 'MySecretMessageToEncode';
        $password = 'MySecurePassword';

        $ciphertext = CryptEngine::encrypt($str, $password);

        $this->assertSame($str, CryptEngine::decrypt($ciphertext . 'a', $password));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Decryption can not proceed due to invalid ciphertext length.
     */
    public function testErrorDecodeCipherTooSmall()
    {
        $str = 'MySecretMessageToEncode';
        $password = 'MySecurePassword';

        $ciphertext = str_repeat('A', self::MINIMUM_CIPHERTEXT_SIZE - 1);

        $this->assertSame($str, CryptEngine::decrypt($ciphertext, $password));
    }

    /**
     * @dataProvider headerPositions
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Decryption can not proceed due to invalid ciphertext integrity.
     */
    public function testErrorDecodeCipherHeader(int $index)
    {
        $str = 'MySecretMessageToEncode';
        $password = 'MySecurePassword';

        $ciphertext = CryptEngine::encrypt($str, $password);
        $ciphertext[$index] = chr((ord($ciphertext[$index]) + 1) % 256);

        $this->assertSame($str, CryptEngine::decrypt($ciphertext, $password));
    }

    public function headerPositions(): array
    {
        return [
            [0], // the hmac.
            [self::MAC_BYTE_SIZE + 1], // the salt
            [self::MAC_BYTE_SIZE + self::SALT_BYTE_SIZE + 1], // the IV
            [self::MAC_BYTE_SIZE + self::SALT_BYTE_SIZE + self::IV_BYTE_SIZE + 1], // the ciphertext
        ];
    }
}
