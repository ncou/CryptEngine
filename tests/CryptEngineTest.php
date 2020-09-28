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
    public function testEmptyString()
    {
        $str = '';
        $key = 'MySecureKey';
        $cipher = CryptEngine::encrypt($str, $key);
        $this->assertSame($str, CryptEngine::decrypt($cipher, $key));
    }

    public function testEncodeAndDecode()
    {
        $str = 'MySecretMessageToEncode';
        $key = 'MySecureKey';
        $cipher = CryptEngine::encrypt($str, $key);
        $this->assertSame($str, CryptEngine::decrypt($cipher, $key));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Decryption can not proceed due to invalid ciphertext checksum.
     */
    public function testErrorDecode()
    {
        $str = 'MySecretMessageToEncode';
        $key = 'MySecureKey';
        $cipher = CryptEngine::encrypt($str, $key);
        $this->assertSame($str, CryptEngine::decrypt($cipher, 'Bad_Secret_Key'));
    }
}
