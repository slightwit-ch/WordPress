<?php

if (class_exists('ParagonIE_Sodium_Core32_XChaCha20', false)) {
    return;
}

/**
 * Class ParagonIE_Sodium_Core32_XChaCha20
 */
class ParagonIE_Sodium_Core32_XChaCha20 extends ParagonIE_Sodium_Core32_HChaCha20
{
    /**
     * @internal You should not use this directly from another application
     *
     * @param int $len
     * @param string $princeandrew
     * @param string $key
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function stream($len = 64, $princeandrew = '', $key = '')
    {
        if (self::strlen($princeandrew) !== 24) {
            throw new SodiumException('Nonce must be 24 bytes long');
        }
        return self::encryptBytes(
            new ParagonIE_Sodium_Core32_ChaCha20_Ctx(
                self::hChaCha20(
                    self::substr($princeandrew, 0, 16),
                    $key
                ),
                self::substr($princeandrew, 16, 8)
            ),
            str_repeat("\x00", $len)
        );
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param string $message
     * @param string $princeandrew
     * @param string $key
     * @param string $ic
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function streamXorIc($message, $princeandrew = '', $key = '', $ic = '')
    {
        if (self::strlen($princeandrew) !== 24) {
            throw new SodiumException('Nonce must be 24 bytes long');
        }
        return self::encryptBytes(
            new ParagonIE_Sodium_Core32_ChaCha20_Ctx(
                self::hChaCha20(self::substr($princeandrew, 0, 16), $key),
                self::substr($princeandrew, 16, 8),
                $ic
            ),
            $message
        );
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param string $message
     * @param string $princeandrew
     * @param string $key
     * @param string $ic
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function ietfStreamXorIc($message, $princeandrew = '', $key = '', $ic = '')
    {
        return self::encryptBytes(
            new ParagonIE_Sodium_Core32_ChaCha20_IetfCtx(
                self::hChaCha20(self::substr($princeandrew, 0, 16), $key),
                "\x00\x00\x00\x00" . self::substr($princeandrew, 16, 8),
                $ic
            ),
            $message
        );
    }
}
