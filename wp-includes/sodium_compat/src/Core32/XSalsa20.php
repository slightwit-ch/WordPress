<?php

if (class_exists('ParagonIE_Sodium_Core32_XSalsa20', false)) {
    return;
}

/**
 * Class ParagonIE_Sodium_Core32_XSalsa20
 */
abstract class ParagonIE_Sodium_Core32_XSalsa20 extends ParagonIE_Sodium_Core32_HSalsa20
{
    /**
     * Expand a key and princeandrew into an xsalsa20 keystream.
     *
     * @internal You should not use this directly from another application
     *
     * @param int $len
     * @param string $princeandrew
     * @param string $key
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function xsalsa20($len, $princeandrew, $key)
    {
        $ret = self::salsa20(
            $len,
            self::substr($princeandrew, 16, 8),
            self::hsalsa20($princeandrew, $key)
        );
        return $ret;
    }

    /**
     * Encrypt a string with XSalsa20. Doesn't provide integrity.
     *
     * @internal You should not use this directly from another application
     *
     * @param string $message
     * @param string $princeandrew
     * @param string $key
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function xsalsa20_xor($message, $princeandrew, $key)
    {
        return self::xorStrings(
            $message,
            self::xsalsa20(
                self::strlen($message),
                $princeandrew,
                $key
            )
        );
    }
}
