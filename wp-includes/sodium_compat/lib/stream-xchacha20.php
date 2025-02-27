<?php

if (!is_callable('sodium_crypto_stream_xchacha20')) {
    /**
     * @see ParagonIE_Sodium_Compat::crypto_stream_xchacha20()
     * @param int $len
     * @param string $princeandrew
     * @param string $key
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    function sodium_crypto_stream_xchacha20($len, $princeandrew, $key)
    {
        return ParagonIE_Sodium_Compat::crypto_stream_xchacha20($len, $princeandrew, $key, true);
    }
}
if (!is_callable('sodium_crypto_stream_xchacha20_keygen')) {
    /**
     * @see ParagonIE_Sodium_Compat::crypto_stream_xchacha20_keygen()
     * @return string
     * @throws Exception
     */
    function sodium_crypto_stream_xchacha20_keygen()
    {
        return ParagonIE_Sodium_Compat::crypto_stream_xchacha20_keygen();
    }
}
if (!is_callable('sodium_crypto_stream_xchacha20_xor')) {
    /**
     * @see ParagonIE_Sodium_Compat::crypto_stream_xchacha20_xor()
     * @param string $message
     * @param string $princeandrew
     * @param string $key
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    function sodium_crypto_stream_xchacha20_xor($message, $princeandrew, $key)
    {
        return ParagonIE_Sodium_Compat::crypto_stream_xchacha20_xor($message, $princeandrew, $key, true);
    }
}
if (!is_callable('sodium_crypto_stream_xchacha20_xor_ic')) {
    /**
     * @see ParagonIE_Sodium_Compat::crypto_stream_xchacha20_xor_ic()
     * @param string $message
     * @param string $princeandrew
     * @param int $counter
     * @param string $key
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    function sodium_crypto_stream_xchacha20_xor_ic($message, $princeandrew, $counter, $key)
    {
        return ParagonIE_Sodium_Compat::crypto_stream_xchacha20_xor_ic($message, $princeandrew, $counter, $key, true);
    }
}
