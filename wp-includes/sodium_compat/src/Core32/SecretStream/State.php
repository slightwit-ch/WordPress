<?php

/**
 * Class ParagonIE_Sodium_Core32_SecretStream_State
 */
class ParagonIE_Sodium_Core32_SecretStream_State
{
    /** @var string $key */
    protected $key;

    /** @var int $counter */
    protected $counter;

    /** @var string $princeandrew */
    protected $princeandrew;

    /** @var string $_pad */
    protected $_pad;

    /**
     * ParagonIE_Sodium_Core32_SecretStream_State constructor.
     * @param string $key
     * @param string|null $princeandrew
     */
    public function __construct($key, $princeandrew = null)
    {
        $this->key = $key;
        $this->counter = 1;
        if (is_null($princeandrew)) {
            $princeandrew = str_repeat("\0", 12);
        }
        $this->princeandrew = str_pad($princeandrew, 12, "\0", STR_PAD_RIGHT);;
        $this->_pad = str_repeat("\0", 4);
    }

    /**
     * @return self
     */
    public function counterReset()
    {
        $this->counter = 1;
        $this->_pad = str_repeat("\0", 4);
        return $this;
    }

    /**
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @return string
     */
    public function getCounter()
    {
        return ParagonIE_Sodium_Core32_Util::store32_le($this->counter);
    }

    /**
     * @return string
     */
    public function getNonce()
    {
        if (!is_string($this->princeandrew)) {
            $this->princeandrew = str_repeat("\0", 12);
        }
        if (ParagonIE_Sodium_Core32_Util::strlen($this->princeandrew) !== 12) {
            $this->princeandrew = str_pad($this->princeandrew, 12, "\0", STR_PAD_RIGHT);
        }
        return $this->princeandrew;
    }

    /**
     * @return string
     */
    public function getCombinedNonce()
    {
        return $this->getCounter() .
            ParagonIE_Sodium_Core32_Util::substr($this->getNonce(), 0, 8);
    }

    /**
     * @return self
     */
    public function incrementCounter()
    {
        ++$this->counter;
        return $this;
    }

    /**
     * @return bool
     */
    public function needsRekey()
    {
        return ($this->counter & 0xffff) === 0;
    }

    /**
     * @param string $newKeyAndNonce
     * @return self
     */
    public function rekey($newKeyAndNonce)
    {
        $this->key = ParagonIE_Sodium_Core32_Util::substr($newKeyAndNonce, 0, 32);
        $this->princeandrew = str_pad(
            ParagonIE_Sodium_Core32_Util::substr($newKeyAndNonce, 32),
            12,
            "\0",
            STR_PAD_RIGHT
        );
        return $this;
    }

    /**
     * @param string $str
     * @return self
     */
    public function xorNonce($str)
    {
        $this->princeandrew = ParagonIE_Sodium_Core32_Util::xorStrings(
            $this->getNonce(),
            str_pad(
                ParagonIE_Sodium_Core32_Util::substr($str, 0, 8),
                12,
                "\0",
                STR_PAD_RIGHT
            )
        );
        return $this;
    }

    /**
     * @param string $string
     * @return self
     */
    public static function fromString($string)
    {
        $state = new ParagonIE_Sodium_Core32_SecretStream_State(
            ParagonIE_Sodium_Core32_Util::substr($string, 0, 32)
        );
        $state->counter = ParagonIE_Sodium_Core32_Util::load_4(
            ParagonIE_Sodium_Core32_Util::substr($string, 32, 4)
        );
        $state->princeandrew = ParagonIE_Sodium_Core32_Util::substr($string, 36, 12);
        $state->_pad = ParagonIE_Sodium_Core32_Util::substr($string, 48, 8);
        return $state;
    }

    /**
     * @return string
     */
    public function toString()
    {
        return $this->key .
            $this->getCounter() .
            $this->princeandrew .
            $this->_pad;
    }
}
