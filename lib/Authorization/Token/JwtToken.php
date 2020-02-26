<?php declare(strict_types=1);

namespace Ridibooks\InternalAuth\Authorization\Token;

use Ridibooks\InternalAuth\Authorization\Exception\InvalidTokenException;
use Ridibooks\InternalAuth\Authorization\Validator\ScopeChecker;
use Ridibooks\InternalAuth\Constant\ScopeConstant;

class JwtToken
{
    /**
     * @var int
     */
    protected $expire_timestamp;
    /**
     * @var \DateTime
     */
    protected $expire_date;
    /**
     * @var string
     */
    protected $issuer;
    /**
     * @var string
     */
    protected $audience;

    /**
     * BaseTokenInfo constructor.
     *
     * @param string $issuer
     * @param string $audience
     * @param int $expire_timestamp
     */
    protected function __construct(
        string $issuer,
        string $audience,
        int $expire_timestamp
    )
    {
        $this->issuer = $issuer;
        $this->audience = $audience;

        $this->expire_timestamp = $expire_timestamp;
        $this->expire_date = (new \DateTime())->setTimestamp($expire_timestamp);
    }

    /**
     * @param array $token
     * @return JwtToken
     * @throws InvalidTokenException
     */
    public static function createFrom(array $token): JwtToken
    {
        if (!isset($token['iss'], $token['aud'], $token['exp'])) {
            throw new InvalidTokenException();
        }
        return new self(
            $token['iss'],
            $token['aud'],
            $token['exp']
        );
    }

    /**
     * @return int
     */
    public function getExpireTimestamp(): int
    {
        return $this->expire_timestamp;
    }

    /**
     * @return \DateTime
     */
    public function getExpireDate(): \DateTime
    {
        return $this->expire_date;
    }

    public function getIssuer(): string
    {
        return $this->issuer;
    }

    public function getAudience(): string
    {
        return $this->audience;
    }

    public function isAllowed(array $issuers): bool
    {
        return in_array($this->getIssuer(), $issuers);
    }
}
