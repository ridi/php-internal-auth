<?php declare(strict_types=1);

namespace Ridibooks\InternalAuth\Authorization\Validator;

use Psr\Cache\CacheException;
use Ridibooks\InternalAuth\Authorization\Exception\AccountServerException;
use Ridibooks\InternalAuth\Authorization\Exception\AuthorizationException;
use Ridibooks\InternalAuth\Authorization\Exception\ClientRequestException;
use Ridibooks\InternalAuth\Authorization\Exception\ExpiredTokenException;
use Ridibooks\InternalAuth\Authorization\Exception\InvalidJwtException;
use Ridibooks\InternalAuth\Authorization\Exception\InvalidJwtSignatureException;
use Ridibooks\InternalAuth\Authorization\Exception\InvalidPublicKeyException;
use Ridibooks\InternalAuth\Authorization\Exception\NotExistedKeyException;
use Ridibooks\InternalAuth\Authorization\Exception\TokenNotFoundException;
use Ridibooks\InternalAuth\Authorization\Token\JwtToken;
use Ridibooks\InternalAuth\Authorization\Jwk\JwkHandler;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWS;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Checker;
use InvalidArgumentException;
use Psr\Cache\CacheItemPoolInterface;

const SIGNATURE_INDEX = 0;

class JwtValidator
{
    /** @var JwkHandler */
    private $jwk_handler;

    /** @var JWSSerializerManager */
    private $serializer_manager;

    /** @var HeaderCheckerManager */
    private $header_checker_manager;

    /** @var ClaimCheckerManager */
    private $claim_checker_manager;

    /** @var AlgorithmManager */
    private $algorithm_manager;

    /** @var JWSVerifier */
    private $jws_verifier;

    /**
     * @param string $jwk_url
     * @param CacheItemPoolInterface|null $cache_item_pool
     * @return void
     */
    public function __construct(string $jwk_url, ?CacheItemPoolInterface $cache_item_pool = null)
    {
        $this->jwk_handler = new JwkHandler($jwk_url, $cache_item_pool);
        $this->serializer_manager = new JWSSerializerManager([
            new CompactSerializer(),
        ]);
        $this->header_checker_manager = new Checker\HeaderCheckerManager(
            [
                new Checker\AlgorithmChecker(['RS256', 'ES256']),
            ],
            [
                new JWSTokenSupport(),
            ]
        );
        $this->claim_checker_manager = new Checker\ClaimCheckerManager(
            [
                new Checker\ExpirationTimeChecker(),
            ]
        );
        $this->algorithm_manager = new AlgorithmManager([
            new RS256(),
            new ES256(),
        ]);
        $this->jws_verifier = new JWSVerifier(
            $this->algorithm_manager
        );
    }

    /**
     * @param string $internal_auth_token
     * @return JWS
     * @throws InvalidJwtException
     */
    public function getJws(string $internal_auth_token): JWS
    {
        try {
            return $this->serializer_manager->unserialize($internal_auth_token);
        } catch (InvalidArgumentException $e) {
            throw new InvalidJwtException($e->getMessage());
        }
    }

    /**
     * @param JWS $jws
     * @return array
     * @throws InvalidJwtException
     */
    public function checkAndGetHeader(JWS $jws): array
    {
        try {
            $this->header_checker_manager->check($jws, SIGNATURE_INDEX, ['alg', 'typ', 'kid']);
        } catch (Checker\MissingMandatoryHeaderParameterException $e) {
            throw new InvalidJwtException($e->getMessage());
        }

        return $jws->getSignature(SIGNATURE_INDEX)->getProtectedHeader();
    }

    /**
     * @param JWS $jws
     * @return array
     * @throws ExpiredTokenException
     * @throws InvalidJwtException
     */
    public function checkAndGetClaims(JWS $jws): array
    {
        $claims = json_decode($jws->getPayload(), true);
        try {
            $this->claim_checker_manager->check($claims, ['iss', 'aud', 'exp']);
        } catch (Checker\InvalidClaimException $e) {
            throw new ExpiredTokenException($e->getMessage());
        } catch (Checker\MissingMandatoryClaimException $e) {
            throw new InvalidJwtException($e->getMessage());
        }

        return $claims;
    }

    /**
     * @param JWS $jws
     * @param JWK $jwk
     * @return void
     * @throws InvalidJwtException
     * @throws InvalidJwtSignatureException
     */
    private function verifyJwsWithJwk(JWS $jws, JWK $jwk): void
    {
        try {
            $isVerified = $this->jws_verifier->verifyWithKey($jws, $jwk, SIGNATURE_INDEX);
        } catch (InvalidArgumentException $e) {
            throw new InvalidJwtException($e->getMessage());
        }

        if (!$isVerified) {
            throw new InvalidJwtSignatureException();
        }
    }

    /**
     * @param string|null $internal_auth_token
     * @return JwtToken
     * @throws AuthorizationException
     * @throws TokenNotFoundException
     * @throws InvalidJwtException
     * @throws NotExistedKeyException
     * @throws InvalidPublicKeyException
     * @throws AccountServerException
     * @throws ClientRequestException
     * @throws CacheException
     */
    public function validateToken($internal_auth_token): JwtToken
    {
        if (!isset($internal_auth_token)) {
            throw new TokenNotFoundException();
        }

        $jws = $this->getJws($internal_auth_token);

        $header = $this->checkAndGetHeader($jws);
        $claims = $this->checkAndGetClaims($jws);

        $jwk = $this->jwk_handler->getJwk($claims['iss'], $header['kid']);
        $this->verifyJwsWithJwk($jws, $jwk);

        return JwtToken::createFrom($header, $claims);
    }
}
