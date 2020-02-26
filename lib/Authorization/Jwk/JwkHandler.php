<?php declare(strict_types=1);

namespace Ridibooks\InternalAuth\Authorization\Jwk;

use Ridibooks\InternalAuth\Authorization\Exception\AccountServerException;
use Ridibooks\InternalAuth\Authorization\Exception\ClientRequestException;
use Ridibooks\InternalAuth\Authorization\Exception\InvalidJwtException;
use Ridibooks\InternalAuth\Authorization\Exception\InvalidPublicKeyException;
use Ridibooks\InternalAuth\Authorization\Exception\NotExistedKeyException;
use Ridibooks\InternalAuth\Constant\JwkConstant;
use Jose\Component\Core\JWK;
use Ridibooks\InternalAuth\Authorization\Api\JwkApi;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\CacheException;

class JwkHandler
{
    /** @var CacheItemPoolInterface */
    private $cache_item_pool;

    /** @var string */
    private $jwk_url;

    /**
     * @param string $jwk_url
     * @param CacheItemPoolInterface|null $cache_item_pool
     * @return void
     */
    public function __construct(string $jwk_url, ?CacheItemPoolInterface $cache_item_pool = null)
    {
        $this->jwk_url = $jwk_url;
        $this->cache_item_pool = $cache_item_pool;
    }

    /**
     * @param string $service_name
     * @param string $kid
     * @return JWK
     * @throws InvalidJwtException
     * @throws NotExistedKeyException
     * @throws InvalidPublicKeyException
     * @throws AccountServerException
     * @throws ClientRequestException
     * @throws CacheException
     */
    public function getJwk(
        string $service_name,
        string $kid
    ): JWK
    {
        $jwk = !is_null($this->cache_item_pool) ? $this->getJwkFromCachePool($service_name, $kid) : null;
        if (is_null($jwk)) {
            $jwk = $this->getJwkFromApiAndMemorizeJwks($service_name, $kid);
        }

        $this->assertValidKey($jwk);

        return $jwk;
    }

    /**
     * @param string $service_name
     * @param string $kid
     * @return JWK|null
     * @throws InvalidJwtException
     * @throws CacheException
     */
    protected function getJwkFromCachePool(string $service_name, string $kid): ?JWK
    {
        $cache_key = $this->makeCacheKey($service_name, $kid);
        $cached_jwk = $this->cache_item_pool->getItem($cache_key);
        return $this->toJwk($cached_jwk->get());
    }

    /**
     * @param JWK $jwk
     * @return void
     * @throws NotExistedKeyException
     * @throws InvalidPublicKeyException
     */
    protected function assertValidKey(
        JWK $jwk
    ): void
    {
        if (!$jwk) {
            throw new NotExistedKeyException();
        }
        if ($jwk->get('use') != JwkConstant::SIG) {
            throw new InvalidPublicKeyException();
        }
    }

    /**
     * @param string $service_name
     * @param string $kid
     * @return JWK
     * @throws AccountServerException
     * @throws ClientRequestException
     * @throws InvalidJwtException
     * @throws CacheException
     */
    protected function getJwkFromApiAndMemorizeJwks(
        string $service_name,
        string $kid
    ): JWK
    {
        $jwk = $this->getJwkArrayFromJwkApi($service_name, $kid);
        $this->setJwkToCachePool($service_name, $kid, $jwk);
        return $this->toJwk($jwk);
    }

    /**
     * @param string $service_name
     * @param string $kid
     * @return array
     * @throws AccountServerException
     * @throws ClientRequestException
     */
    protected function getJwkArrayFromJwkApi(
        string $service_name,
        string $kid
    ): array
    {
        return JwkApi::requestPublicKey($this->jwk_url, $service_name, $kid)[JwkConstant::RESPONSE_KEY];
    }

    /**
     * @param string $service_name
     * @param string $kid
     * @param array $jwk
     * @return void
     * @throws CacheException
     */
    protected function setJwkToCachePool(
        string $service_name,
        string $kid,
        array $jwk
    ): void
    {
        if (empty($this->cache_item_pool)) {
            return;
        }

        $cache_key = $this->makeCacheKey($service_name, $kid);

        $cache_item = $this->cache_item_pool->getItem($cache_key);
        $cache_item->set($jwk);
        $cache_item->expiresAfter(JwkConstant::JWK_EXPIRATION_SEC);
        $this->cache_item_pool->save($cache_item);
    }

    protected function makeCacheKey(string $service_name, string $kid): string
    {
        return $service_name . ':' . $kid;
    }

    /**
     * @param array|null $jwk
     * @return JWK|null
     */
    protected function toJwk(
        ?array $jwk
    ): ?JWK
    {
        if (is_null($jwk)) {
            return null;
        }

        return JWK::createFromJson(json_encode($jwk));
    }
}
