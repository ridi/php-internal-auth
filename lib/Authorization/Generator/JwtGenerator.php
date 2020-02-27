<?php


namespace Ridibooks\InternalAuth\Authorization\Generator;


use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Ridibooks\InternalAuth\Authorization\Exception\NotFoundIssuerException;
use Ridibooks\InternalAuth\Constant\JwtConstant;

class JwtGenerator
{
    /** @var CompactSerializer */
    private $serializer;

    /** @var AlgorithmManager */
    private $algorithm_manager;

    /** @var JWSBuilder */
    private $jws_builder;

    /** @var array */
    private $key_info;

    /**
     * JwtGenerator constructor.
     * @param array $key_info
     */
    public function __construct(array $key_info)
    {
        $this->serializer = new CompactSerializer();
        $this->algorithm_manager = new AlgorithmManager([
            new RS256(),
            new ES256(),
        ]);
        $this->jws_builder = new JWSBuilder($this->algorithm_manager);

        $this->loadKeyInfo($key_info);
    }

    /**
     * @param array $key_info
     */
    private function loadKeyInfo(array $key_info)
    {
        $this->key_info = [];
        foreach ($key_info as $service_name => $value) {
            $this->key_info[$service_name] = [
                'jwk' => JWKFactory::createFromKey($value['key'], null, ['use' => 'sig']),
                'kid' => $value['kid']
            ];
        }
    }

    /**
     * @param string $issuer
     * @param string $audience
     * @param int $expires_in
     * @return string
     * @throws NotFoundIssuerException
     */
    public function generate(
        string $issuer, string $audience, int $expires_in = JwtConstant::DEFAULT_JWT_EXPIRES_IN_SEC
    ): string
    {
        $payload = json_encode([
            'iss' => $issuer,
            'aud' => $audience,
            'exp' => time() + $expires_in
        ]);

        if (!isset($this->key_info[$issuer])) {
            throw new NotFoundIssuerException();
        }

        $kid = $this->key_info[$issuer]['kid'];
        $jwk = $this->key_info[$issuer]['jwk'];

        $jws = $this->jws_builder
            ->create()
            ->withPayload($payload)
            ->addSignature($jwk, ['typ' => 'JWT', 'kid' => $kid, 'alg' => 'RS256'])
            ->build();

        return $this->serializer->serialize($jws, 0);
    }
}
