<?php declare(strict_types=1);

namespace Ridibooks\InternalAuth\Authorization\Api;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Response;
use Ridibooks\InternalAuth\Authorization\Exception\AccountServerException;
use Ridibooks\InternalAuth\Authorization\Exception\ClientRequestException;

class JwkApi
{
    /**
     * @param string $jwk_url
     * @param string $service_name
     * @param string $kid
     * @return array
     * @throws AccountServerException
     * @throws ClientRequestException
     */
    public static function requestPublicKey(
        string $jwk_url,
        string $service_name,
        string $kid
    ): array
    {
        $client = new Client();
        $response = $client->request('GET', $jwk_url . self::makePath($service_name, $kid));
        return self::processResponse($response);
    }

    /**
     * @param string $service_name
     * @param string $kid
     * @return string
     */
    private static function makePath(string $service_name, string $kid): string
    {
        return "/$service_name/$kid";
    }

    /**
     * @param Response $response
     * @return array
     * @throws AccountServerException
     * @throws ClientRequestException
     */
    public static function processResponse(
        Response $response
    ): array
    {
        if ($response->getStatusCode() >= 500) {
            throw new AccountServerException();
        } else if ($response->getStatusCode() >= 400) {
            throw new ClientRequestException();
        }

        $json_decode = json_decode($response->getBody()->getContents(), true);
        return $json_decode;
    }
}
