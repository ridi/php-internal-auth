<?php declare(strict_types=1);

namespace Ridibooks\Test\InternalAuth\Api;

use Mockery;
use Ridibooks\Test\InternalAuth\Common\KeyConstant;

class MockJwkApi
{
    static public function getMockJwkApiResponseBody(): array
    {
        return array(
            "key" => array(
                "kid" => KeyConstant::TEST_KEY_ID,
                "alg" => "RS256",
                "kty" => "RSA",
                "use" => "sig",
                "n" => "vPfvfjTJI-HJvJX1e5LtUjD2oRuxTXNd10KpX2wYQKK4jL88svHCYuDk6H_YDNMpPZufjcQ0qex-fa3Vw7YuUlKf6E-c8KgR-hIlqfI4z0R6OMaWWCU2THmFBkTnPAV2kvaWucM0mduaPWTsMO4QhKYDCmEEiV_KiLh7MIk0vxWjN5jUm7p89P_vdYYdCbGu2f9aDpGBZMA-qOEmnoJ1PD8L8fm24T7a793__MNid9Ua36tKE7UPIb0q3z05UAiwCTkOS9rvU9cxKl3kTxEYVRRccBJWfqASYjWcdINwS6GkSA2GB3-gxhzCPEQsbi8QykoZUH7GoUbAxsTDsZRtI_SS3SDw6Ub9ZJc7ZeEU6Ue4tus-AUZ73syMVDWQm5-kIHMMt2ytrFAAESAIpPy7vNM5PeQZfjPE8AlJ_vUBhJt17sbjYBfC_wtnRpUh_fbZykx-74trXeFuLMOWC7QnyQjSxPfMg1km7dUonkBnoJ7VpNITKLIcO3FpdiNc3I3-zUmLXQSWbaU9Yt8MSO9hN8S9OH2LsUfzOH4oFi6rc4R0ELtJdENlNgaU-UMOD1LqFK714nH3JCz2H6mlWWT_DUa0cklL1NvAxD7wkHwhZvYpN040qAC78qeKAg1y63RWIol1axEEjKYaeqz3QLyxS4g-aMriTs7W7DNZ1MWZIwU=",
                "e" => "AQAB",
            ),
        );
    }

    static public function setUp()
    {
        Mockery::mock('alias:Ridibooks\InternalAuth\Authorization\Api\JwkApi', [
            "requestPublicKey" => self::getMockJwkApiResponseBody(),
        ]);
    }

    static public function tearDown()
    {
        Mockery::close();
    }
}
