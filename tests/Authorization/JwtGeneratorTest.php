<?php


namespace Ridibooks\Test\InternalAuth\Authorization;


use PHPUnit\Framework\TestCase;
use Ridibooks\InternalAuth\Authorization\Generator\JwtGenerator;
use Ridibooks\InternalAuth\Authorization\Validator\JwtValidator;
use Ridibooks\Test\InternalAuth\Api\MockJwkApi;
use Ridibooks\Test\InternalAuth\Common\KeyConstant;

class JwtGeneratorTest extends TestCase
{
    /** @var JwtGenerator */
    private $jwt_generator;

    /** @var JwtValidator */
    private $jwt_validator;

    protected function setUp()
    {
        $this->jwt_generator = new JwtGenerator([
            $this->test_issuer => [
                'kid' => KeyConstant::TEST_KEY_ID,
                'key' => file_get_contents(KeyConstant::KEY_FILE),
            ]
        ]);

        $this->jwt_validator = new JwtValidator(KeyConstant::JWK_URL);
        MockJwkApi::setUp();
    }

    protected function tearDown()
    {
        MockJwkApi::tearDown();
    }


    function testGenerateJwt()
    {
        $token = $this->jwt_generator->generate(KeyConstant::TEST_ISSUER, KeyConstant::TEST_AUDIENCE);
        $validated_token = $this->jwt_validator->validateToken($token);

        $this->assertEquals(KeyConstant::TEST_ISSUER, $validated_token->getIssuer());
        $this->assertEquals(KeyConstant::TEST_AUDIENCE, $validated_token->getAudience());
        $this->assertEquals(KeyConstant::TEST_KEY_ID, $validated_token->getKeyId());
    }
}
