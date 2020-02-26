<?php


namespace Ridibooks\Test\InternalAuth\Authorization;


use PHPUnit\Framework\TestCase;
use Ridibooks\InternalAuth\Authorization\Generator\JwtGenerator;
use Ridibooks\InternalAuth\Authorization\Validator\JwtValidator;
use Ridibooks\Test\InternalAuth\Api\MockJwkApi;
use Ridibooks\Test\InternalAuth\Common\TokenConstant;

class JwtGeneratorTest extends TestCase
{
    /** @var JwtGenerator */
    private $jwt_generator;

    /** @var JwtValidator */
    private $jwt_validator;

    private $test_issuer = 'test-service';
    private $test_audience = 'test-audience';

    private $jwk_url = 'https://account-cdn.dev.ridi.io/internal-auth';

    protected function setUp()
    {
        $this->jwt_generator = new JwtGenerator([
            $this->test_issuer => [
                'kid' => TokenConstant::TEST_KEY_ID,
                'key' => file_get_contents(TokenConstant::KEY_FILE),
            ]
        ]);

        $this->jwt_validator = new JwtValidator($this->jwk_url);
        MockJwkApi::setUp();
    }

    protected function tearDown()
    {
        MockJwkApi::tearDown();
    }


    function testGenerateJwt()
    {
        $token = $this->jwt_generator->generate($this->test_issuer, $this->test_audience);
        $validated_token = $this->jwt_validator->validateToken($token);

        $this->assertEquals($this->test_issuer, $validated_token->getIssuer());
        $this->assertEquals($this->test_audience, $validated_token->getAudience());
        $this->assertEquals(TokenConstant::TEST_KEY_ID, $validated_token->getKeyId());
    }
}
