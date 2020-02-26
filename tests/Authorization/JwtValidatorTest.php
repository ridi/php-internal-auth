<?php
declare(strict_types=1);

namespace Ridibooks\Test\InternalAuth\Authorization;

use PHPUnit\Framework\TestCase;
use Ridibooks\InternalAuth\Authorization\Exception\ExpiredTokenException;
use Ridibooks\InternalAuth\Authorization\Exception\InvalidJwtException;
use Ridibooks\InternalAuth\Authorization\Exception\TokenNotFoundException;
use Ridibooks\InternalAuth\Authorization\Token\JwtToken;
use Ridibooks\InternalAuth\Authorization\Validator\JwtValidator;
use Ridibooks\Test\InternalAuth\Api\MockJwkApi;
use Ridibooks\Test\InternalAuth\Common\KeyConstant;
use Ridibooks\Test\InternalAuth\Common\TokenConstant;

final class JwtValidatorTest extends TestCase
{

    /** @var JwtValidator */
    private $jwt_validator;

    protected function setUp()
    {
        $this->jwt_validator = new JwtValidator(KeyConstant::JWK_URL);
        MockJwkApi::setUp();
    }

    protected function tearDown()
    {
        MockJwkApi::tearDown();
    }

    private function validate($access_token)
    {
        return $this->jwt_validator->validateToken($access_token);
    }

    private function validateWithKid($access_token)
    {
        return $this->jwt_validator->validateToken($access_token);
    }

    public function testCanIntrospect()
    {
        $access_token = TokenConstant::VALID;
        $token = $this->validate($access_token);

        $this->assertNotNull($token);
        $this->assertInstanceOf(JwtToken::class, $token);
    }

    public function testIntrospectExpiredToken()
    {
        $this->expectException(ExpiredTokenException::class);

        $access_token = TokenConstant::EXPIRED;
        $this->validate($access_token);
    }

    public function testCannotIntrospectWrongFormatToken()
    {
        $this->expectException(InvalidJwtException::class);

        $access_token = TokenConstant::INVALID_PAYLOAD;
        $this->validate($access_token);
    }

    public function testCannotIntrospectInvalidSignToken()
    {
        $this->expectException(InvalidJwtException::class);

        $access_token = TokenConstant::INVALID_SIGNATURE;
        $this->validate($access_token);
    }

    public function testCannotIntrospectNullToken()
    {
        $this->expectException(TokenNotFoundException::class);
        $this->validate(null);
    }

    public function testCannotIntrospectEmptyToken()
    {
        $this->expectException(InvalidJwtException::class);

        $access_token = TokenConstant::EMPTY;
        $this->validate($access_token);
    }
}
