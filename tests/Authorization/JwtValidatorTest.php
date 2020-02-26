<?php
declare(strict_types=1);

namespace Ridibooks\Test\InternalAuth\Authorization;

use PHPUnit\Framework\TestCase;
use Ridibooks\InternalAuth\Authorization\Exception\ExpiredTokenException;
use Ridibooks\InternalAuth\Authorization\Exception\InvalidJwtException;
use Ridibooks\InternalAuth\Authorization\Exception\TokenNotFoundException;
use Ridibooks\InternalAuth\Authorization\Token\JwtToken;
use Ridibooks\InternalAuth\Authorization\Validator\JwtValidator;
use Ridibooks\Test\OAuth2\Common\TokenConstant;
use Ridibooks\Test\OAuth2\Api\MockJwkApi;

final class JwtValidatorTest extends TestCase
{
    private $jwk_url = 'https://account-cdn.dev.ridi.io/internal-auth';

    protected function setUp()
    {
        MockJwkApi::setUp();
    }

    protected function tearDown()
    {
        MockJwkApi::tearDown();
    }

    private function validate($access_token)
    {
        $jwtTokenValidator = new JwtValidator($this->jwk_url);
        return $jwtTokenValidator->validateToken($access_token);
    }

    private function validateWithKid($access_token)
    {
        $jwtTokenValidator = new JwtValidator($this->jwk_url);
        return $jwtTokenValidator->validateToken($access_token);
    }

    public function testCanIntrospect()
    {
        $access_token = TokenConstant::TOKEN_VALID;
        $token = $this->validate($access_token);

        $this->assertNotNull($token);
        $this->assertInstanceOf(JwtToken::class, $token);
    }

    public function testIntrospectExpiredToken()
    {
        $this->expectException(ExpiredTokenException::class);

        $access_token = TokenConstant::TOKEN_EXPIRED;
        $this->validate($access_token);
    }

    public function testCannotIntrospectWrongFormatToken()
    {
        $this->expectException(InvalidJwtException::class);

        $access_token = TokenConstant::TOKEN_INVALID_PAYLOAD;
        $this->validate($access_token);
    }

    public function testCannotIntrospectInvalidSignToken()
    {
        $this->expectException(InvalidJwtException::class);

        $access_token = TokenConstant::TOKEN_INVALID_SIGNATURE;
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

        $access_token = TokenConstant::TOKEN_EMPTY;
        $this->validate($access_token);
    }

    public function testCanIntrospectWithES256Token()
    {
        $access_token = TokenConstant::ES256_TOKEN_VALID;
        $token = $this->validateWithKid($access_token);

        $this->assertNotNull($token);
        $this->assertInstanceOf(JwtToken::class, $token);
    }

    public function testCanIntrospectWithES256TokenEmptyKid()
    {
        $this->expectException(InvalidJwtException::class);

        $access_token = TokenConstant::ES256_TOKEN_WITHOUT_KID;
        $token = $this->validateWithKid($access_token);

        $this->assertNotNull($token);
        $this->assertInstanceOf(JwtToken::class, $token);
    }

    public function testCannotIntrospectWithES256TokenInvalidKid()
    {
        $this->expectException(InvalidJwtException::class);
        $access_token = TokenConstant::ES256_TOKEN_INVALID_KID;
        $this->validateWithKid($access_token);
    }
}
