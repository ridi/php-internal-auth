<?php


namespace Ridibooks\Test\InternalAuth\Authorization;


use PHPUnit\Framework\TestCase;
use Ridibooks\InternalAuth\Authorization\Generator\JwtGenerator;
use Ridibooks\Test\InternalAuth\Common\TokenConstant;

class JwtGeneratorTest extends TestCase
{
    /** @var JwtGenerator */
    private $jwt_generator;

    private $test_issuer = 'test-service';

    protected function setUp()
    {
        $this->jwt_generator = new JwtGenerator([
            $this->test_issuer => [
                'kid' => 'test-key-id',
                'key' => file_get_contents(TokenConstant::KEY_FILE),
            ]
        ]);
    }

    function testGenerateJwt()
    {
        $token = $this->jwt_generator->generate($this->test_issuer, 'test-audience');
        echo $token;
    }
}
