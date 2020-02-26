<?php declare(strict_types=1);

namespace Ridibooks\Test\InternalAuth\Common;

class KeyConstant
{
    const KEY_FILE = __DIR__ . '/../resources/jwt.key';
    const PUB_KEY_FILE = __DIR__ . '/../resources/jwt.key.pub';

    const JWK_URL = 'https://account-cdn.dev.ridi.io/internal-auth';
    const TEST_KEY_ID = '606b157aec714959922ee8496e61b23d';
    const TEST_ISSUER = 'test-service';
    const TEST_AUDIENCE = 'test-audience';
}
