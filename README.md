# php-internal-auth

[![Build Status](https://travis-ci.org/ridi/php-internal-auth.svg?branch=master)](https://travis-ci.org/ridi/php-internal-auth)

## 소개
- 내부 서비스 간 통신시 인증을 위한 PHP 라이브러리입니다.
- Ridi 스타일 가이드([내부 서비스간의 SSO](https://github.com/ridi/style-guide/blob/master/API.md#%EB%82%B4%EB%B6%80-%EC%84%9C%EB%B9%84%EC%8A%A4%EA%B0%84%EC%9D%98-sso))에 따라 작성 되었습니다.
- JWK Caching 를 선택적으로 지원합니다. [psr-6](https://www.php-fig.org/psr/psr-6/)의 구현체를 JwtTokenValidator에 주입하면 캐싱 기능을 사용할 수 있습니다. 

## Requirements

- `PHP 7.2` or higher
- `php7.2-gmp` web-token decryption 모듈을 위해서는 php7.2-gmp 를 os 내에 설치해줘야 합니다. 
따라서 이 라이브러리 클라이언트들의 OS 혹은 도커 이미지 내에 꼭 설치해주시길 바랍니다. [참고 PR](https://github.com/ridibooks-docker/viewer-php/pull/1)


## Installation

```
composer require
```

## Usage

### `JwtGenerator`

```
use Ridibooks\InternalAuth\Authorization\Generator\JwtGenerator;

$key_config = [
    '... issuer service name  ...' => [
        'kid' => '... key id ...',
        'key' => '... rsa private key ...',
    ]
];

$jwt_generator = new JwtGenerator($key_config);
$token = $jwt_generator->generate(
    '... issuer service name  ...',
    '... audience service name ...'
)
```

### `Authorizer, JwtValidator Without Caching`

```
use Ridibooks\InternalAuth\Authorization\Validator\JwtValidator;
use Ridibooks\InternalAuth\Authorizer;

$internal_auth_token = '...';

try {
    $jwk_url = $this->configs['jwk_url'];
    $validator = new JwtValidator($jwk_url);

    $authorizer = new Authorizer($validator);
    $authorizer->authorize($internal_auth_token, [InterService.Account]);
} catch (AuthorizationException $e) {
	// handle exception
}
```

### `Authorizer, JwtValidator With Caching`

```php
use Ridibooks\InternalAuth\Authorization\Validator\JwtValidator;
use Ridibooks\InternalAuth\Authorizer;

$internal_auth_token = '...';

try {
    $jwk_url = $this->configs['jwk_url'];
    $cache_item_pool = new FilesystemAdapter(); // [psr-6](https://www.php-fig.org/psr/psr-6/) Implementation Adaptor
    $validator = new JwtValidator($jwk_url, $cache_item_pool);

    $authorizer = new Authorizer($validator);
    $authorizer->authorize($internal_auth_token, [InterService.Account]);
} catch (AuthorizationException $e) {
	// handle exception
}
```
