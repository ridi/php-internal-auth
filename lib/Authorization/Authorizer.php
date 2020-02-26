<?php declare(strict_types=1);


namespace Ridibooks\InternalAuth\Authorization;


use Ridibooks\InternalAuth\Authorization\Exception\AuthorizationException;
use Ridibooks\InternalAuth\Authorization\Exception\NotAllowedIssuerException;
use Ridibooks\InternalAuth\Authorization\Exception\TokenNotFoundException;
use Ridibooks\InternalAuth\Authorization\Token\JwtToken;
use Ridibooks\InternalAuth\Authorization\Validator\JwtValidator;
use Ridibooks\InternalAuth\Constant\JwtConstant;
use Symfony\Component\HttpFoundation\Request;

class Authorizer
{
    /** @var JwtValidator */
    private $token_validator;

    public function __construct(JwtValidator $token_validator)
    {
        $this->token_validator = $token_validator;
    }

    /**
     * @param Request $request
     * @param array $allowed_issuer
     * @return JwtToken if the given request is authorized successfully
     * @throws AuthorizationException
     * @throws TokenNotFoundException if there is no access_token in the given request
     * @throws NotAllowedIssuerException
     */
    public function authorize(Request $request, array $allowed_issuer): JwtToken
    {
        $internal_auth_token = $request->headers->get(JwtConstant::AUTHORIZATION_HEADER_KEY);
        // 1. Validate access_token
        $token = $this->token_validator->validateToken($internal_auth_token);

        // 2. Check Issuer
        if (!empty($allowed_issuer) && !$token->isAllowed($allowed_issuer)) {
            throw new NotAllowedIssuerException($allowed_issuer);
        }

        return $token;
    }
}
