<?php

namespace Frengky\PassportIntrospect;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Routing\Controller as BaseController;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\LocalFileReference;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;

class PassportIntrospectController extends BaseController
{
	/**
	 * @var \Laravel\Passport\Bridge\AccessTokenRepository
	 */
	private $accessTokenRepository;

	/**
	 * @var \Laravel\Passport\ClientRepository
	 */
	private $clientRepository;

    public function __construct(AccessTokenRepository $accessTokenRepository, ClientRepository $clientRepository)
    {
		$this->accessTokenRepository = $accessTokenRepository;
		$this->clientRepository = $clientRepository;
    }

    public function introspect(Request $request)
    {
		$tokenStr = $request->input('token');
		$tokenTypeHint = $request->input('token_type_hint'); // https://tools.ietf.org/html/rfc7662#section-2.1

		if (! empty($tokenTypeHint) && $tokenTypeHint !== 'access_token') {
			return response()->json(['active' => false]);
		}

		try {
			/**
			 * @var \Lcobucci\JWT\UnencryptedToken
			 */
			$token = Configuration::forUnsecuredSigner()->parser()->parse($tokenStr);
			$this->verifyToken($token);

		} catch(\Exception $e) {
			Log::warning(sprintf('OAuth2 introspect: %s', $e->getMessage()));
			return response()->json(['active' => false]);
		}

		$claims = $token->claims();

		$exp = $claims->get('exp');
		$iat = $claims->get('iat');
		$nbf = $claims->get('nbf');
		// $sub = $claims->get('sub');
		$aud = $claims->get('aud');
		$iss = $claims->get('iss');
		$jti = $claims->get('jti');
		$scopes = $claims->get('scopes');

		if ($this->accessTokenRepository->isAccessTokenRevoked($jti)) {
			return response()->json(['active' => false]);
		}

		if ($this->clientRepository->revoked($aud)) {
			return response()->json(['active' => false]);
		}

		$scopeStr = $request->input('scope');
		if (! empty($scopeStr)) {
			$requiredScopes = explode(' ', trim($scopeStr));
			foreach($requiredScopes as $scope) {
				if (! in_array($scope, $scopes)) {
					return response()->json(['active' => false]);
				}
			}
		}

		$tokenRepositoryClass = \Laravel\Passport\TokenRepository::class;
		$accessToken = (new $tokenRepositoryClass)->find($jti);

		/*
		if (! empty($accessToken->user_id)) {
			$userModel = config('auth.providers.users.model');
			$user = (new $userModel)->findOrFail($accessToken->user_id);
		}*/

		$sub = empty($accessToken->user_id) ? $accessToken->client_id : $accessToken->user_id;
		$data = [
			'active' => true,
			'scope' => trim(implode(' ', $scopes)),
			'client_id' => (string) $accessToken->client_id,
			'sub' => (string) $sub,
			'exp' => (int) $exp->format('U'),
			'iat' => (int) $iat->format('U'),
			'nbf' => (int) $nbf->format('U'),
			'aud' => $aud, // array
			'iss' => (string) $iss,
			'token_type' => 'Bearer',
			'token_use' => 'access_token',
			'jti' => $jti,
        ];

        return response()->json($data);
    }

	/**
	 * Verify token
	 *
	 * @throws \Lcobucci\JWT\Validation\ConstraintViolation
	 */
    private function verifyToken(Token $token) : bool
    {
		$signer = new Sha256();
		$key = LocalFileReference::file(Passport::keyPath('oauth-public.key'));

		$signedWith = new SignedWith($signer, $key);
		$signedWith->assert($token);

		$clock = new SystemClock(new \DateTimeZone(config('app.timezone')));
		$strictValidAt = new StrictValidAt($clock);
		$strictValidAt->assert($token);

		return true;
    }
}
