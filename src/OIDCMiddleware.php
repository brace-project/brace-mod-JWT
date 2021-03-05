<?php

namespace Brace\OpenIDConnect;

use Brace\Core\Base\BraceAbstractMiddleware;
use Brace\Session\Session;
use Brace\Session\SessionMiddleware;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Phore\Core\Exception\InvalidDataException;
use Phore\Di\Container\Producer\DiService;
use Phore\HttpClient\Ex\PhoreHttpRequestException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class OIDCMiddleware extends BraceAbstractMiddleware
{
    public const ID_TOKEN_ATTRIBUTE = 'id_token';
    public const ACCESS_TOKEN_ATTRIBUTE = 'access_token';
    private string $idToken;
    private string $accessToken;

    public function __construct(
        private OIDClient $client,
        private string $openIDHost,
    ) {
    }

    //Todo: DOKUMENTATION !!! wenn Session benutzt wird dann muss es nach dieser Definiert werden

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        /* @var $session Session */
        $session = $this->app->get(SessionMiddleware::SESSION_ATTRIBUTE);

        if (!$this->isAuthenticated($request, $session)) {
            try {
                return $this->authenticate($request, $session);
            } catch (\Exception $e) {
                return $this->app->responseFactory->createResponseWithBody("401 Access denied ({$e->getMessage()})", 401);
            }
        }

        $this->app->define(
            self::ID_TOKEN_ATTRIBUTE,
            new DiService(
                function () {
                    return JWT::jsonDecode(
                        $this->idToken
                    );
                }
            )
        );

        try {
            if (!$this->isAuthorized($request)) {
                return $this->app->responseFactory->createResponseWithBody("401 Access denied", 401);
            }
        } catch (\Exception $e) {
            return $this->app->responseFactory->createResponseWithBody("401 Access denied ({$e->getMessage()})", 401);
        }

        $this->app->define(
            self::ACCESS_TOKEN_ATTRIBUTE,
            new DiService(
                function () {
                    return JWT::jsonDecode(
                        $this->accessToken
                    );
                }
            )
        );

        return $handler->handle($request);
    }

    /**
     * @param ServerRequestInterface $request
     * @param Session $session
     * @return bool
     */
    private function isAuthenticated(ServerRequestInterface $request, Session $session): bool
    {
        //Todo: steps
        // -> https://docs.microsoft.com/de-de/azure/active-directory/develop/id-tokens#validating-an-id_token
        $queryParams = $request->getQueryParams();

        //Fehlerantwort von Umleitungs-URI
        if (array_key_exists('error', $queryParams)) {
            $errorDescription = array_key_exists(
                'error_description',
                $queryParams
            ) ? 'Description: ' . $queryParams['error_description'] : '';
            throw new \InvalidArgumentException('Error: ' . $queryParams['error'] . $errorDescription); //Todo: Response 401 Unauthorized?
        }

        //überprüfen ob Token vorhanden und state
        if (!array_key_exists('id_token', $queryParams) ||
            !array_key_exists('state', $queryParams)) {
            return false;
        }

        //verify Token
        $idToken = $queryParams['id_token'];
        $jwk = $this->client->getJWK();
        $idTokenPayload = JWT::decode(
            $idToken,
            JWK::parseKeySet($jwk)
        );
        //Todo: $supportedAlgos -> welche value aus wellknown config
        //Todo: müssen weiter Ansprüche überprüft werden ?
        // -> User/Organization logged in for this App
        // -> Autorisierung und Berechtigung ?

        //state überprüfen
        $queryState = $queryParams['state'];
        $sessionState = $session->get('state');
        if ($queryState !== $sessionState) {
            return false;
        }

        //Nonce aus Session mit dem in Token vergleichen
        $sessionNonce = $session->get('nonce');
        if ($idTokenPayload['nonce'] !== $sessionNonce) {
            return false;
        }

        $this->idToken = $idToken;
        //Token is valid und user Autheticated
        return true;
    }

    /**
     * @param ServerRequestInterface $request
     * @return bool
     * @throws InvalidDataException
     * @throws PhoreHttpRequestException
     */
    private function isAuthorized(ServerRequestInterface $request): bool
    {
        //Todo: steps:
        // ->https://docs.microsoft.com/de-de/azure/active-directory/develop/v2-oauth2-auth-code-flow#request-an-access-token

        $queryParams = $request->getQueryParams();
        $queryParams['code'];
        if($queryParams['code']){
            //Todo: entweder Fehler oder code Anfordern mit Redirect ?!
        }

        $tokenEndpoint = $this->client->getConfig[OIDClient::TOKEN_ENDPOINT] ?? null;
        if ($tokenEndpoint === null) {
            throw new InvalidDataException('TokenEndpoint isnt set');
        }

        $tokenEndpointResponse = phore_http_request($this->openIDHost . $tokenEndpoint)
            ->withQueryParams(
                [
                    "client_id" => "",
                    "scope" => "" , // Todo: optional
                    "code" => "",
                    "redirect_uri" => "", // Todo: ???
                    "grant_type" => "authorization_code",
                    "code_verifier" => "isRandomButNeedstobe43CharactersLong",
                    "client_secret" => ""
                ]
            )
            ->send()
            ->getBodyJson();
        /** Success response
        {
        "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5HVEZ2ZEstZnl0aEV1Q...",
        "token_type": "Bearer",
        "expires_in": 3599,
        "scope": "https%3A%2F%2Fgraph.microsoft.com%2Fmail.read",
        "refresh_token": "AwABAAAAvPM1KaPlrEqdFSBzjqfTGAMxZGUTdM0t4B4...",
        "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiIyZDRkMTFhMi1mODE0LTQ2YTctOD...",
        }
         */

        /** Error Response
         {
        "error": "invalid_scope",
        "error_description": "AADSTS70011: The provided value for the input parameter 'scope' is not valid. The scope https://foo.microsoft.com/mail.read is not valid.\r\nTrace ID: 255d1aef-8c98-452f-ac51-23d051240864\r\nCorrelation ID: fb3d2015-bc17-4bb9-bb85-30c5cf1aaaa7\r\nTimestamp: 2016-01-09 02:02:12Z",
        "error_codes": [
        70011
        ],
        "timestamp": "2016-01-09 02:02:12Z",
        "trace_id": "255d1aef-8c98-452f-ac51-23d051240864",
        "correlation_id": "fb3d2015-bc17-4bb9-bb85-30c5cf1aaaa7"
        }
         */

        //Todo: Token validieren und if($token is nicht gültig und nutzer hat  keine authorization)
        // -> oder macht das jede Route für sich nochmal ?
        // -> mit dem Token fragt Webserver -> WebAPI
        $this->accessToken = $tokenEndpointResponse['access_token'];
        $jwk = $this->client->getJWK();
        $accessTokenPayload = JWT::decode(
            $this->accessToken,
            JWK::parseKeySet($jwk)
        );
        $expiresIn = $queryParams['expires_in'];
        $tokentype = $queryParams['token_type'];

        //isAuthorized
        return true;
    }

    /**
     *
     *
     * @param Session $session
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     * @throws InvalidDataException
     */
    private function authenticate(ServerRequestInterface $request, Session $session): ResponseInterface
    {
        $state = phore_random_str();
        $nonce = phore_random_str();
        $session->set('state', $state);
        $session->set('nonce', $nonce);
        $endpoint = $this->client->getConfig()[OIDClient::AUHTORIZATION_ENDPOINT] ?? null;
        if ($endpoint === null) {
            throw new InvalidDataException('authorization endpoint isnt set');
        }
        return $this->redirectResponse(
            $endpoint,
            [
                "client_id" => $this->client->getClientID(),
                "response_type" => "id_token token", //Todo: eigentlich id_token code
                "redirect_uri" => $request->getUri(),
                "response_mode" => "form_post",
                "scope" => $this->client->getScopesAsOneString(),
                "state" => $state,
                "nonce" => $nonce
            ]
        );
    }

    /**
     * redirects the response to the given $endpoint with the given $params
     *
     * @param string $endpoint
     * @param array $params
     * @return ResponseInterface
     */
    private function redirectResponse(string $endpoint, array $params = []): ResponseInterface
    {
        $response = $this->app->responseFactory->createResponse();
        $response = $response->withHeader('Location', $endpoint . '?' . http_build_query($params));
        return $response;
    }
}