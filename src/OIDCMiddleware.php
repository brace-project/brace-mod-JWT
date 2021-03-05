<?php

namespace Brace\OpenIDConnect;

use Brace\Core\Base\BraceAbstractMiddleware;
use Brace\Session\Session;
use Brace\Session\SessionMiddleware;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Phore\Di\Container\Producer\DiService;
use Phore\HttpClient\Ex\PhoreHttpRequestException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class OIDCMiddleware extends BraceAbstractMiddleware
{
    public const ID_TOKEN_ATTRIBUTE = 'id_token';

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
            return $this->authenticate();
        }

        // wird das Token überhaupt verändert wenn ja wie ?
        $this->app->define(
            self::ID_TOKEN_ATTRIBUTE,
            new DiService(
                function () use ($idToken) {
                    return JWT::jsonDecode(
                        $idToken
                    ); //Todo: id_token weiterreichen/ und wenn ja Token oder Decoded Payload ?
                }
            )
        );

        if (!$this->isAuthorized()) {
            //Todo: return Permission denied
        }

        return $handler->handle($request);
    }

    /**
     * @param ServerRequestInterface $request
     * @param Session $session
     * @return bool
     */
    private function isAuthenticated(ServerRequestInterface $request, Session $session): bool
    {
        $queryParams = $request->getQueryParams();
        //Fehlerantwort von Umleitungs-URI
        if (array_key_exists('error', $queryParams) ||
            array_key_exists('error_description', $queryParams)) {
            return false;
            //Todo: throw new exception oder einfach nur wieder zum Login ?
        }
        //überprüfen ob Token vorhanden und state
        if (!array_key_exists('id_token', $queryParams) ||
            !array_key_exists('state', $queryParams)) {
            return false;
        }

        //verify Token
        $token = $queryParams['id_token'];
        $jwk = $this->client->getJWK();
        $idTokenPayload = JWT::decode(
            $token,
            JWK::parseKeySet($jwk)
        ); // Todo: $supportedAlgos -> welche value aus wellknown config
        //Todo: müssen weiter Ansprüche überprüft werden ?

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

        //Token is valid und user Autheticated
        return true;
    }

    /**
     * @return bool
     * @throws PhoreHttpRequestException
     */
    private function isAuthorized(): bool
    {
        $tokenEndpoint = $this->client->getConfig[OIDClient::TOKEN_ENDPOINT] ?? null;
        if ($tokenEndpoint === null) {
            //Todo: throw Exception ??
        }
        //bekommt Token & RefreshToken //Todo: wofür Refreshtoken ?
        $oAuthBearerToken = phore_http_request($this->openIDHost . $tokenEndpoint)
            ->withQueryParams(
                [

                ]
            )
            ->send()
            ->getBodyJson();
        //mit dem Token fragt Webserver -> WebAPI


        //isAuthorized
        return true;
    }

    /**
     *
     *
     * @param Session $session
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     */
    private function authenticate(Session $session, ServerRequestInterface $request): ResponseInterface
    {
        $state = phore_random_str();
        $nonce = phore_random_str();
        $session->set('state', $state);
        $session->set('nonce', $nonce); //Todo: wird die Session dann trotzdem persistiert
        $endpoint = $this->client->getConfig()[OIDClient::AUHTORIZATION_ENDPOINT] ?? null;
        if ($endpoint === null) {
            //Todo: was wenn das null ?
        }
        return $this->redirectResponse(
            $endpoint,
            [
                "client_id" => $this->client->getClientID(),
                "response_type" => "id_token token",
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