<?php

namespace Brace\OAuth;

use Brace\Core\Base\BraceAbstractMiddleware;
use Brace\Session\Session;
use Brace\Session\SessionMiddleware;
use Firebase\JWT\JWT;
use Phore\Di\Container\Producer\DiService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class OAuthMiddleware extends BraceAbstractMiddleware
{
    public const JWT_ATTRIBUTE = 'jwt';

    public function __construct(
        private OAuthClient $client,
        private string $openIDHost,
    ) {
    }

    //Todo: DOKUMENTATION !!! wenn Session benutzt wird dann muss es nach dieser Definiert werden
    //OpenID Connect for user Atuhentication
    //machen wir jetzt Oauht 2.0 oder OpenIDConnect
    //OAuth2.0 nämlich nur Autorisierungsprotokoll
    //OpenID Connect erweiterung als Authentifizierungsprotokoll (identity layer on top of the OAuth2.0)
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        /* @var $session Session */
        $session = $this->app->get(SessionMiddleware::SESSION_ATTRIBUTE);

        if (!$this->isAuthenticated($request, $session)) {
            return $this->redirect(
                $this->client->config[OAuthClient::AUHTORIZATION_ENDPOINT],
                [
                    "client_id" => $this->client->getClientID(),
                    "response_type" => "id_token",
                    "redirect_uri" => "", //Todo: aktuelle Route
                    "scope" => $this->client->getScopesAsOneString(),
                    "state" => phore_random_str(), //Todo: muss vorher in Session gespeichert werden
                    "nonce" => phore_random_str()  //Todo: muss vorher in Session gespeichert werden
                ]
            );
        }
        // wird das Token überhaupt verändert wenn ja wie ?
        $this->app->define(
            self::JWT_ATTRIBUTE,
            new DiService(
                function () use () {
                    return; //Todo: id_token weiterreichen/ und wenn ja Token oder Decoded Payload ?
                }
            )
        );

        //Bis hier hin nur um zu gucken ob der Nutzer überhaupt angemeldet ist
        //Nun gucken auf welchen Teil der Api er zugreifen kann dazu fragt der Webserver beim Token Endpoint ein Token an
        //das nur er behält und der Nutzer nicht bekommt

        //OauthBearerToken
        //Webserver -> WebAPI
        //bekommt Token & RefreshToken
        $tokenEndpoint = $this->client->config[OAuthClient::TOKEN_ENDPOINT] ?? null;
        if ($tokenEndpoint === null) {
            //Todo: throw Exception ??
        }
        $tokenEndpointData = phore_http_request($this->openIDHost . $tokenEndpoint)
            ->withQueryParams(
                [
                    "access_token" => "",
                    "token_type" => "Bearer",
                    "expires_in" => 1234
                ]
            )
            ->send()
            ->getBodyJson();

        //send Request an TokenEndpoint




        $response = $handler->handle($request);

        $session->set("id_token", $idToken);
        //hier wahrschienlich nochmal token in Session speichern ?
        //wenn Token verändert muss es dann nicht auch an einen header gehängt werden ?

        return $response;
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
        $jwt = new JWT();
        $publicKey = $this->getPublicKey();// Todo: woher public key ?
        $idTokenPayload = $jwt::decode($token, $publicKey);
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

    private function redirect(string $endpoint, array $params): ResponseInterface
    {
    }
}