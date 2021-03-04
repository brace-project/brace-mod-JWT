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
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        /* @var $session Session */
        $session = $this->app->get(SessionMiddleware::SESSION_ATTRIBUTE);
        /* @var $idToken JWT */
        $idToken = $session->get('id_token'); //is ein JWT Token

        if (!$this->isAuthenticated($request, $idToken, $session)) {
            return;//redirect Method
            $this->client->config[OAuthClient::AUHTORIZATION_ENDPOINT];
            [
                "client_id" => $this->client->getClientID(),
                "response_type" => "id_token",
                "redirect_uri" => , //aktueller Request
                "scope" => $this->client->getScopesAsOneString(),
                "state" => phore_random_str(), //state in session speichern
                "nonce" => phore_random_str()  //nonce in session speichern (verify in token claim)

            ];
        }
        //frage hier ob das id_token dann in der Session gespeichert wird
        //und wie sowas validiert wird

        //Bis hier hin nur um zu gucken ob der Nutzer überhaupt rechte auf dem Server hat
        //Nun gucken auf welchen Teil der Api er zugreifen kann dazu fragt der Webserver beim Token Endpoint ein Token an
        //das nur er behält und der Nutzer nicht bekommt

        //OauthBearerToken
        //Webserver -> WebAPI
        //bekommt Token & RefreshToken
        $tokenEndpoint = $this->client->config[OAuthClient::TOKEN_ENDPOINT] ?? null;
        //send Request an TokenEndpoint
        [
            access_token => ,
            token_type => "Bearer",
            "expires_in" =>
        ]

        // wird das Token überhaupt verändert wenn ja wie ?
        $this->app->define(
            self::JWT_ATTRIBUTE,
            new DiService(
                function () use (){
                    return ; // das richtig Token
                }
            )
        );

        $response = $handler->handle($request);

        $session->set("id_token", $idToken);
        //hier wahrschienlich nochmal token in Session speichern ?
        //wenn Token verändert muss es dann nicht auch an einen header gehängt werden ?

        return $response;
    }

    /**
     * @param ServerRequestInterface $request
     * @param JWT|null $token
     * @param Session $session
     * @return bool
     */
    private function isAuthenticated(ServerRequestInterface $request, ?JWT $token, Session $session): bool
    {
        $requestIdToken = $request->get();// id Token
        if ($token === null ||
            $requestIdToken === null ||
            $requestIdToken !== $token) {
            return false;
        }

        $requestState = $request->get();// state
        $sessionState = $session->get();//state
        if ($requestState !== $sessionState) {
            return false;
        }

        //$decodedToken = $token->jsonDecode();
        $sessionNonce = $session->get();//nonce
        if () { //nonce aus decoded JwT ungleich dem aus der Session
            return false;
        }

        //Token is valid und user Autheticated
        return true;
    }
}