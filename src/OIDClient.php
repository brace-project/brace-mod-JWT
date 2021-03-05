<?php

namespace Brace\OpenIDConnect;

use JetBrains\PhpStorm\Pure;
use Phore\HttpClient\Ex\PhoreHttpRequestException;

class OIDClient
{
    public const AUHTORIZATION_ENDPOINT = "authorization_endpoint";
    public const TOKEN_ENDPOINT = "token_endpoint";
    public const TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED = "token_endpoint_auth_methods_supported";
    public const JWKS_URI = "jwks_uri";
    public const USERINFO_ENDPOINT = "userinfo_endpoint";
    public const SUBJECT_TYPES_SUPPORTED = "subject_types_supported";
    private const OPENIDCONFIG_PATH = "/.well-known/openid-configuration";
    private array $config;

    public function __construct(
        private string $clientId,
        private string $clientSecret,
        string $host,
        private array $clientScopes
    ) {
        $this->_getOpenIDConfiguration($host);
    }

    /**
     * loads the OpenIdConfiguration from the given openIdHost
     *
     * @param string $openIdHost
     */
    private function _getOpenIDConfiguration(string $openIdHost): void
    {
        try {
            $this->config = phore_http_request(
                $openIdHost . self::OPENIDCONFIG_PATH
            )
                ->send()
                ->getBodyJson();
        } catch (PhoreHttpRequestException $e) {
            //Todo: was wenn nicht erreichbar ?
        }
    }

    public function getJWK(): array
    {
        try {
            return $this->config = phore_http_request(
                self::JWKS_URI
            )
                ->send()
                ->getBodyJson();
        } catch (PhoreHttpRequestException $e) {
            //Todo: was wenn nicht erreichbar ?
        }
    }

    /**
     * Returns all scopes as a space-separated list of scopes
     *
     * @return string
     */
    #[Pure] public function getScopesAsOneString(): string
    {
        return implode(" ", $this->clientScopes);
    }

    /**
     * @return string
     */
    public function getClientID(): string
    {
        return $this->clientId;
    }

    /**
     * @return array
     */
    public function getConfig(): array
    {
        return $this->config;
    }
}