<?php
/*
 * This file is part of the simplesamlphp-module-oauth2.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oauth2;

use SimpleSAML\Module\oauth2\OAuth2AuthorizationServer;
use SimpleSAML\Module\oauth2\Entity\UserEntity;
use SimpleSAML\Module\oauth2\Repositories\UserRepository;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequestFactory;
use SimpleSAML\Configuration;
use SimpleSAML\Session;

class Controller
{
    /** @var \SimpleSAML\Configuration */
    protected $config;

    /** @var \SimpleSAML\Configuration */
    protected $oauth2config;

    /** @var \SimpleSAML\Configuration */
    protected $session;

    /** @var bool */
    protected $showerrors = false;

    /**
     *  constructor.
     *
     * @param \SimpleSAML\Configuration $config The configuration to use.
     * @param \SimpleSAML\Session $session The current user session.
     */
    public function __construct(Configuration $config, Session $session)
    {
        $this->config = $config;
        $this->session = $session;
        $this->oauth2config = Configuration::getOptionalConfig('module_oauth2.php');
        $this->showerrors = $this->oauth2config->getBoolean('showerrors', false);
    }

    public function authorize()
    {

        try {

            $useridattr = $this->oauth2config->getString('useridattr');

            $as = $this->oauth2config->getString('auth');
            $auth = new \SimpleSAML\Auth\Simple($as);
            $auth->requireAuth();

            $attributes = $auth->getAttributes();
            if (!isset($attributes[$useridattr])) {
                throw new \Exception('Oauth2 useridattr doesn\'t exists. Available attributes are: ' . implode(", ", $attributes));
            }
            $userid = $attributes[$useridattr][0];

            // Persists the user attributes on the database
            $userRepository = new UserRepository();
            $userRepository->insertOrCreate($userid, $attributes);

            $server = OAuth2AuthorizationServer::getInstance();
            $request = ServerRequestFactory::fromGlobals();

            $authRequest = $server->validateAuthorizationRequest($request);
            $authRequest->setUser(new UserEntity($userid));
            $authRequest->setAuthorizationApproved(true);

            $response = $server->completeAuthorizationRequest($authRequest, new Response());

            $emiter = new Response\SapiEmitter();
            $emiter->emit($response);
        } catch (Exception $e) {
            header('Content-type: text/plain; utf-8', TRUE, 500);
            header('OAuth-Error: ' . $e->getMessage());

            if ($this->showerrors) {
                print_r($e);
            }
        }
    }

    public function token()
    {

        try {
            $server = OAuth2AuthorizationServer::getInstance();
            $request = ServerRequestFactory::fromGlobals();

            $response = $server->respondToAccessTokenRequest($request, new Response());

            $emiter = new Response\SapiEmitter();
            $emiter->emit($response);
        } catch (Exception $e) {
            header('Content-type: text/plain; utf-8', TRUE, 500);
            header('OAuth-Error: ' . $e->getMessage());

            if ($this->showerrors) {
                print_r($e);
            }
        }
    }

    public function userinfo()
    {
        try {
            $server = OAuth2ResourceServer::getInstance();
            $request = ServerRequestFactory::fromGlobals();

            $authorization = $server->validateAuthenticatedRequest($request);

            $oauth2Attributes = $authorization->getAttributes();
            $tokenId = $oauth2Attributes['oauth_access_token_id'];

            $accessTokenRepository = new AccessTokenRepository();
            $userId = $accessTokenRepository->getUserId($tokenId);

            $userRepository = new UserRepository();
            $attributes['attributes'] = $userRepository->getAttributes($userId);
            $attributes['username'] = $userId;

            $response = new Response\JsonResponse($attributes);

            $emiter = new Response\SapiEmitter();
            $emiter->emit($response);
        } catch (Exception $e) {
            header('Content-type: text/plain; utf-8', TRUE, 500);
            header('OAuth-Error: ' . $e->getMessage());

            if ($this->showerrors) {
                print_r($e);
            }
        }
    }
}
