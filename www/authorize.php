<?php
/*
 * This file is part of the simplesamlphp-module-oauth2.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */


use SimpleSAML\Module\oauth2\Entity\UserEntity;
use SimpleSAML\Module\oauth2\OAuth2AuthorizationServer;
use SimpleSAML\Module\oauth2\Repositories\UserRepository;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\HttpHandlerRunner\Emitter\SapiEmitter;


$oauth2config = \SimpleSAML\Configuration::getOptionalConfig('module_oauth2.php');
$showerrors = $oauth2config->getBoolean('showerrors', false);

try {

    $useridattr = $oauth2config->getString('useridattr');

    $as = $oauth2config->getString('auth');
    $auth = new \SimpleSAML\Auth\Simple($as);
    $auth->requireAuth();

    $attributes = $auth->getAttributes();
    if (!isset($attributes[$useridattr])) {
        throw new \Exception('OAuth2 useridattr ' . $useridattr . ' doesn\'t exist. Available attributes are: ' . implode(", ", $attributes));
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

    $emiter = new SapiEmitter();
    $emiter->emit($response);
} catch (Exception $e) {
    header('Content-type: text/plain; utf-8', TRUE, 500);
    header('OAuth-Error: ' . $e->getMessage());

    if ($showerrors) {
        print_r($e);
    }
}
