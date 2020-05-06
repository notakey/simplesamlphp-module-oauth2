<?php
/*
 * This file is part of the simplesamlphp-module-oauth2.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */


use SimpleSAML\Module\oauth2\OAuth2ResourceServer;
use SimpleSAML\Module\oauth2\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oauth2\Repositories\UserRepository;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\HttpHandlerRunner\Emitter\SapiEmitter;

try {
    $oauth2config = \SimpleSAML\Configuration::getOptionalConfig('module_oauth2.php');
    $showerrors = $oauth2config->getBoolean('showerrors', false);
} catch (Exception $e) {
    $showerrors = false;
}

try {
    $server = OAuth2ResourceServer::getInstance();
    $request = ServerRequestFactory::fromGlobals();

    $authorization = $server->validateAuthenticatedRequest($request);

    $oauth2Attributes = $authorization->getAttributes();
    $tokenId = $oauth2Attributes['oauth_access_token_id'];

    $accessTokenRepository = new AccessTokenRepository();
    $userId = $accessTokenRepository->getUserId($tokenId);

    if (!$userId) {
        throw new Exception("OAuth2 user not found.");
    }

    $userRepository = new UserRepository();
    $attributes['attributes'] = $userRepository->getAttributes($userId);
    $attributes['username'] = $userId;

    $response = new Response\JsonResponse($attributes);

    $emiter = new SapiEmitter();
    $emiter->emit($response);
} catch (Exception $e) {
    header('Content-type: text/plain; utf-8', TRUE, 500);
    header('OAuth-Error: ' . $e->getMessage());

    if ($showerrors) {
        print_r($e);
    }
}
