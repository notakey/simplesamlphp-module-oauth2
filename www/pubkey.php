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
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\HttpHandlerRunner\Emitter\SapiEmitter;
use SimpleSAML\Utils\Config;
use SimpleSAML\Module\oauth2\Repositories\ClientRepository;

try {
    $oauth2config = \SimpleSAML\Configuration::getOptionalConfig('module_oauth2.php');
    $showerrors = $oauth2config->getBoolean('showerrors', false);
    $allowPubkey = $oauth2config->getBoolean('pubkey', false);
    $pubkeyAuth = $oauth2config->getBoolean('pubkey-auth', true);
} catch (Exception $e) {
    $showerrors = false;
    $allowPubkey = false;
    $pubkeyAuth = true;
}

try {
    if (!$allowPubkey) {
        throw new \SimpleSAML\Error\Exception("Not supported", 8104);
    }

    $server = OAuth2ResourceServer::getInstance();
    $request = ServerRequestFactory::fromGlobals();

    $request = ServerRequestFactory::fromGlobals();

    $clientRepo = new ClientRepository();

    if ($pubkeyAuth) {
        if (!$request->hasHeader('Authorization')) {
            throw new \SimpleSAML\Error\Exception("Missing authorization", 8100);
        }

        $header = $request->getHeader('Authorization')[0];
        if (\strpos($header, 'Basic ') !== 0) {
            throw new \SimpleSAML\Error\Exception("Invalid authorization", 8101);
        }

        if (!($decoded = \base64_decode(\substr($header, 6)))) {
            throw new \SimpleSAML\Error\Exception("Invalid authorization", 8102);
        }

        list($clienId, $clientSecret) = \explode(':', $decoded, 2);
        if (!$clientRepo->validateClient($clienId, $clientSecret, null)) {
            throw new \SimpleSAML\Error\Exception("Invalid credentials", 8103);
        }
    }

    $publicKeyPath = Config::getCertPath('oauth2_module.crt');

    if (\strpos($publicKeyPath, 'file://') !== 0) {
        $publicKeyPath = 'file://' . $publicKeyPath;
    }

    $pubKeyInfo = openssl_pkey_get_details(openssl_pkey_get_public($publicKeyPath));
    $pubkey = ["pubkey" => $pubKeyInfo['key']];

    $response = new Response\JsonResponse($pubkey);

    $emiter = new SapiEmitter();
    $emiter->emit($response);
} catch (Exception $e) {
    header('Content-type: text/plain; utf-8', TRUE, 500);
    header('OAuth-Error: ' . $e->getMessage());

    if ($showerrors) {
        print_r($e);
    }
}
