<?php
/*
 * This file is part of the simplesamlphp-module-oauth2.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequestFactory;


$oauth2config = \SimpleSAML\Configuration::getOptionalConfig('module_oauth2.php');
$showerrors = $oauth2config->getBoolean('showerrors', false);

try {

    if (!isset($_GET['RelayState'])) {
        throw new \SimpleSAML\Error\Error('NORELAYSTATE');
    }

    $relay_url = \SimpleSAML\Utils\HTTP::checkURLAllowed((string) $_GET['RelayState']);

    $as = $oauth2config->getString('auth');
    $auth = new \SimpleSAML\Auth\Simple($as);

    if ($auth->isAuthenticated()) {
        $auth->logout();
    }

    \SimpleSAML\Utils\HTTP::redirectTrustedURL($relay_url);
} catch (Exception $e) {
    header('Content-type: text/plain; utf-8', TRUE, 500);
    header('OAuth-Error: ' . $e->getMessage());

    if ($showerrors) {
        print_r($e);
    }
}
