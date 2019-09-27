<?php

namespace SimpleSAML\Module\negotiate;;

use SimpleSAML\Configuration;
use SimpleSAML\Session;
use Symfony\Component\HttpFoundation\Request;

/**
 * @author Mathias Meisfjordskar, University of Oslo.
 *         <mathias.meisfjordskar@usit.uio.no>
 * @package SimpleSAMLphp
 */

$config = Configuration::getInstance();
$session = Session::getSessionFromRequest();
$request = Request::createFromGlobals();
$authState = $request->get('authState');
$controller = new Controller\Negotiate($config, $session);
$response = $controller->disable($authState);
$response->send();

