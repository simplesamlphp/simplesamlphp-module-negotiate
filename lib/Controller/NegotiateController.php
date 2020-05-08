<?php

namespace SimpleSAML\Module\negotiate\Controller;

use Exception;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module;
use SimpleSAML\Module\negotiate\Auth\Source\Negotiate;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Controller class for the negotiate module.
 *
 * This class serves the different views available in the module.
 *
 * @package SimpleSAML\Module\negotiate
 */
class NegotiateController
{
    /** @var \SimpleSAML\Configuration */
    protected $config;

    /** @var \SimpleSAML\Session */
    protected $session;


    /**
     * Controller constructor.
     *
     * It initializes the global configuration and session for the controllers implemented here.
     *
     * @param \SimpleSAML\Configuration              $config The configuration to use by the controllers.
     * @param \SimpleSAML\Session                    $session The session to use by the controllers.
     *
     * @throws \Exception
     */
    public function __construct(
        Configuration $config,
        Session $session
    ) {
        $this->config = $config;
        $this->session = $session;
    }


    /**
     * Show enable.
     *
     * @return \SimpleSAML\XHTML\Template
     */
    public function enable(): Template
    {
        $this->session->setData('negotiate:disable', 'session', false, 86400); // 24*60*60=86400

        $cookie = new \Symfony\Component\HttpFoundation\Cookie(
            'NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT',
            'null', // value
            mktime(0, 0, 0, 1, 1, 2038), // expire
            '/', // path
            '', // domain
            true, // secure
            true // httponly
        );

        $t = new Template($this->config, 'negotiate:enable.twig');
        $t->headers->setCookie($cookie);
        $t->data['url'] = Module::getModuleURL('negotiate/disable');

        return $t;
    }


    /**
     * Show disable.
     *
     * @return \SimpleSAML\XHTML\Template
     */
    public function disable(): Template
    {
        $this->session->setData('negotiate:disable', 'session', false, 86400); //24*60*60=86400

        $cookie = new \Symfony\Component\HttpFoundation\Cookie(
            'NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT',
            'True', // value
            mktime(0, 0, 0, 1, 1, 2038), // expire
            '/', // path
            '', // domain
            true, // secure
            true // httponly
        );

        $t = new Template($this->config, 'negotiate:disable.twig');
        $t->headers->setCookie($cookie);
        $t->data['url'] = Module::getModuleURL('negotiate/enable');

        return $t;
    }


    /**
     * Show retry
     *
     * @param Request $request The request that lead to this retry operation.
     * @return \SimpleSAML\HTTP\RunnableResponse
     */
    public function retry(Request $request): RunnableResponse
    {
        $authState = $request->get('AuthState', null);
        if ($authState === null) {
            throw new Error\BadRequest('Missing required AuthState query parameter.');
        }

        /** @psalm-var array $state */
        $state = Auth\State::loadState($authState, Negotiate::STAGEID);

        $metadata = MetaDataStorageHandler::getMetadataHandler();
        $idpid = $metadata->getMetaDataCurrentEntityID('saml20-idp-hosted', 'metaindex');
        $idpmeta = $metadata->getMetaData($idpid, 'saml20-idp-hosted');

        if (isset($idpmeta['auth'])) {
            $source = Auth\Source::getById($idpmeta['auth']);
            if ($source === null) {
                throw new Error\BadRequest('Invalid AuthId "' . $idpmeta['auth'] . '" - not found.');
            }

            $this->session->setData('negotiate:disable', 'session', false, 86400); //24*60*60=86400
            Logger::debug('Negotiate(retry) - session enabled, retrying.');

            return new RunnableResponse([$source, 'authenticate'], [$state]);
        }
        throw new Exception('Negotiate - retry - no "auth" parameter found in IdP metadata.');
    }


    /**
     * Show fallback
     *
     * @param Request $request The request that lead to this retry operation.
     * @return \SimpleSAML\HTTP\RunnableResponse
     */
    public function fallback(Request $request): RunnableResponse
    {
        $authState = $request->get('AuthState', null);
        if ($authState === null) {
            throw new Error\BadRequest('Missing required AuthState query parameter.');
        }

        /** @psalm-var array $state */
        $state = Auth\State::loadState($authState, Negotiate::STAGEID);

        Logger::debug('backend - fallback: ' . $state['LogoutState']['negotiate:backend']);

        return new RunnableResponse([Negotiate::class, 'fallback'], [$state]);
    }
}
