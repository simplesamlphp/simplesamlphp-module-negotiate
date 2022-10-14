<?php

declare(strict_types=1);

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
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * Controller class for the negotiate module.
 *
 * This class serves the different views available in the module.
 *
 * @package simplesamlphp/simplesamlphp-module-negotiate
 */
class NegotiateController
{
    /**
     * @var \SimpleSAML\Auth\Source|string
     * @psalm-var \SimpleSAML\Auth\Source|class-string
     */
    protected $authSource = Auth\Source::class;

    /**
     * @var \SimpleSAML\Auth\State|string
     * @psalm-var \SimpleSAML\Auth\State|class-string
     */
    protected $authState = Auth\State::class;

    /** @var \SimpleSAML\Configuration */
    protected $config;

    /**
     * @var \SimpleSAML\Logger|string
     * @psalm-var \SimpleSAML\Logger|class-string
     */
    protected $logger = Logger::class;

    /** @var \SimpleSAML\Metadata\MetaDataStorageHandler|null */
    protected ?MetaDataStorageHandler $metadataHandler = null;

    /**
     * @var \SimpleSAML\Module|string
     * @psalm-var \SimpleSAML\Module|class-string
     */
    protected $module = Module::class;

    /** @var \SimpleSAML\Session */
    protected Session $session;


    /**
     * Controller constructor.
     *
     * It initializes the global configuration and session for the controllers implemented here.
     *
     * @param \SimpleSAML\Configuration $config The configuration to use by the controllers.
     * @param \SimpleSAML\Session $session The session to use by the controllers.
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
     * Inject the \SimpleSAML\Auth\Source dependency.
     *
     * @param \SimpleSAML\Auth\Source $authSource
     */
    public function setAuthSource(Auth\Source $authSource): void
    {
        $this->authSource = $authSource;
    }


    /**
     * Inject the \SimpleSAML\Auth\State dependency.
     *
     * @param \SimpleSAML\Auth\State $authState
     */
    public function setAuthState(Auth\State $authState): void
    {
        $this->authState = $authState;
    }


    /**
     * Inject the \SimpleSAML\Logger dependency.
     *
     * @param \SimpleSAML\Logger $logger
     */
    public function setLogger(Logger $logger): void
    {
        $this->logger = $logger;
    }


    /**
     * Get the metadata storage handler instance.
     *
     * @return MetaDataStorageHandler
     */
    protected function getMetadataStorageHandler(): MetaDataStorageHandler
    {
        return $this->metadataHandler ?: MetaDataStorageHandler::getMetadataHandler();
    }


    /**
     * Inject the \SimpleSAML\Metadata\MetaDataStorageHandler dependency.
     *
     * @param \SimpleSAML\Metadata\MetaDataStorageHandler $handler
     */
    public function setMetadataStorageHandler(MetaDataStorageHandler $handler): void
    {
        $this->metadataHandler = $handler;
    }


    /**
     * Inject the \SimpleSAML\Module dependency.
     *
     * @param \SimpleSAML\Module $module
     */
    public function setModule(Module $module): void
    {
        $this->module = $module;
    }


    /**
     * Show enable.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \SimpleSAML\XHTML\Template
     * @throws Exception
     */
    public function enable(Request $request): Template
    {
        $this->session->setData('negotiate:disable', 'session', false, 86400); // 24*60*60=86400

        $cookie = new Cookie(
            'NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT',
            null, // value
            mktime(0, 0, 0, 1, 1, 2038), // expire
            '/', // path
            '', // domain
            true, // secure
            true // httponly
        );

        $t = new Template($this->config, 'negotiate:enable.twig');
        $t->headers->setCookie($cookie);
        $t->data['url'] = $this->module::getModuleURL('negotiate/disable');

        return $t;
    }


    /**
     * Show disable.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \SimpleSAML\XHTML\Template
     * @throws Exception
     */
    public function disable(Request $request): Template
    {
        $this->session->setData('negotiate:disable', 'session', false, 86400); //24*60*60=86400

        $cookie = new Cookie(
            'NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT',
            'true', // value
            mktime(0, 0, 0, 1, 1, 2038), // expire
            '/', // path
            '', // domain
            true, // secure
            true // httponly
        );

        $t = new Template($this->config, 'negotiate:disable.twig');
        $t->headers->setCookie($cookie);
        $t->data['url'] = $this->module::getModuleURL('negotiate/enable');

        return $t;
    }


    /**
     * Show retry
     *
     * @param Request $request The request that lead to this retry operation.
     * @return \SimpleSAML\HTTP\RunnableResponse
     * @throws \Exception
     * @throws \SimpleSAML\Error\BadRequest
     */
    public function retry(Request $request): RunnableResponse
    {
        /** @psalm-var string|null $authState */
        $authState = $request->query->get('AuthState', null);
        if ($authState === null) {
            throw new Error\BadRequest('Missing required AuthState query parameter.');
        }

        $state = $this->authState::loadState($authState, Negotiate::STAGEID);

        $mdh = $this->getMetadataStorageHandler();
        $idpid = $mdh->getMetaDataCurrentEntityID('saml20-idp-hosted', 'metaindex');
        $idpmeta = $mdh->getMetaData($idpid, 'saml20-idp-hosted');

        if (isset($idpmeta['auth'])) {
            $source = $this->authSource::getById($idpmeta['auth']);
            if ($source === null) {
                throw new Error\BadRequest('Invalid AuthId "' . $idpmeta['auth'] . '" - not found.');
            }

            $this->session->setData('negotiate:disable', 'session', false, 86400); //24*60*60=86400
            $this->logger::debug('Negotiate(retry) - session enabled, retrying.');

            return new RunnableResponse([$source, 'authenticate'], [$state]);
        }
        throw new Exception('Negotiate - retry - no "auth" parameter found in IdP metadata.');
    }


    /**
     * Show fallback
     *
     * @param Request $request The request that lead to this retry operation.
     *
     * @return \Symfony\Component\HttpFoundation\StreamedResponse
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NoState
     */
    public function fallback(Request $request): StreamedResponse
    {
        /** @psalm-var string|null $authState */
        $authState = $request->query->get('AuthState', null);
        if ($authState === null) {
            throw new Error\BadRequest('Missing required AuthState query parameter.');
        }

        $state = $this->authState::loadState($authState, Negotiate::STAGEID);

        $this->logger::debug('backend - fallback: ' . $state['LogoutState']['negotiate:backend']);

        return new class ([Negotiate::class, 'fallBack'], $state) extends StreamedResponse
        {
            /** @var array $state */
            protected array $state;

            public function __construct(callable $callback, array &$state)
            {
                parent::__construct($callback);
                $this->state = $state;
            }

            public function sendContent()
            {
                call_user_func_array($this->callback, [&$this->state]);
                return $this;
            }
        };
    }
}
