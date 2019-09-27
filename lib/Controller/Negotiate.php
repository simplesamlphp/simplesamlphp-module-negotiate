<?php

namespace SimpleSAML\Module\negotiate\Controller;

use SimpleSAML\Auth;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Metadata;
use SimpleSAML\Module;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;

/**
 * Controller class for the negotiate module.
 *
 * This class serves the different views available in the module.
 *
 * @package SimpleSAML\Module\negotiate
 */
class Negotiate
{
    /** @var \SimpleSAML\Configuration */
    protected $config;

    /** @var \SimpleSAML\Session */
    protected $session;


    /**
     * Controller constructor.
     *
     * It initializes the global configuration and session
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
     * enable
     *
     * @return \SimpleSAML\XHTML\Template
     *   An HTML template or a redirection if we are not authenticated.
     */
    public function enable()
    {
        $params = [
            'secure' => true,
            'httponly' => true,
        ];
        Utils\HTTP::setCookie('NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT', null, $params, false);

        $this->session->setData('negotiate:disable', 'session', false, 86400); // 24*60*60=86400
        $t = new Template($this->config, 'negotiate:enable.php');
        $t->data['url'] = Module::getModuleURL('negotiate/disable.php');
        return $t;
    }


    /**
     * disable
     *
     * @return \SimpleSAML\XHTML\Template
     *   An HTML template or a redirection if we are not authenticated.
     */
    public function disable()
    {
        $params = [
            'expire' => (mktime(0, 0, 0, 1, 1, 2038)),
            'secure' => true,
            'httponly' => true,
        ];
        Utils\HTTP::setCookie('NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT', 'True', $params, false);

        $this->session->setData('negotiate:disable', 'session', false, 86400); //24*60*60=86400
        $t = new Template($this->config, 'negotiate:disable.php');
        $t->data['url'] = Module::getModuleURL('negotiate/enable.php');
        return $t;
    }


    /**
     * backend
     *
     * @return \SimpleSAML\XHTML\Template
     *   An HTML template or a redirection if we are not authenticated.
     */
    public function backend($authState)
    {
        $state = Auth\State::loadState(
            $authState,
            Module\negotiate\Auth\Source\Negotiate::STAGEID
        );
        Logger::debug('backend - fallback: '.$state['LogoutState']['negotiate:backend']);
        Module\negotiate\Auth\Source\Negotiate::fallBack($state);
    }


    /**
     * retry
     *
     * @return \SimpleSAML\XHTML\Template
     *   An HTML template or a redirection if we are not authenticated.
     */
    public function retry($authState)
    {
        $state = Auth\State::loadState(
            $authState,
            Module\negotiate\Auth\Source\Negotiate::STAGEID
        );
        $metadata = Metadata\MetaDataStorageHandler::getMetadataHandler();
        $idpid = $metadata->getMetaDataCurrentEntityID('saml20-idp-hosted', 'metaindex');
        $idpmeta = $metadata->getMetaData($idpid, 'saml20-idp-hosted');
        if (isset($idpmeta['auth'])) {
            $source = Auth\Source::getById($idpmeta['auth']);
            if ($source === null) {
                throw new Error\BadRequest('Invalid AuthId "'.$idpmeta['auth'].'" - not found.');
            }
            $this->session->setData('negotiate:disable', 'session', false, 86400); //24*60*60=86400
            Logger::debug('Negotiate(retry) - session enabled, retrying.');
            $source->authenticate($state);
            assert(false);
        } else {
            Logger::error('Negotiate - retry - no "auth" parameter found in IdP metadata.');
            assert(false);
        }
    }
}
