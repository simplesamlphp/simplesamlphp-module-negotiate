<?php

namespace SimpleSAML\Module\negotiate\Controller;

use SimpleSAML\Configuration;
use SimpleSAML\Module;
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
class Negotiate
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
        $params = [
            'secure' => false,
            'httponly' => true,
        ];

        Utils\HTTP::setCookie('NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT', null, $params, false);

        $this->session->setData('negotiate:disable', 'session', false, 86400); // 24*60*60=86400

        $t = new Template($this->config, 'negotiate:enable.twig');
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
        $params = [
            'expire' => mktime(0, 0, 0, 1, 1, 2038),
            'secure' => false,
            'httponly' => true,
        ];

        Utils\HTTP::setCookie('NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT', 'True', $params, false);

        $this->session->setData('negotiate:disable', 'session', false, 86400); //24*60*60=86400

        $t = new Template($this->config, 'negotiate:disable.twig');
        $t->data['url'] = Module::getModuleURL('negotiate/enable');

        return $t;
    }
}
