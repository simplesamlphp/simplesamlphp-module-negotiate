<?php

declare(strict_types=1);

namespace SimpleSAML\Module\negotiate\Auth\Source;

use Exception;
use KRB5NegotiateAuth;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\ldap\Auth\Ldap;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;

/**
 * The Negotiate module. Allows for password-less, secure login by Kerberos and Negotiate.
 *
 * @package simplesamlphp/simplesamlphp-module-negotiate
 */
class Negotiate extends Auth\Source
{
    // Constants used in the module
    public const STAGEID = '\SimpleSAML\Module\negotiate\Auth\Source\Negotiate.StageId';

    public const AUTHID = '\SimpleSAML\Module\negotiate\Auth\Source\Negotiate.AuthId';

    /** @var \SimpleSAML\Module\ldap\Auth\Ldap */
    protected Ldap $ldap;

    /** @var string */
    protected string $backend = '';

    /** @var string */
    protected string $hostname = '';

    /** @var int */
    protected int $port = 389;

    /** @var bool */
    protected bool $referrals = true;

    /** @var bool */
    protected bool $enableTLS = false;

    /** @var bool */
    protected bool $debugLDAP = false;

    /** @var int */
    protected int $timeout = 30;

    /** @var string */
    protected string $keytab = '';

    /** @var string|integer|null */
    protected $spn = null;

    /** @var array */
    protected array $base = [];

    /** @var array */
    protected array $attr = ['uid'];

    /** @var array|null */
    protected ?array $subnet = null;

    /** @var string|null */
    protected ?string $admin_user = null;

    /** @var string|null */
    protected ?string $admin_pw = null;

    /** @var array|null */
    protected ?array $attributes = null;

    /** @var array */
    protected array $binaryAttributes = [];


    /**
     * Constructor for this authentication source.
     *
     * @param array $info Information about this authentication source.
     * @param array $config The configuration of the module
     *
     * @throws \Exception If the KRB5 extension is not installed or active.
     */
    public function __construct(array $info, array $config)
    {
        if (!extension_loaded('krb5')) {
            throw new Exception('KRB5 Extension not installed');
        }
        // call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        $cfg = Configuration::loadFromArray($config);

        $this->backend = $cfg->getString('fallback');
        $this->hostname = $cfg->getString('hostname');
        $this->port = $cfg->getInteger('port', 389);
        $this->referrals = $cfg->getBoolean('referrals', true);
        $this->enableTLS = $cfg->getBoolean('enable_tls', false);
        $this->debugLDAP = $cfg->getBoolean('debugLDAP', false);
        $this->timeout = $cfg->getInteger('timeout', 30);
        $configUtils = new Utils\Config();
        $this->keytab = $configUtils->getCertPath($cfg->getString('keytab'));
        $this->base = $cfg->getArrayizeString('base');
        $this->attr = $cfg->getArrayizeString('attr', 'uid');
        $this->subnet = $cfg->getArray('subnet', null);
        $this->admin_user = $cfg->getString('adminUser', null);
        $this->admin_pw = $cfg->getString('adminPassword', null);
        $this->attributes = $cfg->getArray('attributes', null);
        $this->binaryAttributes = $cfg->getArray('attributes.binary', []);
        $this->spn = $cfg->getValue('spn', null);
    }


    /**
     * The inner workings of the module.
     *
     * Checks to see if client is in the defined subnets (if defined in config). Sends the client a 401 Negotiate and
     * responds to the result. If the client fails to provide a proper Kerberos ticket, the login process is handed over
     * to the 'fallback' module defined in the config.
     *
     * LDAP is used as a user metadata source.
     *
     * @param array &$state Information about the current authentication.
     */
    public function authenticate(array &$state): void
    {
        // set the default backend to config
        $state['LogoutState'] = [
            'negotiate:backend' => $this->backend,
        ];
        $state['negotiate:authId'] = $this->authId;


        // check for disabled SPs. The disable flag is stored in the SP metadata
        if (array_key_exists('SPMetadata', $state) && $this->spDisabledInMetadata($state['SPMetadata'])) {
            $this->fallBack($state);
        }
        /* Go straight to fallback if Negotiate is disabled or if you are sent back to the IdP directly from the SP
        after having logged out. */
        $session = Session::getSessionFromRequest();
        $disabled = $session->getData('negotiate:disable', 'session');

        if (
            $disabled
            || (!empty($_COOKIE['NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT'])
                && $_COOKIE['NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT'] === 'true')
        ) {
            Logger::debug('Negotiate - session disabled. falling back');
            $this->fallBack($state);
            // never executed
            assert(false);
        }
        $mask = $this->checkMask();
        if (!$mask) {
            $this->fallBack($state);
            // never executed
            assert(false);
        }

        Logger::debug('Negotiate - authenticate(): looking for Negotiate');
        if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
            Logger::debug('Negotiate - authenticate(): Negotiate found');
            $this->ldap = new Ldap(
                $this->hostname,
                $this->enableTLS,
                $this->debugLDAP,
                $this->timeout,
                $this->port,
                $this->referrals
            );

            list($mech,) = explode(' ', $_SERVER['HTTP_AUTHORIZATION'], 2);
            if (strtolower($mech) == 'basic') {
                Logger::debug('Negotiate - authenticate(): Basic found. Skipping.');
            } else {
                if (strtolower($mech) != 'negotiate') {
                    Logger::debug('Negotiate - authenticate(): No "Negotiate" found. Skipping.');
                }
            }

            Assert::true(is_string($this->spn) || (is_int($this->spn) && ($this->spn === 0)) || is_null($this->spn));

            if (version_compare(phpversion('krb5'), '1.1.3', '<')) {
                $auth = new KRB5NegotiateAuth($this->keytab);
            } elseif (version_compare(phpversion('krb5'), '1.1.3', 'eq') && is_null($this->spn)) {
                /**
                 * This is a workaround for a bug in krb5 v1.1.3 that has been fixed in SVN, just not yet released.
                 * Once v1.1.4 is released, get rid of the elseif-clause and then make sure to mark the
                 * v.1.1.3 version of the extension as a conflict in the composer.json file.
                 */
                $auth = new KRB5NegotiateAuth($this->keytab);
            } else {
                $auth = new KRB5NegotiateAuth($this->keytab, $this->spn);
            }

            // attempt Kerberos authentication
            try {
                $reply = $auth->doAuthentication();
            } catch (Exception $e) {
                Logger::error('Negotiate - authenticate(): doAuthentication() exception: ' . $e->getMessage());
                $reply = null;
            }

            if ($reply) {
                // success! krb TGS received
                $user = $auth->getAuthenticatedUser();
                Logger::info('Negotiate - authenticate(): ' . $user . ' authenticated.');
                $lookup = $this->lookupUserData($user);
                if ($lookup !== null) {
                    $state['Attributes'] = $lookup;
                    // Override the backend so logout will know what to look for
                    $state['LogoutState'] = [
                        'negotiate:backend' => null,
                    ];
                    Logger::info('Negotiate - authenticate(): ' . $user . ' authorized.');
                    Auth\Source::completeAuth($state);
                    // Never reached.
                    assert(false);
                }
            } else {
                // Some error in the received ticket. Expired?
                Logger::info('Negotiate - authenticate(): Kerberos authN failed. Skipping.');
            }
        } else {
            // No auth token. Send it.
            Logger::debug('Negotiate - authenticate(): Sending Negotiate.');
            // Save the $state array, so that we can restore if after a redirect
            Logger::debug('Negotiate - fallback: ' . $state['LogoutState']['negotiate:backend']);
            $id = Auth\State::saveState($state, self::STAGEID);
            $params = ['AuthState' => $id];

            $this->sendNegotiate($params);
            exit;
        }

        Logger::info('Negotiate - authenticate(): Client failed Negotiate. Falling back');
        $this->fallBack($state);
        // The previous function never returns, so this code is never executed
        assert(false);
    }


    /**
     * @param array $spMetadata
     * @return bool
     */
    public function spDisabledInMetadata(array $spMetadata): bool
    {
        if (array_key_exists('negotiate:disable', $spMetadata)) {
            if ($spMetadata['negotiate:disable'] == true) {
                Logger::debug('Negotiate - SP disabled. falling back');
                return true;
            } else {
                Logger::debug('Negotiate - SP disable flag found but set to FALSE');
            }
        } else {
            Logger::debug('Negotiate - SP disable flag not found');
        }
        return false;
    }


    /**
     * checkMask() looks up the subnet config option and verifies
     * that the client is within that range.
     *
     * Will return TRUE if no subnet option is configured.
     *
     * @return bool
     */
    public function checkMask(): bool
    {
        // No subnet means all clients are accepted.
        if ($this->subnet === null) {
            return true;
        }
        $ip = $_SERVER['REMOTE_ADDR'];
        $netUtils = new Utils\Net();
        foreach ($this->subnet as $cidr) {
            $ret = $netUtils->ipCIDRcheck($cidr);
            if ($ret) {
                Logger::debug('Negotiate: Client "' . $ip . '" matched subnet.');
                return true;
            }
        }
        Logger::debug('Negotiate: Client "' . $ip . '" did not match subnet.');
        return false;
    }


    /**
     * Send the actual headers and body of the 401. Embedded in the body is a post that is triggered by JS if the client
     * wants to show the 401 message.
     *
     * @param array $params additional parameters to the URL in the URL in the body.
     */
    protected function sendNegotiate(array $params): void
    {
        $config = Configuration::getInstance();

        $url = htmlspecialchars(Module::getModuleURL('negotiate/backend', $params));

        $t = new Template($config, 'negotiate:redirect.twig');
        $t->setStatusCode(401);
        $t->headers->set('WWW-Authenticate', 'Negotiate');
        $t->data['baseurlpath'] = Module::getModuleURL('negotiate');
        $t->data['url'] = $url;
        $t->send();
    }


    /**
     * Passes control of the login process to a different module.
     *
     * @param array $state Information about the current authentication.
     *
     * @throws \SimpleSAML\Error\Error If couldn't determine the auth source.
     * @throws \SimpleSAML\Error\Exception
     * @throws \Exception
     */
    public static function fallBack(array &$state): void
    {
        $authId = $state['LogoutState']['negotiate:backend'];

        if ($authId === null) {
            throw new Error\Error([500, "Unable to determine auth source."]);
        }

        /** @psalm-var \SimpleSAML\Module\negotiate\Auth\Source\Negotiate|null $source */
        $source = Auth\Source::getById($authId);
        if ($source === null) {
            throw new Exception('Could not find authentication source with id ' . $state[self::AUTHID]);
        }

        try {
            $source->authenticate($state);
        } catch (Error\Exception $e) {
            Auth\State::throwException($state, $e);
        } catch (Exception $e) {
            $e = new Error\UnserializableException($e);
            Auth\State::throwException($state, $e);
        }
        // fallBack never returns after loginCompleted()
        Logger::debug('Negotiate: backend returned');
        self::loginCompleted($state);
    }


    /**
     * Strips away the realm of the Kerberos identifier, looks up what attributes to fetch from SP metadata and
     * searches the directory.
     *
     * @param string $user The Kerberos user identifier.
     *
     * @return array|null The attributes for the user or NULL if not found.
     */
    protected function lookupUserData(string $user): ?array
    {
        // Kerberos user names include realm. Strip that away.
        $pos = strpos($user, '@');
        if ($pos === false) {
            return null;
        }
        $uid = substr($user, 0, $pos);

        $this->adminBind();
        try {
            /** @psalm-var string $dn */
            $dn = $this->ldap->searchfordn($this->base, $this->attr, $uid);
            return $this->ldap->getAttributes($dn, $this->attributes, $this->binaryAttributes);
        } catch (Error\Exception $e) {
            Logger::debug('Negotiate - ldap lookup failed: ' . $e);
            return null;
        }
    }


    /**
     * Elevates the LDAP connection to allow restricted lookups if
     * so configured. Does nothing if not.
     *
     * @throws \SimpleSAML\Error\AuthSource
     */
    protected function adminBind(): void
    {
        if ($this->admin_user === null || $this->admin_pw === null) {
            // no admin user
            return;
        }
        Logger::debug('Negotiate - authenticate(): Binding as system user ' . var_export($this->admin_user, true));

        if (!$this->ldap->bind($this->admin_user, $this->admin_pw)) {
            $msg = 'Unable to authenticate system user (LDAP_INVALID_CREDENTIALS) '
                . var_export($this->admin_user, true);
            Logger::error('Negotiate - authenticate(): ' . $msg);
            throw new Error\AuthSource('negotiate', $msg);
        }
    }


    /**
     * Log out from this authentication source.
     *
     * This method either logs the user out from Negotiate or passes the
     * logout call to the fallback module.
     *
     * @param array &$state Information about the current logout operation.
     */
    public function logout(array &$state): void
    {
        // get the source that was used to authenticate
        $authId = $state['negotiate:backend'];
        Logger::debug('Negotiate - logout has the following authId: "' . $authId . '"');

        if ($authId === null) {
            $session = Session::getSessionFromRequest();
            $session->setData('negotiate:disable', 'session', true, 24 * 60 * 60);
            parent::logout($state);
        } else {
            /** @psalm-var \SimpleSAML\Module\negotiate\Auth\Source\Negotiate|null $source */
            $source = Auth\Source::getById($authId);
            if ($source === null) {
                throw new \Exception('Could not find authentication source with id ' . $state[self::AUTHID]);
            }
            $source->logout($state);
        }
    }
}
