<?php

declare(strict_types=1);

namespace SimpleSAML\Module\negotiate\Auth\Source;

use Exception;
use GSSAPIChannelBinding;
use KRB5NegotiateAuth;
use SimpleSAML\Assert\Assert;
use SimpleSAML\{Auth, Configuration, Error, Logger, Module, Session, Utils};
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\{IpUtils, Request};

use function array_key_exists;
use function extension_loaded;
use function htmlspecialchars;
use function is_int;
use function is_null;
use function is_string;
use function pack;
use function phpversion;
use function preg_split;
use function sprintf;
use function str_replace;
use function strval;
use function version_compare;

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

    /** @var string|null */
    protected ?string $backend = null;

    /** @var string|null */
    protected ?string $fallback;

    /** @var string */
    protected string $keytab;

    /** @var string|integer|null */
    protected $spn = null;

    /** @var array|null */
    protected ?array $subnet = null;

    /** @var array */
    private array $realms;

    /** @var string[] */
    private array $allowedCertificateHashes;

    /** @var bool */
    private bool $enforceChannelBinding = false;


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
        $this->fallback = $cfg->getOptionalString('fallback', null);
        $this->spn = $cfg->getOptionalValue('spn', null);
        $configUtils = new Utils\Config();
        $this->keytab = $configUtils->getCertPath($cfg->getString('keytab'));
        $this->subnet = $cfg->getOptionalArray('subnet', null);
        $this->realms = $cfg->getArray('realms');
        $this->allowedCertificateHashes = $cfg->getOptionalArray('allowedCertificateHashes', []);
        $this->enforceChannelBinding = $cfg->getOptionalBoolean('enforceChannelBinding', false);
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
            'negotiate:backend' => $this->fallback,
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
            $disabled ||
            (array_key_exists('NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT', $_COOKIE) &&
            $_COOKIE['NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT'] === 'true')
        ) {
            Logger::debug('Negotiate - session disabled. falling back');
            $this->fallBack($state);
            return;
        }

        if (!$this->checkMask()) {
            Logger::debug('Negotiate - IP matches blacklisted subnets. falling back');
            $this->fallBack($state);
            return;
        }

        Logger::debug('Negotiate - authenticate(): looking for authentication header');
        if (array_key_exists('HTTP_AUTHORIZATION', $_SERVER) && !empty($_SERVER['HTTP_AUTHORIZATION'])) {
            Logger::debug('Negotiate - authenticate(): Authentication header found');

            Assert::true(is_string($this->spn) || (is_int($this->spn) && ($this->spn === 0)) || is_null($this->spn));

            list($mech,) = explode(' ', $_SERVER['HTTP_AUTHORIZATION'], 2);
            if (strtolower($mech) === 'basic') {
                Logger::debug('Negotiate - authenticate(): Basic found. Skipping.');
            } elseif (strtolower($mech) !== 'negotiate') {
                Logger::debug('Negotiate - authenticate(): No "Negotiate" found. Skipping.');
            } else {
                // attempt Kerberos authentication
                $reply = null;

                try {
                    if (version_compare(phpversion('krb5'), '1.1.6', '<')) {
                        Logger::debug('Negotiate - authenticate(): Trying to authenticate (channel binding not available).');
                        $auth = new KRB5NegotiateAuth($this->keytab, $this->spn);
                        $reply = $this->doAuthentication($auth);
                    } else if (empty($this->allowedCertificateHashes) && $this->enforceChannelBinding === false) {
                        Logger::debug('Negotiate - authenticate(): Trying to authenticate without channel binding.');
                        $auth = new KRB5NegotiateAuth($this->keytab, $this->spn);
                        $reply = $this->doAuthentication($auth);
                    } else {
                        Logger::debug('Negotiate - authenticate(): Trying to authenticate with channel binding.');

                        $hashes = str_replace(':', '', $this->allowedCertificateHashes);
                        foreach ($hashes as $hash) {
                            $binding = $this->createBinding($hash);
                            $auth = new KRB5NegotiateAuth($this->keytab, $this->spn, $binding);

                            try {
                                $reply = $this->doAuthentication($auth, $hash);
                                break;
                            } catch (Exception $e) {
                                continue;
                            }
                        }

                        if (!$auth->isChannelBound()) {
                            throw new Error\Exception(
                                'Negotiate - authenticate(): Failed to perform channel binding using '
                                . 'any of the configured certificate hashes.',
                            );
                        }
                    }
                } catch (Exception $e) {
                    Logger::error('Negotiate - authenticate(): doAuthentication() exception: ' . $e->getMessage());
                }

                if ($reply) {
                    // success! krb TGS received
                    /** @psalm-var \KRB5NegotiateAuth $auth */
                    $userPrincipalName = $auth->getAuthenticatedUser();
                    Logger::info('Negotiate - authenticate(): ' . $userPrincipalName . ' authenticated.');

                    // Search for the corresponding realm and set current variables
                    @list($uid, $realmName) = preg_split('/@/', $userPrincipalName, 2);
                    /** @psalm-var string $realmName */
                    Assert::notNull($realmName);

                    // Use the correct realm
                    if (isset($this->realms[$realmName])) {
                        Logger::info(sprintf('Negotiate - setting realm parameters for "%s".', $realmName));
                        $this->backend = $this->realms[$realmName];
                    } elseif (isset($this->realms['*'])) {
                        // Use default realm ("*"), if set
                        Logger::info('Negotiate - setting realm parameters with default realm.');
                        $this->backend = $this->realms['*'];
                    } else {
                        // No corresponding realm found, cancel
                        $this->fallBack($state);
                        return;
                    }

                    if (($lookup = $this->lookupUserData($uid)) !== null) {
                        $state['Attributes'] = $lookup;
                        // Override the backend so logout will know what to look for
                        $state['LogoutState'] = [
                            'negotiate:backend' => $this->backend,
                        ];
                        Logger::info('Negotiate - authenticate(): ' . $userPrincipalName . ' authorized.');
                        Auth\Source::completeAuth($state);
                        return;
                    }
                } else {
                    // Some error in the received ticket. Expired?
                    Logger::info('Negotiate - authenticate(): Kerberos authN failed. Skipping.');
                }
            }
        } else {
            // Save the $state array, so that we can restore if after a redirect
            Logger::debug('Negotiate - fallback: ' . $state['LogoutState']['negotiate:backend']);
            $id = Auth\State::saveState($state, self::STAGEID);
            $params = ['AuthState' => $id];

            // No auth token. Send it.
            Logger::debug('Negotiate - authenticate(): Sending Negotiate.');
            $this->sendNegotiate($params); // never returns
        }

        Logger::info('Negotiate - authenticate(): Client failed Negotiate. Falling back');
        $this->fallBack($state);
        return;
    }


    private function doAuthentication(KRB5NegotiateAuth $auth, string $hash = null): bool
    {
        if ($this->enforceChannelBinding === true && ($hash === null)) {
            throw new Error\Exception(
                'Negotiate - doAuthenticate(): Channel binding is required, but the client '
                . 'did not provide binding info.',
            );
        }

        try {
            $reply = $auth->doAuthentication();
            if ($hash !== null) {
                Logger::debug(sprintf(
                    'Negotiate - doAuthenticate(): Authentication with channel binding succeeded using hash; %s.',
                    $hash,
                ));
            } else {
                Logger::debug(
                    'Negotiate - doAuthenticate(): Authentication without channel binding succeeded.',
                );
            }
            return $reply;
        } catch (Exception $e) {
            Logger::debug(sprintf(
                'Negotiate - doAuthenticate(): Authentication with channel binding failed using hash; %s.',
                strval($hash),
            ));
            throw $e;
        }
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

        $ip = Request::createFromGlobals()->getClientIp() ?? '127.0.0.1';
        Assert::notNull($ip, "Unable to determine client IP.");

        if (IpUtils::checkIp($ip, $this->subnet)) {
            Logger::debug('Negotiate: Client "' . $ip . '" matched subnet.');
            return true;
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
        exit;
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
    public static function fallBack(array &$state): void // never
    {
        $authId = $state['LogoutState']['negotiate:backend'];
        if ($authId === null) {
            throw new Error\Error([500, "Unable to determine auth source."]);
        }

        /** @psalm-var \SimpleSAML\Auth\Source|null $source */
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
     * Looks up what attributes to fetch from SP metadata and searches the directory.
     *
     * @param string $uid The user identifier.
     *
     * @return array|null The attributes for the user or NULL if not found.
     */
    protected function lookupUserData(string $uid): ?array
    {
        /**
         * @var \SimpleSAML\Module\ldap\Auth\Source\Ldap|null $source
         * @psalm-var string $this->backend - We only reach this method when $this->backend is set
         */
        $source = Auth\Source::getById($this->backend);
        if ($source === null) {
            throw new Exception('Could not find authentication source with id ' . $this->backend);
        }

        try {
            return $source->getAttributes($uid);
        } catch (Error\Exception $e) {
            Logger::debug('Negotiate - ldap lookup failed: ' . $e);
            return null;
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
                throw new Exception('Could not find authentication source with id ' . $state[self::AUTHID]);
            }
            $source->logout($state);
        }
    }


    /**
     * @param string $hash
     * @return \GSSAPIChannelBinding
     */
    private function createBinding(string $hash): GSSAPIChannelBinding
    {
        $binding = new GSSAPIChannelBinding();
        $binding->setApplicationData(sprintf(
            '%s:%s',
            'tls-server-end-point',
            pack('H*', $hash),
        ));

        return $binding;
    }
}
