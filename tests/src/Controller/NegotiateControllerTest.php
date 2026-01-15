<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\negotiate\Controller;

use Exception;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth\Source;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module;
use SimpleSAML\Module\negotiate\Controller;
use SimpleSAML\Session;
use Symfony\Component\HttpFoundation\Request;

/**
 * Set of tests for the controllers in the "negotiate" module.
 *
 * @package SimpleSAML\Test
 * @psalm-suppress PropertyNotSetInConstructor
 */
final class NegotiateControllerTest extends TestCase
{
    protected Configuration $config;

    protected Logger $logger;

    protected Module $module;

    protected Session $session;


    /**
     * Set up for each test.
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->config = Configuration::loadFromArray(
            [
                'module.enable' => ['negotiate' => true],
            ],
            '[ARRAY]',
            'simplesaml',
        );

        $this->session = Session::getSessionFromRequest();

        Configuration::setPreLoadedConfig($this->config, 'config.php');

        $this->logger = new class () extends Logger {
            public static function debug(string $string): void
            {
                // do nothing
            }
        };

        $this->module = new class () extends Module {
        };
    }


    /**
     * Test that a valid requests results in a Twig template
     */
    public function testEnable(): void
    {
        $request = Request::create(
            '/enable',
            'GET',
        );

        $c = new Controller\NegotiateController($this->config, $this->session);
        $c->setModule($this->module);

        $response = $c->enable($request);

        // Validate response
        $this->assertTrue($response->isSuccessful());

        // Validate cookie
        /** @var non-empty-array<mixed> $cookies */
        $cookies = $response->headers->getCookies();
        foreach ($cookies as $cookie) {
            if ($cookie->getName() === 'NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT') {
                break;
            }
        }

        $this->assertEquals($cookie->getValue(), null);
        $this->assertEquals($cookie->getDomain(), null);
        $this->assertEquals($cookie->getPath(), '/');
        $this->assertEquals($expiration = $cookie->getExpiresTime(), mktime(0, 0, 0, 1, 1, 2038));
        $this->assertEquals($cookie->getMaxAge(), $expiration - time());
        $this->assertTrue($cookie->isSecure());
        $this->assertTrue($cookie->isHttpOnly());
    }


    /**
     * Test that a valid requests results in a Twig template
     */
    public function testDisable(): void
    {
        $request = Request::create(
            '/disable',
            'GET',
        );

        $c = new Controller\NegotiateController($this->config, $this->session);
        $c->setModule($this->module);

        $response = $c->disable($request);

        // Validate response
        $this->assertTrue($response->isSuccessful());

        // Validate cookie
        /** @var non-empty-array<mixed> $cookies */
        $cookies = $response->headers->getCookies();
        foreach ($cookies as $cookie) {
            if ($cookie->getName() === 'NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT') {
                break;
            }
        }

        $this->assertEquals($cookie->getValue(), 'true');
        $this->assertEquals($cookie->getDomain(), null);
        $this->assertEquals($cookie->getPath(), '/');
        $this->assertEquals($expiration = $cookie->getExpiresTime(), mktime(0, 0, 0, 1, 1, 2038));
        $this->assertEquals($cookie->getMaxAge(), $expiration - time());
        $this->assertTrue($cookie->isSecure());
        $this->assertTrue($cookie->isHttpOnly());
    }


    /**
     * Test that a valid requests results in a RunnableResponse
     * @throws \SimpleSAML\Error\BadRequest
     */
    public function testRetry(): void
    {
        $request = Request::create(
            '/retry',
            'GET',
            ['AuthState' => 'someState'],
        );

        $c = new Controller\NegotiateController($this->config, $this->session);
        $c->setLogger($this->logger);
        $c->setAuthState(new class () extends State {
            /** @return array<mixed> */
            public static function loadState(string $id, string $stage, bool $allowMissing = false): array
            {
                return [
                    'LogoutState' => [
                        'negotiate:backend' => 'foo',
                    ],
                ];
            }
        });

        $mdh = $this->createMock(MetaDataStorageHandler::class);
        $mdh->method('getMetaDataCurrentEntityID')->willReturn('entityID');
        $mdh->method('getMetaData')->willReturn([
            'auth' => 'auth_source_id',
        ]);

        $c->setMetadataStorageHandler($mdh);
        $c->setAuthSource(new class () extends Source {
            final public function __construct()
            {
                // stub
            }


            /** @param array<mixed> $state */
            public function authenticate(array &$state): void
            {
                // stub
            }


            public static function getById(string $authId, ?string $type = null): Source
            {
                return new static();
            }
        });

        $response = $c->retry($request);

        $this->assertTrue($response->isSuccessful());
    }


    /**
     * Test that invalid metadata throws an Exception
     */
    public function testRetryInvalidMetadataThrowsException(): void
    {
        $request = Request::create(
            '/retry',
            'GET',
            ['AuthState' => 'someState'],
        );

        $c = new Controller\NegotiateController($this->config, $this->session);
        $c->setLogger($this->logger);
        $c->setAuthState(new class () extends State {
            /** @return array<mixed> */
            public static function loadState(string $id, string $stage, bool $allowMissing = false): array
            {
                return [
                    'LogoutState' => [
                        'negotiate:backend' => 'foo',
                    ],
                ];
            }
        });

        $mdh = $this->createMock(MetaDataStorageHandler::class);
        $mdh->method('getMetaDataCurrentEntityID')->willReturn('entityID');
        $mdh->method('getMetaData')->willReturn([
            'noauth' => 'auth_source_id',
        ]);
        $c->setMetadataStorageHandler($mdh);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Negotiate - retry - no "auth" parameter found in IdP metadata.');

        $c->retry($request);
    }


    /**
     * Test that an invalid authsource throws an Exception
     */
    public function testRetryInvalidAuthSourceThrowsException(): void
    {
        $request = Request::create(
            '/retry',
            'GET',
            ['AuthState' => 'someState'],
        );

        $c = new Controller\NegotiateController($this->config, $this->session);
        $c->setLogger($this->logger);
        $c->setAuthState(new class () extends State {
            /** @return array<mixed> */
            public static function loadState(string $id, string $stage, bool $allowMissing = false): array
            {
                return [
                    'LogoutState' => [
                        'negotiate:backend' => 'foo',
                    ],
                ];
            }
        });

        $mdh = $this->createMock(MetaDataStorageHandler::class);
        $mdh->method('getMetaDataCurrentEntityID')->willReturn('entityID');
        $mdh->method('getMetaData')->willReturn([
            'auth' => 'auth_source_id',
        ]);
        $c->setMetadataStorageHandler($mdh);

        $as = new class () extends Source {
            public function __construct()
            {
                // stub
            }


            /** @param array<mixed> $state */
            public function authenticate(array &$state): void
            {
                // stub
            }


            public static function getById(string $authId, ?string $type = null): null
            {
                return null;
            }
        };
        $c->setAuthSource($as);

        $this->expectException(Error\BadRequest::class);
        $c->retry($request);
    }


    /**
     * Test that a missing AuthState results in a BadRequest-error
     * @throws \SimpleSAML\Error\BadRequest
     */
    public function testRetryMissingState(): void
    {
        $request = Request::create(
            '/retry',
            'GET',
        );

        $c = new Controller\NegotiateController($this->config, $this->session);
        $c->setLogger($this->logger);

        $this->expectException(Error\BadRequest::class);

        $c->retry($request);
    }


    /**
     * Test that a valid requests results in a RunnableResponse
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NoState
     */
    public function testBackend(): void
    {
        $request = Request::create(
            '/backend',
            'GET',
            ['AuthState' => 'someState'],
        );

        $c = new Controller\NegotiateController($this->config, $this->session);
        $c->setLogger($this->logger);
        $c->setAuthState(new class () extends State {
            /** @return array<mixed> */
            public static function loadState(string $id, string $stage, bool $allowMissing = false): array
            {
                return [
                    'LogoutState' => [
                        'negotiate:backend' => 'foo',
                    ],
                ];
            }
        });

        $response = $c->fallback($request);

        $this->assertTrue($response->isSuccessful());
    }


    /**
     * Test that a missing AuthState results in a BadRequest-error
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NoState
     */
    public function testBackendMissingState(): void
    {
        $request = Request::create(
            '/backend',
            'GET',
        );

        $c = new Controller\NegotiateController($this->config, $this->session);
        $c->setLogger($this->logger);

        $this->expectException(Error\BadRequest::class);

        $c->fallback($request);
    }
}
