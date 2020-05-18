<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\negotiate\Controller;

use Exception;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth\Source;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module\negotiate\Controller;
use SimpleSAML\Session;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * Set of tests for the controllers in the "negotiate" module.
 *
 * @package SimpleSAML\Test
 */
class NegotiateTest extends TestCase
{
    /** @var \SimpleSAML\Configuration */
    protected $config;

    /** @var \SimpleSAML\Logger */
    protected $logger;

    /** @var \SimpleSAML\Module */
    protected $module;

    /** @var \SimpleSAML\Session */
    protected $session;


    /**
     * Set up for each test.
     * @return void
     */
    protected function setUp()
    {
        parent::setUp();

        $this->config = Configuration::loadFromArray(
            [
                'module.enable' => ['negotiate' => true],
            ],
            '[ARRAY]',
            'simplesaml'
        );

        $this->session = Session::getSessionFromRequest();

        Configuration::setPreLoadedConfig($this->config, 'config.php');

        $this->logger = new class () extends Logger {
            /**
             * @param string $str
             * @return void
             */
            public static function debug($str)
            {
                // do nothing
            }
        };

        $this->module = new class () extends Module {
        };
    }


    /**
     * Test that a valid requests results in a Twig template
     * @return void
     */
    public function testEnable()
    {
        $request = Request::create(
            '/enable',
            'GET'
        );

        $c = new Controller\NegotiateController($this->config, $this->session);
        $c->setModule($this->module);

        /** @var \SimpleSAML\XHTML\Template $response */
        $response = $c->enable($request);

        // Validate response
        $this->assertInstanceOf(Template::class, $response);
        $this->assertTrue($response->isSuccessful());

        // Validate cookie
        /** @var non-empty-array $cookies */
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
     * @return void
     */
    public function testDisable()
    {
        $request = Request::create(
            '/disable',
            'GET'
        );

        $c = new Controller\NegotiateController($this->config, $this->session);
        $c->setModule($this->module);

        /** @var \SimpleSAML\XHTML\Template $response */
        $response = $c->disable($request);

        // Validate response
        $this->assertInstanceOf(Template::class, $response);
        $this->assertTrue($response->isSuccessful());

        // Validate cookie
        /** @var non-empty-array $cookies */
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
     * @return void
     * @throws \SimpleSAML\Error\BadRequest
     */
    public function testRetry()
    {
        $request = Request::create(
            '/retry',
            'GET',
            ['AuthState' => 'someState']
        );

        $c = new Controller\NegotiateController($this->config, $this->session);
        $c->setLogger($this->logger);
        $c->setAuthState(new class () extends State {
            public static function loadState($id, $stage, $allowMissing = false)
            {
                return [
                    'LogoutState' => [
                        'negotiate:backend' => 'foo'
                    ]
                ];
            }
        });

        /** @var \PHPUnit_Framework_MockObject_Builder_InvocationMocker $mdh */
        $mdh = $this->createMock(MetaDataStorageHandler::class);
        $mdh->method('getMetaDataCurrentEntityID')->willReturn('entityID');
        $mdh->method('getMetaData')->willReturn([
            'auth' => 'auth_source_id',
        ]);

        /** @psalm-suppress InvalidArgument */
        $c->setMetadataStorageHandler($mdh);
        $c->setAuthSource(new class () extends Source {
            public function __construct()
            {
                // stub
            }

            /**
             * @param array &$state
             * @return void
             */
            public function authenticate(&$state)
            {
                // stub
            }

            /**
             * @param string $authId
             * @param string|null $type
             * @return self
             */
            public static function getById($authId, $type = null)
            {
                return new static();
            }
        });

        $response = $c->retry($request);

        $this->assertInstanceOf(RunnableResponse::class, $response);
        $this->assertTrue($response->isSuccessful());
    }


    /**
     * Test that invalid metadata throws an Exception
     * @return void
     */
    public function testRetryInvalidMetadataThrowsException()
    {
        $request = Request::create(
            '/retry',
            'GET',
            ['AuthState' => 'someState']
        );

        $c = new Controller\NegotiateController($this->config, $this->session);
        $c->setLogger($this->logger);
        $c->setAuthState(new class () extends State {
            /**
             * @param string $id
             * @param string $stage
             * @param bool $allowMissing
             * @return array
             */
            public static function loadState($id, $stage, $allowMissing = false)
            {
                return [
                    'LogoutState' => [
                        'negotiate:backend' => 'foo'
                    ]
                ];
            }
        });

        /** @var \PHPUnit_Framework_MockObject_Builder_InvocationMocker $mdh */
        $mdh = $this->createMock(MetaDataStorageHandler::class);
        $mdh->method('getMetaDataCurrentEntityID')->willReturn('entityID');
        $mdh->method('getMetaData')->willReturn([
            'noauth' => 'auth_source_id',
        ]);
        /** @psalm-suppress InvalidArgument */
        $c->setMetadataStorageHandler($mdh);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Negotiate - retry - no "auth" parameter found in IdP metadata.');

        $c->retry($request);
    }


    /**
     * Test that an invalid authsource throws an Exception
     * @return void
     */
    public function testRetryInvalidAuthSourceThrowsException()
    {
        $request = Request::create(
            '/retry',
            'GET',
            ['AuthState' => 'someState']
        );

        $c = new Controller\NegotiateController($this->config, $this->session);
        $c->setLogger($this->logger);
        $c->setAuthState(new class () extends State {
            /**
             * @param string $id
             * @param string $stage
             * @param bool $allowMissing
             * @return array
             */
            public static function loadState($id, $stage, $allowMissing = false)
            {
                return [
                    'LogoutState' => [
                        'negotiate:backend' => 'foo'
                    ]
                ];
            }
        });

        /** @var \PHPUnit_Framework_MockObject_Builder_InvocationMocker $mdh */
        $mdh = $this->createMock(MetaDataStorageHandler::class);
        $mdh->method('getMetaDataCurrentEntityID')->willReturn('entityID');
        $mdh->method('getMetaData')->willReturn([
            'auth' => 'auth_source_id',
        ]);
        /** @psalm-suppress InvalidArgument */
        $c->setMetadataStorageHandler($mdh);

        $as = new class () extends Source {
            public function __construct()
            {
                // stub
            }

            /**
             * @param array &$state
             * @return void
             */
            public function authenticate(&$state)
            {
                // stub
            }

            /**
             * @param string $authId
             * @param string|null $type
             * @return null
             */
            public static function getById($authId, $type = null)
            {
                return null;
            }
        };
        $c->setAuthSource($as);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage('Invalid AuthId "auth_source_id" - not found.');

        $c->retry($request);
    }


    /**
     * Test that a missing AuthState results in a BadRequest-error
     * @return void
     * @throws \SimpleSAML\Error\BadRequest
     */
    public function testRetryMissingState()
    {
        $request = Request::create(
            '/retry',
            'GET'
        );

        $c = new Controller\NegotiateController($this->config, $this->session);
        $c->setLogger($this->logger);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage('BADREQUEST(\'%REASON%\' => \'Missing required AuthState query parameter.\')');

        $c->retry($request);
    }


    /**
     * Test that a valid requests results in a RunnableResponse
     * @return void
     * @throws Error\BadRequest
     * @throws Error\NoState
     */
    public function testBackend()
    {
        $request = Request::create(
            '/backend',
            'GET',
            ['AuthState' => 'someState']
        );

        $c = new Controller\NegotiateController($this->config, $this->session);
        $c->setLogger($this->logger);
        $c->setAuthState(new class () extends State {
            public static function loadState($id, $stage, $allowMissing = false)
            {
                return [
                    'LogoutState' => [
                        'negotiate:backend' => 'foo'
                    ]
                ];
            }
        });

        $response = $c->fallback($request);

        $this->assertInstanceOf(StreamedResponse::class, $response);
        $this->assertTrue($response->isSuccessful());
    }


    /**
     * Test that a missing AuthState results in a BadRequest-error
     * @return void
     * @throws Error\BadRequest
     * @throws Error\NoState
     */
    public function testBackendMissingState()
    {
        $request = Request::create(
            '/backend',
            'GET'
        );

        $c = new Controller\NegotiateController($this->config, $this->session);
        $c->setLogger($this->logger);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage('BADREQUEST(\'%REASON%\' => \'Missing required AuthState query parameter.\')');

        $c->fallback($request);
    }
}
