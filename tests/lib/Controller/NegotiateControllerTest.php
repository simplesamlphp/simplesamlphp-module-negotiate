<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\negotiate\Controller;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth\Source;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module\negotiate\Controller;
use SimpleSAML\Session;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;

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

    /** @var \SimpleSAML\Session */
    protected $session;


    /**
     * Set up for each test.
     * @return void
     */
    protected function setUp(): void
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

        $this->logger = new class() extends Logger {
            public static function debug(string $string): void
            { // do nothing
            }
        };
    }


    /**
     * Test that a valid requests results in a Twig template
     * @return void
     */
    public function testEnable(): void
    {
        $request = Request::create(
            '/enable',
            'GET'
        );

        $c = new Controller\NegotiateController($this->config, $this->session);

        /** @var \SimpleSAML\XHTML\Template $response */
        $response = $c->enable($request);

        // Validate response
        $this->assertInstanceOf(Template::class, $response);
        $this->assertTrue($response->isSuccessful());

        // Validate cookie
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
    public function testDisable(): void
    {
        $request = Request::create(
            '/disable',
            'GET'
        );

        $c = new Controller\NegotiateController($this->config, $this->session);

        /** @var \SimpleSAML\XHTML\Template $response */
        $response = $c->disable($request);

        // Validate response
        $this->assertInstanceOf(Template::class, $response);
        $this->assertTrue($response->isSuccessful());

        // Validate cookie
        $cookies = $response->headers->getCookies();
        foreach ($cookies as $cookie) {
            if ($cookie->getName() === 'NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT') {
                break;
            }
        }

        $this->assertEquals($cookie->getValue(), true);
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
    public function testRetry(): void
    {
        $request = Request::create(
            '/retry',
            'GET',
            ['AuthState' => 'someState']
        );

        $c = new Controller\NegotiateController($this->config, $this->session);
        $c->setLogger($this->logger);
        $c->setAuthState(new class() extends State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'LogoutState' => [
                        'negotiate:backend' => 'foo'
                    ]
                ];
            }
        });
        $mdh = $this->createMock(MetaDataStorageHandler::class);
        $mdh->method('getMetaDataCurrentEntityID')->willReturn('entityID');
        $mdh->method('getMetaData')->willReturn([
            'auth' => 'auth_source_id',
        ]);
        $c->setMetadataStorageHandler($mdh);
        $c->setAuthSource(new class() extends Source {
            public function __construct()
            { // stub
            }

            public function authenticate(array &$state): void
            { // stub
            }

            public static function getById(string $authId, ?string $type = null): ?Source
            {
                return new static();
            }
        });
        $response = $c->retry($request);

        $this->assertInstanceOf(RunnableResponse::class, $response);
        $this->assertTrue($response->isSuccessful());
    }


    /**
     * Test that a missing AuthState results in a BadRequest-error
     * @return void
     * @throws Error\BadRequest
     */
    public function testRetryMissingState(): void
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
    public function testBackend(): void
    {
        $request = Request::create(
            '/backend',
            'GET',
            ['AuthState' => 'someState']
        );

        $c = new Controller\NegotiateController($this->config, $this->session);
        $c->setLogger($this->logger);
        $c->setAuthState(new class() extends State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'LogoutState' => [
                        'negotiate:backend' => 'foo'
                    ]
                ];
            }
        });

        $response = $c->fallback($request);

        $this->assertInstanceOf(RunnableResponse::class, $response);
        $this->assertTrue($response->isSuccessful());
    }


    /**
     * Test that a missing AuthState results in a BadRequest-error
     * @return void
     * @throws Error\BadRequest
     * @throws Error\NoState
     */
    public function testBackendMissingState(): void
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
