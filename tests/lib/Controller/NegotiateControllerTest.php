<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\negotiate\Controller;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
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
    public function testRetry(): void
    {
        $request = Request::create(
            '/retry',
            'GET',
            ['AuthState' => 'someState'],
        );

        $c = new Controller\NegotiateController($this->config, $this->session);

        $response = $c->retry($request);

        $this->assertInstanceOf(RunnableResponse::class, $response);
        $this->assertTrue($response->isSuccessful());
    }
     */


    /**
     * Test that a missing AuthState results in a BadRequest-error
     * @return void
     */
    public function testRetryMissingState(): void
    {
        $request = Request::create(
            '/retry',
            'GET'
        );

        $c = new Controller\NegotiateController($this->config, $this->session);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage('BADREQUEST(\'%REASON%\' => \'Missing required AuthState query parameter.\')');

        $c->retry($request);
    }


    /**
     * Test that an invalid AuthState results in a NOSTATE-error
     * @return void
     */
    public function testRetryInvalidState(): void
    {
        $request = Request::create(
            '/retry',
            'GET',
            ['AuthState' => 'someState']
        );

        $c = new Controller\NegotiateController($this->config, $this->session);

        $this->expectException(Error\NoState::class);
        $this->expectExceptionMessage('NOSTATE');

        $c->retry($request);
    }


    /**
     * Test that a valid requests results in a RunnableResponse
     * @return void
    public function testBackend(): void
    {
        $request = Request::create(
            '/backend',
            'GET',
            ['AuthState' => 'someState'],
        );

        $c = new Controller\NegotiateController($this->config, $this->session);

        $response = $c->fallback($request);

        $this->assertInstanceOf(RunnableResponse::class, $response);
        $this->assertTrue($response->isSuccessful());
    }
     */


    /**
     * Test that a missing AuthState results in a BadRequest-error
     * @return void
     */
    public function testBackendMissingState(): void
    {
        $request = Request::create(
            '/backend',
            'GET'
        );

        $c = new Controller\NegotiateController($this->config, $this->session);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage('BADREQUEST(\'%REASON%\' => \'Missing required AuthState query parameter.\')');

        $c->fallback($request);
    }


    /**
     * Test that an invalid AuthState results in a NOSTATE-error
     * @return void
     */
    public function testBackendInvalidState(): void
    {
        $request = Request::create(
            '/backend',
            'GET',
            ['AuthState' => 'someState']
        );

        $c = new Controller\NegotiateController($this->config, $this->session);

        $this->expectException(Error\NoState::class);
        $this->expectExceptionMessage('NOSTATE');

        $c->fallback($request);
    }
}
