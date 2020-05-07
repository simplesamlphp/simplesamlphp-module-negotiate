<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\negotiate\Controller;

use PHPUnit\Framework\TestCase;
//use SimpleSAML\Auth;
use SimpleSAML\Configuration;
//use SimpleSAML\Error;
use SimpleSAML\Module\negotiate\Controller;
use SimpleSAML\Session;
use SimpleSAML\XHTML\Template;
//use Symfony\Component\HttpFoundation\Response;
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

        $c = new Controller\Negotiate($this->config, $this->session);

        /** @var \SimpleSAML\XHTML\Template $response */
        $response = $c->enable($request, null);

        $this->assertInstanceOf(Template::class, $response);
        $this->assertTrue($response->isSuccessful());
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

        $c = new Controller\Negotiate($this->config, $this->session);

        /** @var \SimpleSAML\XHTML\Template $response */
        $response = $c->disable($request, null);

        $this->assertInstanceOf(Template::class, $response);
        $this->assertTrue($response->isSuccessful());
    }
}
