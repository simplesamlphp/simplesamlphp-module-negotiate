# Negotiate module

The Negotiate module implements Microsofts Kerberos SPNEGO mechanism.
It is intended to only support Kerberos and not NTLM which RFC4559
implements.

`negotiate:Negotiate`
: Authenticates users via HTTP authentication

## `negotiate:Negotiate`

Negotiate implements the following mechanics:

* Initiate HTTP_AUTHN with the client
* Authorize user against a LDAP directory
* Collect metadata from LDAP directory
* Fall back to other SimpleSamlPhp module for any client/user that
  fails to authenticate in the Negotiate module
* Check only clients from a certain subnet
* Supports enabling/disabling a client
* Supports multiple realm/ldap config for complex AD topology

In effect this module aims to extend the Microsoft AD SSO session to
the SAML IdP. (Or any other Kerberos domain) It doesn't work like this
of course but for the user the client is automatically authenticated
when an SP sends the client to the IdP. In reality Negotiate
authenticates the user via SPNEGO and issues a separate SAML session.
The Kerberos session against the Authentication Server is completely
separate from the SAML session with the IdP. The only time the
Kerberos session affects the SAML session is at authN at the IdP.

The module is meant to supplement existing auth modules and not
replace them. Users do not always log in on the IdP from a machine in
the Windows domain (or another Kerberos domain) and from their own
domain accounts. A fallback mechanism must be supplemented.

The Kerberos TGS can be issued for a wide variety of accounts so an
authoriation backend via LDAP is needed. If the search, with filters,
fails, the fallback in invoked. This to prevent kiosk accounts and the
likes to get faulty SAML sessions.

The subnet is required to prevent excess attempts to authenticate via
Kerberos for clients that always will fail. Worst case scenario the
browser will prompt the user for u/p in a popup box that will always
fail. Only when the user clicks cancel the proper login process will
continue. This is handled through the body of the 401 message the
client receives with the Negotiate request. In the body a URL to the
fallback mechanism is supplied and Javascript is used to redirect the
client.

All configuration is handled in authsources.php:

```php
'weblogin' => [
    'negotiate:Negotiate',
    'keytab' => '/path/to/keytab-file',
    'realms' => [
        '*' => 'ldap',
    ],
    'allowedCertificateHashes' => [],
    'fallback' => 'crypto-hash',
    'spn' => null,
],
'ldap' => [
    'ldap:LDAP',
    'hostname' => 'ldap.example.com',
    'enable_tls' => true,
    'dnpattern' => 'uid=%username%,cn=people,dc=example,dc=com',
    'search.enable' => false,
],
'crypto-hash' => [
    'authcrypt:Hash',
    // hashed version of 'verysecret', made with bin/pwgen.php
    'professor:{SSHA256}P6FDTEEIY2EnER9a6P2GwHhI5JDrwBgjQ913oVQjBngmCtrNBUMowA==' => [
        'uid' => ['prof_a'],
        'eduPersonAffiliation' => ['member', 'employee', 'board'],
    ],
]
```

### `php_krb5`

The processing involving the actual Kerberos ticket handling is done
by php_krb5.

NOTE! If running using virtual hosts or behind a reverse proxy, you
might need to change the 'spn' variable to 0 (match any entry in the
keytab file) or set it to the specific entry you are trying to match.

```php
'spn' => 'HTTP/host',

'spn' => 0,
```

Depending on you apache config you may need a rewrite rule to allow
php_krb5 to read the HTTP_AUTHORIZATION header:

```apacheconf
RewriteEngine on
RewriteCond %{HTTP:Authorization}  !^$
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization},L]
```

Test the Kerberos setup with the following script:

```php
if(!extension_loaded('krb5')) {
    die('KRB5 Extension not installed');
}

if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
    list($mech, $data) = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
    if (strtolower($mech) == 'basic') {
        echo "Client sent basic";
        die('Unsupported request');
    } else if(strtolower($mech) != 'negotiate') {
        echo "Couldn't find negotiate";
        die('Unsupported request');
    }

    $auth = new KRB5NegotiateAuth('/path/to/keytab');
    $reply = '';
    if ($reply = $auth->doAuthentication()) {
        header('HTTP/1.1 200 Success');
        echo 'Success - authenticated as ' . $auth->getAuthenticatedUser() . '<br>';
    } else {
        echo 'Failed to authN.';
        die();
    }
} else {
    header('HTTP/1.1 401 Unauthorized');
    header('WWW-Authenticate: Negotiate',false);
    echo 'Not authenticated. No HTTP_AUTHORIZATION available.';
    echo 'Check headers sent by the browser and verify that ';
    echo 'apache passes them to PHP';
}
```

### LDAP

LDAP is used to verify the user due to the lack of metadata in
Kerberos. A domain can contain lots of kiosk users, non-personal
accounts and the likes. The LDAP lookup will authorize and fetch
attributes as defined by SimpleSAMLphp metadata.

Read the documentation of the LDAP auth module for more information.

This module supports using several Kerberos realms. This requires you to
specify an LDAP configuration for each Kerberos realm that may be used.
If you're using only one realm (one AD domain for example) then you could
let your ldap configuration with the magic "*" key. For multi realms the
syntax is :

```php
'weblogin' => [
    'negotiate:Negotiate',
    ...
    'realms' => [
        'realm1' => 'backend for realm1',
        'realm2' => 'backend for realm2',
        '*' => 'backend for any other realm',
    ],
],
```

### Subnet filtering

Subnet is meant to filter which clients you subject to the
WWW-Authenticate request.

Syntax is:

```php
'subnet' => [ '127.0.0.0/16','192.168.0.0/16' ],
```

Browsers, especially IE, behave erratically when they encounter a
WWW-Authenticate from the webserver. Included in RFC4559 Negotiate is
NTLM authentication which IE seems prone to fall back to under various
conditions. This triggers a popup login box which defeats the whole
purpose of this module.

TBD: Replace or supplement with LDAP lookups in the domain. Machines
currently in the domain should be the only ones that are prompted with
WWW-Authenticate: Negotiate.

### Enabling/disabling Negotiate from a web browser

Included in Negotiate are semi-static web pages for enabling and
disabling Negotiate for any given client. The pages simplly set/delete
a cookie that Negotiate will look for when a client attempts AuthN.
The help text in the JSON files should be locally overwritten to fully
explain which clients are accepted by Negotiate.

### Channel binding

A shortage of Kerberos-over-HTTP is that there are no distinguished SPN's for HTTP- and HTTPS-services [1][1].
This means that a ticket that's being transmitted over an insecure HTTP-connection can also be used for
HTTPS-connections to the same host. Besides this, Kerberos is also known to be vulnerable for MitM-attacks
where the service-label of the SPN can be altered when an alternative service is available on the same host [2][2].

[1]: https://techcommunity.microsoft.com/t5/iis-support-blog/how-to-use-spns-when-you-configure-web-applications-thatare/ba-p/324648
[2]: https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html

To prevent this, certificate-based channel binding is supported by this module as of version v1.1.6.
Syntax for this is:

```php
'enforceChannelBinding' => true,
'allowedCertificateHashes' => [<SHA-256 finterprint 1>, <SHA-256 fingerprint 2>],
```

Usually this array will contain just the one fingerprint for the current HTTPS-certificate of this IdP, but multiple can be
used in a certificate-rollover situation.
If the `enforceChannelBinding` setting is set to `true`, clients that do not provide binding-info will automatically be sent
to the fallback authsource.

### Logout/Login loop and reauthenticating

Due to the automatic AuthN of certain clients and how SPs will
automatically redirect clients to the IdP when clients try to access
restricted content, a session variable has been put into Negotiate. This
variable makes sure Negotiate doesn't reautenticate a recently logged
out user. The consequence of this is that the user will be presented
with the login mechanism of the fallback module specified in Negotiate
config.

SimpleSamlPHP offers no decent way of adding hooks or piggyback this
information to the fallback module. In future releases one might add a
box of information to the user explaining what's happening.

One can add this bit of code to the template in the fallback AuthN
module:

```php
// This should be placed in your www script
$nego_session = false;
$nego_perm = false;
$nego_retry = null;

if (array_key_exists('negotiate:authId', $state)) {
    $nego = \SimpleSAML\Auth\Source::getById($state['negotiate:authId']);
    $mask = $nego->checkMask();
    $disabled = $nego->spDisabledInMetadata($spMetadata);
    $session_disabled = $session->getData('negotiate:disable', 'session');

    if ($mask and !$disabled) {
        if (array_key_exists('NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT', $_COOKIE) &&
           $_COOKIE['NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT'] == 'True') {
            $nego_perm = true;
        } elseif ($session_disabled) {
            $retryState = \SimpleSAML\Auth\State::cloneState($state);
            unset($retryState[\SimpleSAML\Auth\State::ID]);
            $nego_retry = \SimpleSAML\Auth\State::saveState($retryState, '\SimpleSAML\Module\negotiate\Auth\Source\Negotiate.StageId');
            $nego_session = true;
        }
    }
}
    
// This should reside in your template
if ($this->data['nego']['disable_perm']) {
    echo '<span id="login-extra-info-uio.no" class="login-extra-info">'
          . '<span class="login-extra-info-divider"></span>'
          . $this->t('{feide:login:login_uio_negotiate_disabled_permanent_info}')
          . '</span>';
} elseif ($this->data['nego']['disable_session']) {
     echo '<span id="login-extra-info-uio.no" class="login-extra-info">'
          . '<span class="login-extra-info-divider"></span>'
          . $this->t('{feide:login:login_uio_negotiate_disabled_session_info}')
          . '<br><a href="'.SimpleSAML\Module::getModuleURL('negotiate/retry.php', [ 'AuthState' => $this->data['nego']['retry_id'] ]).'">'
          . $this->t('{feide:login:login_uio_negotiate_disabled_session_info_link}')
          . '</a>'
          . '</span>';
}
```

The above may or may not work right out of the box for you but it is
the gist of it. By looking at the state variable, cookie and checking
for filters and the likes, only clients that are subjected to
Negotiate should get the help text.

Note that with Negotiate there is also a small script to allow the
user to re-authenticate with Negotiate after being sent to the
fallback mechanism due to the session cookie. In the example above you
can see the construction of the URL. The cloning of the current state
is necessary for retry.php to load a state without triggering a
security check in SSP's state handling library. If you omit this and
pass on the original state you will see a warning in the log like
this:

```plain text
Sep 27 13:47:36 simplesamlphp WARNING [b99e6131ee] Wrong stage in state. Was 'foo', should be '\SimpleSAML\Module\negotiate\Auth\Source\Negotiate.StageId'.
```

It will work as loadState will take control and call
Negotiate->authenticate() but remaining code in retry.php will be
discarded. Other side-effects may occur.

### Clients

#### Internet Explorer

YMMV but generally you need to have your IdP defined in "Internet
Options" -> "Security" -> "Local intranet" -> "Sites" -> "Advanced".
You also need "Internet Options" -> "Advanced" -> "Security" -> Enable
Integrated Windows Authentication" enabled.

#### Firefox

Open "about:config". Locate "network.auth.use-sspi" and verify that
this is true (on a Windows machine). Next locate
"network.negotiate-auth.trusted-uris" and insert your IdP.

#### Safari

TODO

#### Chromium

To allow Kerberos SPN generation on Linux-based platforms, add the
following line to /etc/chromium.d/default-flags:

```bash
export CHROMIUM_FLAGS="$CHROMIUM_FLAGS --auth-server-whitelist=.example.com"
```
