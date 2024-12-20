# Negotiate module

![Build Status](https://github.com/simplesamlphp/simplesamlphp-module-negotiate/actions/workflows/php.yml/badge.svg)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/simplesamlphp/simplesamlphp-module-negotiate/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/simplesamlphp/simplesamlphp-module-negotiate/?branch=master)
[![Coverage Status](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-negotiate/branch/master/graph/badge.svg)](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-negotiate)
[![Type Coverage](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-negotiate/coverage.svg)](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-negotiate)
[![Psalm Level](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-negotiate/level.svg)](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-negotiate)

## Install

Install with composer

```bash
vendor/bin/composer require simplesamlphp/simplesamlphp-module-negotiate
```

## Configuration

Next thing you need to do is to enable the module:

in `config.php`, search for the `module.enable` key and set `negotiate` to true:

```php
    'module.enable' => [ 'negotiate' => true, … ],
```
