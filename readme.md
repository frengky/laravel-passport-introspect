# Laravel Passport Token Introspection

## Introduction
This package add token introspection endpoint ([RFC 7662](https://tools.ietf.org/html/rfc7662)) for your [Laravel Passport](https://laravel.com/docs/passport) OAuth2 implementation.

### Requirements
* Laravel Passport 10.x

## Installation

1. Installing the package
```console
$ composer require frengky/laravel-passport-introspect
```
2. Add the service provider to your `config/app.php`
```
\Frengky\PassportIntrospect\ServiceProvider::class
```
From now on the introspection endpoint route is available to access
> POST /api/oauth2/introspect

Example:
```console
curl -X POST -d 'token=hKustjeCOOSXC....' http://localhost/api/oauth2/introspect
```
Result:
```json
{
  "active": true,
  "scope": "",
  "client_id": "93048e9a-f227-47ad-91f2-9630fd77fe0a",
  "sub": "1",
  "exp": 1616481476,
  "iat": 1616477876,
  "nbf": 1616477876,
  "aud": [
	"93048e9a-f227-47ad-91f2-9630fd77fe0a"
  ],
  "iss": "",
  "token_type": "Bearer",
  "token_use": "access_token",
  "jti": "58eb3b4824891f4621075fbbbbd825fd4bf7c49e9c364d4fa4069ea62fe7b8a043a92bfa278612e6"
}
```