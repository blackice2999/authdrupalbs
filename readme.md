# Drupal 7 Auth Plugin for Dokuwiki

## Installation

Download and install vendor dependencies with composer.

see: https://getcomposer.org/doc/00-intro.md

@todo

## How it works

This plugin needs access to the drupal database for cookie checking and use http requests for login sharing.

### Auth Check

This plugin checks the current user session agains the drupal database and confirm the login to dokuwiki.

### Login

If a user wants to log in the entered user data will be transmitted to drupal by a http request from dokuwiki to drupal.
The returned session will be proxied and transmitted back to the client.

## Sponsored by

This dokuwiki plugin is sponsored by:

![kaspermedia.de](http://www.kaspermedia.de/wp-content/uploads/2013/06/kaspermedia_logo.png)

http://www.kaspermedia.de