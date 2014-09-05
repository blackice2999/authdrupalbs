<?php
/**
 * @file
 *
 * @author Dennis Brücke (blackice2999) | TWD - team:Werbedesign UG
 * @see http://drupal.org/user/413429
 * @see http://team-wd.de
 */

// Used by auth
$conf['drupal_factory_class'] = 'AuthDrupalBS\DokuWikiDrupal\DrupalFactory';
$conf['drupal_class'] = 'AuthDrupalBS\DokuWikiDrupal\Drupal7';

$conf['drupal_database'] = 'mysql://';
// Used by class
$conf['drupal_url'] = '';
$conf['drupal_url_username'] = '';
$conf['drupal_url_password'] = '';
$conf['drupal_cookie_domain'] = '';
$conf['drupal_use_realname'] = TRUE;
$conf['drupal_root'] = '../drupal';
