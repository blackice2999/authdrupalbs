<?php

$meta['drupal_factory_class'] = array('string', '_caution' => 'danger');
$meta['drupal_class'] = array('string', '_caution' => 'danger');

$meta['drupal_database'] = array('string', '_caution' => 'danger');
// Used by class
$meta['drupal_url'] = array('string', '_caution' => 'danger');
$meta['drupal_url_username'] = array('string'); // Used for httpauth
$meta['drupal_url_password'] = array('string'); // Used for httpauth

$meta['drupal_cookie_domain'] = array('string', '_caution' => 'danger');
$meta['drupal_use_realname'] = array('onoff');
$meta['drupal_root'] = array('string', '_caution' => 'danger');
