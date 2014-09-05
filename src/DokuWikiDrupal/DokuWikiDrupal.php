<?php
 /**
 * @file
 *
 * @author Dennis Brücke (blackice2999) | TWD - team:Werbedesign UG
 * @see http://drupal.org/user/413429
 * @see http://team-wd.de
 */

namespace AuthDrupalBS\DokuWikiDrupal;

use ezcDbHandler;

interface DokuWikiDrupal {
  public function __construct($conf, ezcDbHandler $db);
  public function user_authenticate($name, $pass);
  public function user_authenticate_http($name, $pass);
  public function check_session();
  public function user_load_by_name($user);
  public function getSessionName();
  public function setCookieDomain($cookie_domain);
}