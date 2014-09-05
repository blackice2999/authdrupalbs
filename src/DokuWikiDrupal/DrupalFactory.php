<?php
/**
 * @file
 *
 * @author Dennis Brücke (blackice2999) | TWD - team:Werbedesign UG
 * @see http://drupal.org/user/413429
 * @see http://team-wd.de
 */


namespace AuthDrupalBS\DokuWikiDrupal;

class DrupalFactory {
  static public function create(array $conf, \ezcDbHandler $db_connector, $class = 'AuthDrupalBS\DokuWikiDrupal\Drupal7') {
    return new $class($conf, $db_connector);
  }
}