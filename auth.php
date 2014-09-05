<?php

/**
 * @file
 *
 * @author Dennis Brücke (blackice2999) | TWD - team:Werbedesign UG
 * @see http://drupal.org/user/413429
 * @see http://team-wd.de
 */

if (!defined('DOKU_INC')) {
  die();
}

require 'vendor/autoload.php';

/**
 * Class auth_plugin_authdrupalbs
 */
class auth_plugin_authdrupalbs extends DokuWiki_Auth_Plugin {

  /**
   * @var AuthDrupalBS\DokuWikiDrupal\DokuWikiDrupal;
   */
  var $drupal = NULL;

  var $db_connector = NULL;

  /**
   * @var array user cache
   */
  protected $users = null;

  public function __construct() {
    // User cant be created or deleted here... Use Drupal!
    $this->cando['addUser'] = false; // can Users be created?
    $this->cando['delUser'] = false; // can Users be deleted?

    // Modification of users and groups only on drupal not here!
    $this->cando['modLogin'] = false; // can login names be changed?
    $this->cando['modPass'] = false; // can passwords be changed?
    $this->cando['modName'] = false; // can real names be changed?
    $this->cando['modMail'] = false; // can emails be changed?
    $this->cando['modGroups'] = false; // can groups be changed?

    $this->cando['getUsers'] = false; // can a (filtered) list of users be retrieved?
    $this->cando['getUserCount'] = false; // can the number of users be retrieved?
    $this->cando['getGroups'] = false; // can a list of available groups be retrieved?
    $this->cando['external'] = true; // does the module do external auth checking?
    $this->cando['logout'] = false; // can the user logout again? (eg. not possible with HTTP auth)

    // Drupal7 Class need some configuration parameters
    $conf = array(
      'drupal_cookie_domain' => $this->getConf('drupal_cookie_domain'),
      'drupal_use_realname' => $this->getConf('drupal_use_realname'),
      'drupal_root' => $this->getConf('drupal_root'),
      'drupal_url' => $this->getConf('drupal_url'),
      'drupal_url_username' => $this->getConf('drupal_url_username'),
      'drupal_url_password' => $this->getConf('drupal_url_password'),
    );

    // Get Drupal Class from Factory
    $class = $this->getConf('drupal_factory_class');
    $this->drupal = $class::create($conf, $this->getDatabaseConnector());
  }

  /**
   * Implements trustExternal Method
   *
   * @param string $user
   * @param string $pass
   * @param bool $sticky
   * @return bool
   */
  public function trustExternal($user, $pass, $sticky = false) {
    global $USERINFO;
    global $lang;

    /**
     * User has submitted the login form so we are in a login moment
     */
    if (!empty($user)) {
      // Try to login user
      if ($cookie = $this->user_authenticate($user, $pass)) {
        /**
         * @var \Guzzle\Plugin\Cookie\Cookie $cookie
         */
        if ($cookie instanceof \Guzzle\Plugin\Cookie\Cookie) {
          setcookie(
            $cookie->getName(),
            $cookie->getValue(),
            $cookie->getExpires(),
            $cookie->getPath(),
            $cookie->getDomain(),
            $cookie->getSecure(),
            $cookie->getHttpOnly()
          );
        }
      }
      else {
        // Declined
        msg($lang['badlogin'], -1);
        auth_logoff(); // needs implementation of logOff() method
        return false;
      }
    }

    /**
     * Page load without form submission so we need to check the sessions
     */
    if ($drupal_user = $this->check_session($cookie)) {
      $USERINFO['name'] = $drupal_user->name;
      $USERINFO['mail'] = $drupal_user->mail;
      $USERINFO['grps'] = array();
      foreach ($drupal_user->roles as $role) {
        $USERINFO['grps'][] = $role;
      }

      // Drupal User 1 is admin!
      if ($drupal_user->uid == 1) {
        $USERINFO['grps'][] = 'admin';
      }

      $_SERVER['REMOTE_USER'] = $drupal_user->name;
      $_SESSION[DOKU_COOKIE]['auth']['user'] = $drupal_user->name;
      $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
      return true;
    }
    else {
      auth_logoff(); // needs implementation of logOff() method
      return false;
    }
  }

  /**
   * Get User Data of a specific user from Drupal database
   *
   * @param string $user
   * @return array
   */
  public function getUserData($user) {
    // Load user from drupal
    if (!$drupal_user = $this->drupal->user_load_by_name($user)) {
      return FALSE;
    }

    $userinfo = array(
      'pass' => '',
      'name' => ($drupal_user->realname) ? $drupal_user->realname : $drupal_user->name,
      'mail' => $drupal_user->mail,
      'grps' => array(),
    );

    foreach ($drupal_user->roles as $role) {
      $userinfo['grps'][] = $role;
    }

    // Drupal User 1 is admin!
    if ($drupal_user->uid == 1) {
      $userinfo['grps'][] = 'admin';
    }

    return $userinfo;
  }

  /**
   * Authenticate a username and password agains a drupal data
   *
   * @param $name
   * @param $pass
   * @return mixed
   */
  protected function user_authenticate($name, $pass) {
    return $this->drupal->user_authenticate_http($name, $pass);
  }

  /**
   * Check
   *
   * @return mixed
   */
  protected function check_session($cookie = NULL) {
    return $this->drupal->check_session($cookie);
  }

  /**
   * Initialise Database Connector and returns a instance of ezDbHandler
   *
   * @return \ezcDbHandler
   */
  protected function getDatabaseConnector() {
    if ($this->db_connector) {
      return $this->db_connector;
    }

    try {
      $this->db_connector = ezcDbFactory::create($this->getConf('drupal_database'));
    } catch (Exception $e) {
      msg('Database failed');
      return false;
    }
    return $this->db_connector;
  }
}
