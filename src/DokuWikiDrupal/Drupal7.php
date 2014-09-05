<?php
/**
 * @file
 *
 * @author Dennis Brücke (blackice2999) | TWD - team:Werbedesign UG
 * @see http://drupal.org/user/413429
 * @see http://team-wd.de
 *
 * some pice of code based uppon drupal 7 session / password handling
 */

namespace AuthDrupalBS\DokuWikiDrupal;

use PDO;
use ezcDbHandler;
use ezcDbInstance;
use Guzzle\Http\Client as GuzzleClient;
use Guzzle\Plugin\Cookie\CookiePlugin as GuzzleCookiePlugin;


class Drupal7 implements DokuWikiDrupal {

  protected $session_prefix = NULL;
  protected $cookie_domain = NULL;
  protected $conf = array();
  /** @var string Contains the Session name */
  protected $session_name = NULL;
  /** @var bool|string If we are using https or http for cookie */
  protected $is_https = NULL;
  /** @var ezcDbInstance */
  protected $db = NULL;
  // Guzzle instances
  /** @var GuzzleClient */
  protected $httpClient = NULL;
  /** @var GuzzleCookiePlugin */
  protected $httpCookie = NULL;

  function __construct($conf, ezcDbHandler $db) {
    $this->conf = $conf;
    $this->db = $db;
    $this->session_prefix = ini_get('session.cookie_secure') ? 'SSESS' : 'SESS';
    $this->cookie_domain = $this->setCookieDomain($conf['drupal_cookie_domain']);

    $this->is_https = isset($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) == 'on';

    // Get Guzzle for login
    $this->httpCookie = new GuzzleCookiePlugin();
    $this->httpClient = new GuzzleClient($this->conf['drupal_url']);
    $this->httpClient->addSubscriber($this->httpCookie);

    // If we had a username and password for auth use it!s
    if (!empty($this->conf['drupal_url_username']) && !empty($this->conf['drupal_url_password'])) {
      $this->httpClient->setDefaultOption('auth', array(
        $this->conf['drupal_url_username'],
        $this->conf['drupal_url_password'],
        'Basic'
      ));
    }
  }

  /**
   * @param string $cookie_domain
   * @return string the cookie domain name
   */
  public function setCookieDomain($cookie_domain) {
    return $this->cookie_domain = trim($cookie_domain);
  }

  /**
   * Authenticate a user agains the drupal database
   *
   * @param $name
   * @param $password
   * @return bool
   */
  public function user_authenticate($name, $password) {
    $uid = FALSE;
    if (!empty($name) && !empty($password)) {
      $account = $this->user_load_by_name($name);
      if ($account) {
        // Allow alternate password hashing schemes.
        require_once $this->conf['drupal_root'] . '/includes/password.inc';
        if (user_check_password($password, $account)) {
          $uid = $account->uid;
        }
      }
    }
    return $uid;
  }

  /**
   * Authenticate a user agains a drupal over http post request
   * and forward cookie
   *
   * @param $name
   * @param $pass
   * @return bool|mixed
   */
  public function user_authenticate_http($name, $pass) {

    $this->httpClient->post('user', null, array(
      'name' => $name,
      'pass' => $pass,
      'form_id' => 'user_login',
    ))->send();

    $cookie = $this->httpCookie->getCookieJar()->all();
    return empty($cookie) ? FALSE : reset($cookie);
  }

  /**
   * Directly check a drupal user password hash
   *
   * @param $password
   * @param $account
   * @return bool
   */
  protected function user_check_password($password, $account) {
    // Password that need to be updated from Drupal are not supported here
    if (substr($account->pass, 0, 2) == 'U$') {
      return FALSE;
    }
    else {
      $stored_hash = $account->pass;
    }

    $type = substr($stored_hash, 0, 3);
    switch ($type) {
      case '$S$':
        // A normal Drupal 7 password using sha512.
        $hash = _password_crypt('sha512', $password, $stored_hash);
        break;
      case '$H$':
        // phpBB3 uses "$H$" for the same thing as "$P$".
      case '$P$':
        // A phpass password generated using md5.  This is an
        // imported password or from an earlier Drupal version.
        $hash = _password_crypt('md5', $password, $stored_hash);
        break;
      default:
        return FALSE;
    }
    return ($hash && $stored_hash == $hash);
  }

  /**
   * Check the current session of user
   *
   * @return
   * returns the Session User Object or FALSE
   */
  public function check_session($cookie = NULL) {
    $session_name = $this->getSessionName();
    // If we dont have any cookie the user is not logged in..
    if (!$_COOKIE[$session_name] && !$cookie) {
      return false;
    }

    if ($cookie) {
      /**
       * @var Cookie $cookie
       */
      $sid = $cookie->getValue();
    }
    else {
      $sid = $_COOKIE[$session_name];
    }

    $result = $this->session_load_by_id($sid);
    return ($result) ? $result : FALSE;
  }

  /**
   * Get User Session from Drupal Database
   *
   * @param $sid
   * @return mixed
   */
  protected function session_load_by_id($sid) {
    if ($this->is_https) {
      $user = "SELECT u.*, s.* FROM users u INNER JOIN sessions s ON u.uid = s.uid WHERE s.ssid = :sid";
    }
    else {
      $user = "SELECT u.*, s.* FROM users u INNER JOIN sessions s ON u.uid = s.uid WHERE s.sid = :sid";
    }

    $stmt = $this->db->prepare($user);
    $stmt->setFetchMode(PDO::FETCH_OBJ);
    $stmt->bindValue(':sid', $sid);
    $stmt->execute();
    $user = $stmt->fetchObject();

    if ($user && $user->uid > 0 && $user->status == 1) {
      // This is done to unserialize the data member of $user.
      $user->data = unserialize($user->data);

      // Add user roles
      $this->user_load_roles($user);
    }
    elseif ($user) {
      // The user is anonymous or blocked. Only preserve two fields from the
      // {sessions} table.
      $account = $this->drupal_anonymous_user();
      $account->session = $user->session;
      $account->timestamp = $user->timestamp;
      $user = $account;
    }
    else {
      // The session has expired.
      $user = $this->drupal_anonymous_user();
      $user->session = '';
    }

    return $user;
  }

  /**
   * Drupals session name is based upon domain name or settings.php cookiename variable
   * to find the correct drupal cookie we try rebuilding the cookie name and search for the right cookie
   */
  public function getSessionName() {
    if ($this->session_name) {
      return $this->session_name;
    }

    // Create base URL.
    $http_protocol = $this->is_https ? 'https' : 'http';
    $base_root = $http_protocol . '://' . $_SERVER['HTTP_HOST'];
    $base_url = $base_root;
    // $_SERVER['SCRIPT_NAME'] can, in contrast to $_SERVER['PHP_SELF'], not
    // be modified by a visitor.
    if ($dir = rtrim(dirname($_SERVER['SCRIPT_NAME']), '\/')) {
      $base_path = $dir;
      $base_url .= $base_path;
    }

    if ($this->cookie_domain) {
      // If the user specifies the cookie domain, also use it for session name.
      $session_name = $this->cookie_domain;
    }
    else {
      // Otherwise use $base_url as session name, without the protocol
      // to use the same session identifiers across HTTP and HTTPS.
      list(, $session_name) = explode('://', $base_url, 2);
    }

    return $this->session_name = $this->session_prefix . substr(hash('sha256', $session_name), 0, 32);
  }

  /**
   * Returns a anonymous user object
   *
   * @see https://api.drupal.org/api/drupal/includes%21bootstrap.inc/function/drupal_anonymous_user/7
   * @return stdClass
   */
  protected function drupal_anonymous_user() {
    $user = new \stdClass();
    $user->uid = 0;
    $user->roles = array();
    $user->roles[1] = 'anonymous user';
    $user->cache = 0;
    return $user;
  }

  /**
   * Loads most user data from Drupal database by name
   * @param $name
   */
  protected function user_load_by_name_multiple($name) {
    static $data = array();
    if (isset($data[$name])) {
      return $data[$name];
    }

    if ($this->conf['drupal_use_realname']) {
      $sql_query = "SELECT u.uid, u.pass, u.name, u.mail, r.realname FROM users u LEFT JOIN realname r ON u.uid = r.uid WHERE u.name = :name";
    }
    else {
      $sql_query = "SELECT u.uid, u.pass, u.name, u.mail FROM users u WHERE u.name = :name";
    }

    $stmt = $this->db->prepare($sql_query);
    $stmt->setFetchMode(PDO::FETCH_OBJ);
    $stmt->bindValue(':name', $name);
    $stmt->execute();

    foreach ($stmt as $key => $user) {
      $this->user_load_roles($user);

      $result[$user->uid] = $user;
    }

    return $result;
  }

  /**
   * Load a drupal user by name
   *
   * @param $name
   * @return bool|mixed
   */
  public function user_load_by_name($name) {
    $result = $this->user_load_by_name_multiple($name);
    return !empty($result) ? reset($result) : FALSE;
  }

  /**
   * Add user roles to user object by reference and returns the list of roles
   *
   * @param $user
   */
  protected function user_load_roles($user) {
    if (!$user) {
      return false;
    }
    // Assign roles
    $user->roles = array();
    $user->roles[2] = 'authenticated user';

    // Add roles element to $user.
    $stmt = $this->db->prepare("SELECT r.rid, r.name FROM role r INNER JOIN users_roles ur ON ur.rid = r.rid WHERE ur.uid = :uid");
    $stmt->bindValue(':uid', $user->uid);
    $stmt->execute();
    $roles_prepare = $stmt->fetchAll(PDO::FETCH_NUM);

    foreach ($roles_prepare as $row) {
      $user->roles[$row[0]] = $row[1];
    }

    return $user->roles;
  }
}

