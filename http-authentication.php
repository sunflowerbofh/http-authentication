<?php
/*
Plugin Name: HTTP Authentication
Version: 1.2
Plugin URI: http://dev.webadmin.ufl.edu/~dwc/2005/03/10/http-authentication-plugin/
Description: Authenticate users using basic HTTP authentication (<code>REMOTE_USER</code>). This plugin assumes users are externally authenticated (as with <a href="http://www.gatorlink.ufl.edu/">GatorLink</a>).
Author: Daniel Westermann-Clark
Author URI: http://dev.webadmin.ufl.edu/~dwc/
*/

add_action('admin_menu', array('HTTPAuthentication', 'admin_menu'));
add_action('wp_authenticate', array('HTTPAuthentication', 'authenticate'), 10, 2);
add_action('wp_login', array('HTTPAuthentication', 'login'));
add_action('wp_logout', array('HTTPAuthentication', 'logout'));
add_action('lost_password', array('HTTPAuthentication', 'disable_function'));
add_action('retrieve_password', array('HTTPAuthentication', 'disable_function'));
add_action('password_reset', array('HTTPAuthentication', 'disable_function'));
add_action('check_passwords', array('HTTPAuthentication', 'check_passwords'), 10, 3);
add_filter('show_password_fields', array('HTTPAuthentication', 'show_password_fields'));


if (is_plugin_page()) {
	$logout_uri = HTTPAuthentication::get_logout_uri();
?>
<div class="wrap">
  <h2>HTTP Authentication Options</h2>
  <form name="httpauthenticationoptions" method="post" action="options.php">
    <input type="hidden" name="action" value="update" />
    <input type="hidden" name="page_options" value="'http_authentication_logout_uri'" />
    <fieldset class="options">
      <label for="http_authentication_logout_uri">Logout URI</label>
      <input name="http_authentication_logout_uri" type="text" id="http_authentication_logout_uri" value="<?php echo htmlspecialchars($logout_uri) ?>" size="50" />
    </fieldset>
    <p class="submit">
      <input type="submit" name="Submit" value="Update Options &raquo;" />
    </p>
  </form>
</div>
<?php
}

if (! class_exists('HTTPAuthentication')) {
	class HTTPAuthentication {
		/*
		 * Add an options pane for this plugin.
		 */
		function admin_menu() {
			add_options_page('HTTP Authentication', 'HTTP Authentication', 9, __FILE__);
		}

		/*
		 * Return the logout URI from the database, creating the option
		 * if it doesn't exist.
		 */
		function get_logout_uri() {
			global $cache_nonexistantoptions;

			$logout_uri = get_settings('http_authentication_logout_uri');
			if (! $logout_uri or $cache_nonexistantoptions['http_authentication_logout_uri']) {
				$logout_uri = get_settings('siteurl');
				HTTPAuthentication::add_logout_uri_option($logout_uri);
			}

			return $logout_uri;
		}

		/*
		 * Add the logout URI option to the database.
		 */
		function add_logout_uri_option($logout_uri) {
			add_option('http_authentication_logout_uri', $logout_uri, 'The URI to which the user is redirected when she chooses "Logout".');
		}

		/*
		 * If the REMOTE_USER evironment is set, use it as the username.
		 * This assumes that you have externally authenticated the user.
		 */
		function authenticate($username, $password) {
			global $using_cookie, $wpdb;

			// Reset values from input ($_POST and $_COOKIE)
			$username = $password = '';

			if ($_SERVER['REMOTE_USER']) {
				$username = $_SERVER['REMOTE_USER'];

				// WordPress expects a double-MD5 hash, so MD5 the value in the database (MD5 of password generated in check_password)
				$password = $wpdb->get_var("SELECT MD5(user_pass) FROM $wpdb->users WHERE user_login = '$username'");
				if ($password) {
					// User is authorized; now force WordPress to use the generated password
					$using_cookie = true;
					wp_setcookie($username, $password, $using_cookie);
				}
				else {
					$username = $password = '';
				}
			}
		}

		/*
		 * Once WordPress has verified the login, set the redirect
		 * target appropriately. This is done because wp-login.php never
		 * sees a POST with the correct redirect_to variable, which
		 * breaks plugins like registered-only.
		 */
		function login($username) {
			global $redirect_to;

			if (! empty($_REQUEST['redirect_to'])) {
				$redirect_to = preg_replace('|[^a-z0-9-~+_.?#=&;,/:]|i', '', $_REQUEST['redirect_to']);
			}
		}

		/*
		 * Logout the user by redirecting them to the logout URI.
		 */
		function logout() {
			header('Location: ' . HTTPAuthentication::get_logout_uri());
			exit();
		}

		/*
		 * Generate a password for the user. This plugin does not
		 * require the user to enter this value, but we want to set it
		 * to something nonobvious.
		 */
		function check_passwords($username, $password1, $password2) {
			$password1 = $password2 = substr(md5(uniqid(microtime())), 0, 10);
		}

		/*
		 * Used to disable certain login functions, e.g. retrieving a
		 * user's password.
		 */
		function disable_function() {
			die('Disabled');
		}

		/*
		 * Used to disable certain display elements, e.g. password
		 * fields on profile screen.
		 */
		function show_password_fields($show_password_fields) {
			return false;
		}
	}
}
?>
