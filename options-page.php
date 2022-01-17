<?php

/*
Copyright (C) 2011-2012 Daniel Westermann-Clark <daniel@danieltwc.com>
Copyright (C) 2022 Katharina Drexel <katharina.drexel@bfh.ch>

SPDX-License-Identifier: GPL-2.0+

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

class HTTPAuthenticationOptionsPage {
	var $plugin;
	var $group;
	var $page;
	var $options;
	var $title;

	function __construct($plugin, $group, $page, $options, $title = 'HTTP Authentication') {
		$this->plugin = $plugin;
		$this->group = $group;
		$this->page = $page;
		$this->options = $options;
		$this->title = $title;

		add_action('admin_init', array($this, 'register_options'));
		add_action('admin_menu', array($this, 'add_options_page'));
	}

	/*
	 * Register the options for this plugin so they can be displayed and updated below.
	 */
	function register_options() {
		register_setting($this->group, $this->group, array($this, 'sanitize_settings'));

		$section = 'http_authentication_main';
		add_settings_section($section, 'Main Options', array($this, '_display_options_section'), $this->page);
		add_settings_field('http_authentication_allow_wp_auth', 'Allow WordPress authentication?', array($this, '_display_option_allow_wp_auth'), $this->page, $section, array('label_for' => 'http_authentication_allow_wp_auth'));
		add_settings_field('http_authentication_auth_label', 'Authentication label', array($this, '_display_option_auth_label'), $this->page, $section, array('label_for' => 'http_authentication_auth_label'));
		add_settings_field('http_authentication_login_uri', 'Login URI', array($this, '_display_option_login_uri'), $this->page, $section, array('label_for' => 'http_authentication_login_uri'));
		add_settings_field('http_authentication_logout_uri', 'Logout URI', array($this, '_display_option_logout_uri'), $this->page, $section, array('label_for' => 'http_authentication_logout_uri'));
		add_settings_field('http_authentication_additional_server_keys', '$_SERVER variables', array($this, '_display_option_additional_server_keys'), $this->page, $section, array('label_for' => 'http_authentication_additional_server_keys'));
		add_settings_field('http_authentication_auto_create_user', 'Automatically create accounts?', array($this, '_display_option_auto_create_user'), $this->page, $section, array('label_for' => 'http_authentication_auto_create_user'));
		add_settings_field('http_authentication_auto_create_email_domain', 'Email address domain', array($this, '_display_option_auto_create_email_domain'), $this->page, $section, array('label_for' => 'http_authentication_auto_create_email_domain'));
		$section2 = 'ldap_authentication_main';
		add_settings_section($section2, 'LDAP Options', array($this, '_display_ldap_options_section'), $this->page);
		add_settings_field('http_authentication_allow_ldap', 'Activate LDAP group-role mapping?', array($this, '_display_option_allow_ldap'), $this->page, $section2, array('label_for' => 'http_authentication_allow_ldap'));
		add_settings_field('http_authentication_ldap_protocol', 'LDAP protocol (usually ldap or ldaps)', array($this, '_display_option_ldap_protocol'), $this->page, $section2, array('label_for' => 'http_authentication_ldap_protocol'));
		add_settings_field('http_authentication_ldap_server', 'LDAP server (FQDN)', array($this, '_display_option_ldap_server'), $this->page, $section2, array('label_for' => 'http_authentication_ldap_server'));
		add_settings_field('http_authentication_ldap_port', 'LDAP port', array($this, '_display_option_ldap_port'), $this->page, $section2, array('label_for' => 'http_authentication_ldap_port'));
		add_settings_field('http_authentication_ldap_version', 'LDAP version', array($this, '_display_option_ldap_version'), $this->page, $section2, array('label_for' => 'http_authentication_ldap_version'));
		add_settings_field('http_authentication_ldap_user', 'LDAP user', array($this, '_display_option_ldap_user'), $this->page, $section2, array('label_for' => 'http_authentication_ldap_user'));
		add_settings_field('http_authentication_ldap_password', 'LDAP password', array($this, '_display_option_ldap_password'), $this->page, $section2, array('label_for' => 'http_authentication_ldap_password'));
		add_settings_field('http_authentication_ldap_search_base', 'LDAP search base', array($this, '_display_option_ldap_search_base'), $this->page, $section2, array('label_for' => 'http_authentication_ldap_search_base'));
		add_settings_field('http_authentication_ldap_group_dn', 'LDAP group DN', array($this, '_display_option_ldap_group_dn'), $this->page, $section2, array('label_for' => 'http_authentication_ldap_group_dn'));
		add_settings_field('http_authentication_ldap_admin_group', 'LDAP administrator group', array($this, '_display_option_ldap_admin_group'), $this->page, $section2, array('label_for' => 'http_authentication_ldap_admin_group'));
		add_settings_field('http_authentication_ldap_editor_group', 'LDAP editor group', array($this, '_display_option_ldap_editor_group'), $this->page, $section2, array('label_for' => 'http_authentication_ldap_editor_group'));
		add_settings_field('http_authentication_ldap_author_group', 'LDAP author group', array($this, '_display_option_ldap_author_group'), $this->page, $section2, array('label_for' => 'http_authentication_ldap_author_group'));
	}

	/*
	 * Set the database version on saving the options.
	 */
	function sanitize_settings($input) {
		$output = $input;
		$output['db_version'] = $this->plugin->db_version;
		$output['allow_wp_auth'] = isset($input['allow_wp_auth']) ? (bool) $input['allow_wp_auth'] : false;
		$output['allow_ldap'] = isset($input['allow_ldap']) ? (bool) $input['allow_ldap'] : false;
		$output['auto_create_user'] = isset($input['auto_create_user']) ? (bool) $input['auto_create_user'] : false;

		return $output;
	}

	/*
	 * Add an options page for this plugin.
	 */
	function add_options_page() {
		add_options_page($this->title, $this->title, 'manage_options', $this->page, array($this, '_display_options_page'));
	}

	/*
	 * Display the options for this plugin.
	 */
	function _display_options_page() {
		if (! current_user_can('manage_options')) {
			wp_die(__('You do not have sufficient permissions to access this page.'));
		}
?>
<div class="wrap">
  <h2>HTTP Authentication Options</h2>
  <p>For the Login URI and Logout URI options, you can use the following variables to support your installation:</p>
  <ul>
    <li><code>%host%</code> - The current value of <code>$_SERVER['HTTP_HOST']</code></li>
    <li><code>%base%</code> - The base domain URL (everything before the path)</li>
    <li><code>%site%</code> - The WordPress home URI</li>
    <li><code>%redirect%</code> - The return URI provided by WordPress</li>
  </ul>
  <p>You can also use <code>%host_encoded%</code>, <code>%site_encoded%</code>, and <code>%redirect_encoded%</code> for URL-encoded values.</p>
  <form action="options.php" method="post">
    <?php settings_errors(); ?>
    <?php settings_fields($this->group); ?>
    <?php do_settings_sections($this->page); ?>
    <p class="submit">
      <input type="submit" name="Submit" value="<?php esc_attr_e('Save Changes'); ?>" class="button-primary" />
    </p>
  </form>
</div>
<?php
	}

	/*
	 * Display explanatory text for the main options section.
	 */
	function _display_options_section() {
	}
	/*
	 * Display explanatory text for the ldap options section.
	 */
	function _display_ldap_options_section() {
?>
Mapping roles to LDAP groups (optional). Works only if the wordpress server can connect to an LDAP server. If no group matches user is put into default role.
<?php
	}

	/*
	 * Display the WordPress authentication checkbox.
	 */
	function _display_option_allow_wp_auth() {
		$allow_wp_auth = $this->options['allow_wp_auth'];
		$this->_display_checkbox_field('allow_wp_auth', $allow_wp_auth);
?>
Should the plugin fallback to WordPress authentication if none is found from the server?
<?php
		if ($allow_wp_auth && $this->options['login_uri'] == htmlspecialchars_decode(wp_login_url())) {
			echo '<br /><strong>WARNING</strong>: You must set the login URI below to your external authentication system. Otherwise you will not be able to login!';
		}
	}

	/*
	 * Display the authentication label field, describing the authentication system
	 * in use.
	 */
	function _display_option_auth_label() {
		$auth_label = $this->options['auth_label'];
		$this->_display_input_text_field('auth_label', $auth_label);
?>
Default is <code>HTTP authentication</code>; override to use the name of your single sign-on system.
<?php
	}

	/*
	 * Display the login URI field.
	 */
	function _display_option_login_uri() {
		$login_uri = $this->options['login_uri'];
		$this->_display_input_text_field('login_uri', $login_uri);
?>
Default is <code><?php echo wp_login_url(); ?></code>; override to direct users to a single sign-on system. See above for available variables.<br />
Example: <code>%base%/Shibboleth.sso/Login?target=%redirect_encoded%</code>
<?php
	}

	/*
	 * Display the logout URI field.
	 */
	function _display_option_logout_uri() {
		$logout_uri = $this->options['logout_uri'];
		$this->_display_input_text_field('logout_uri', $logout_uri);
?>
Default is <code><?php echo htmlspecialchars(remove_query_arg('_wpnonce', htmlspecialchars_decode(wp_logout_url()))); ?></code>; override to e.g. remove a cookie. See above for available variables.<br />
Example: <code>%base%/Shibboleth.sso/Logout?return=%redirect_encoded%</code>
<?php
	}

	/*
	 * Display the additional $_SERVER keys field.
	 */
	function _display_option_additional_server_keys() {
		$additional_server_keys = $this->options['additional_server_keys'];
		$this->_display_input_text_field('additional_server_keys', $additional_server_keys);
?>
<code>$_SERVER</code> variables in addition to <code>REMOTE_USER</code> and <code>REDIRECT_REMOTE_USER</code> to check for the username value, separated by a comma. Use this to e.g. support personal X.509 certificates for authentication.<br />
Example: <code>SSL_CLIENT_S_DN_CN</code>
<?php
	}

	/*
	 * Display the automatically create accounts checkbox.
	 */
	function _display_option_auto_create_user() {
		$auto_create_user = $this->options['auto_create_user'];
		$this->_display_checkbox_field('auto_create_user', $auto_create_user);
?>
Should a new user be created automatically if not already in the WordPress database?<br />
Created users will obtain the role defined under &quot;New User Default Role&quot; on the <a href="options-general.php">General Options</a> page.
<?php
	}

	/*
	 * Display the email domain field.
	 */
	function _display_option_auto_create_email_domain() {
		$auto_create_email_domain = $this->options['auto_create_email_domain'];
		$this->_display_input_text_field('auto_create_email_domain', $auto_create_email_domain);
?>
When a new user logs in, this domain is used for the initial email address on their account. The user can change his or her email address by editing their profile.
<?php
	}

	/*
	 * Display the LDAP mapping checkbox.
	 */
	function _display_option_allow_ldap() {
		$allow_ldap = $this->options['allow_ldap'];
		$this->_display_checkbox_field('allow_ldap', $allow_ldap);
?>
Activate ldap group to role mapping?
<?php
		if ($allow_ldap ) {
			echo '<br /><strong>Hint:</strong> You must set at least the LDAP server and define one group.';
		}
	}

	/*
	 * Display the LDAP protocol field
	 */
	function _display_option_ldap_protocol() {
		$ldap_protocol = $this->options['ldap_protocol'];
		$this->_display_input_text_field('ldap_protocol', $ldap_protocol);
?>
Default is <code>ldaps</code>; use <code>ldap</code> when the server has no encryption.
<?php
	}

	/*
	 * Display the LDAP server field
	 */
	function _display_option_ldap_server() {
		$ldap_server = $this->options['ldap_server'];
		$this->_display_input_text_field('ldap_server', $ldap_server);
?>
Fully qualified LDAP server name (e.g. ldap.example.com)
<?php
	}

	/*
	 * Display the LDAP server field
	 */
	function _display_option_ldap_port() {
		$ldap_port = $this->options['ldap_port'];
		$this->_display_input_text_field('ldap_port', $ldap_port);
?>
LDAP port, usually 389 or 636
<?php
	}

	/*
	 * Display the LDAP version field
	 */
	function _display_option_ldap_version() {
		$ldap_version = $this->options['ldap_version'];
		$this->_display_input_text_field('ldap_version', $ldap_version);
?>
LDAP version, mostly you can leave it at 3.
<?php
	}

	/*
	 * Display the LDAP user field
	 */
	function _display_option_ldap_user() {
		$ldap_user = $this->options['ldap_user'];
		$this->_display_input_text_field('ldap_user', $ldap_user);
?>
User for LDAP bind, leave empty for anonymous bind.
<?php
	}

	/*
	 * Display the LDAP password field
	 */
	function _display_option_ldap_password() {
		$ldap_password = $this->options['ldap_password'];
		$this->_display_input_password_field('ldap_password', $ldap_password);
?>
Password for LDAP user, leave empty for anonymous bind.
<?php
	}

	/*
	 * Display the LDAP search base field
	 */
	function _display_option_ldap_search_base() {
		$ldap_search_base = $this->options['ldap_search_base'];
		$this->_display_input_text_field('ldap_search_base', $ldap_search_base);
?>
LDAP search base
<?php
	}

	/*
	 * Display the LDAP group dn field
	 */
	function _display_option_ldap_group_dn() {
		$ldap_group_dn = $this->options['ldap_group_dn'];
		$this->_display_input_text_field('ldap_group_dn', $ldap_group_dn);
?>
LDAP group DN. Will be concatenated with LDAP groups below (can be left empty when you want to use LDAP groups from different trees; in that case you have to enter the full path within each ldap group field).
<?php
	}

	/*
	 * Display the LDAP admin group field
	 */
	function _display_option_ldap_admin_group() {
		$ldap_admin_group = $this->options['ldap_admin_group'];
		$this->_display_input_text_field('ldap_admin_group', $ldap_admin_group);
?>
LDAP group which should be mapped to the role 'administrator'. Can be full LDAP tree or only cn (if LDAP group field is set). Leave empty when you don't want that role.
<?php
	}

	/*
	 * Display the LDAP editor group field
	 */
	function _display_option_ldap_editor_group() {
		$ldap_editor_group = $this->options['ldap_editor_group'];
		$this->_display_input_text_field('ldap_editor_group', $ldap_editor_group);
?>
LDAP group which should be mapped to the role 'editor' (leave empty when you don't want that role).
<?php
	}

	/*
	 * Display the LDAP author group field
	 */
	function _display_option_ldap_author_group() {
		$ldap_author_group = $this->options['ldap_author_group'];
		$this->_display_input_text_field('ldap_author_group', $ldap_author_group);
?>
LDAP group which should be mapped to the role 'author' (leave empty when you don't want that role).
<?php
	}

	/*
	 * Display a text input field.
	 */
	function _display_input_text_field($name, $value, $size = 75) {
?>
<input type="text" name="<?php echo htmlspecialchars($this->group); ?>[<?php echo htmlspecialchars($name); ?>]" id="http_authentication_<?php echo htmlspecialchars($name); ?>" value="<?php echo htmlspecialchars($value) ?>" size="<?php echo htmlspecialchars($size); ?>" /><br />
<?php
	}

	/*
	 * Display a password input field.
	 */
	function _display_input_password_field($name, $value, $size = 75) {
?>
<input type="password" name="<?php echo htmlspecialchars($this->group); ?>[<?php echo htmlspecialchars($name); ?>]" id="http_authentication_<?php echo htmlspecialchars($name); ?>" value="<?php echo htmlspecialchars($value) ?>" size="<?php echo htmlspecialchars($size); ?>" /><br />
<?php
	}

	/*
	 * Display a checkbox field.
	 */
	function _display_checkbox_field($name, $value) {
?>
<input type="checkbox" name="<?php echo htmlspecialchars($this->group); ?>[<?php echo htmlspecialchars($name); ?>]" id="http_authentication_<?php echo htmlspecialchars($name); ?>"<?php if ($value) echo ' checked="checked"' ?> value="1" /><br />
<?php
	}
}
?>
