=== HTTP Authentication ===
Contributors: sunflower99, dwc
Tags: authentication, ldap
Requires at least: 5.8
Tested up to: 5.8.2
Stable tag: 4.6

Use an external authentication source in WordPress.
Put user into wordpress role depending on LDAP group immediately after login.

== Installation ==

1. Login as an existing user, such as admin.
2. Upload the `http-authentication` folder to your plugins folder, usually `wp-content/plugins`. (Or simply via the built-in installer.)
3. Activate the plugin on the Plugins screen.
4. Add one or more LDAP groups that should get the role administrator, editor or author (optional).
5. Logout.
6. Protect `wp-login.php` and `wp-admin` using your external authentication (using, for example, `.htaccess` files).
7. Try logging in as one of the users added via LDAP or .htaccess.

== Frequently Asked Questions ==

= What authentication mechanisms can I use? =

Any authentication mechanism which sets the `REMOTE_USER` (or `REDIRECT_REMOTE_USER`, in the case of ScriptAlias'd PHP-as-CGI) environment variable can be used in conjunction with this plugin. Examples include Apache's `mod_auth` and `mod_auth_ldap`.

= How should I set up external authentication? =

This depends on your hosting environment and your means of authentication.

Many Apache installations allow configuration of authentication via `.htaccess` files, while some do not. Try adding the following to your blog's top-level `.htaccess` file:
`<Files wp-login.php>
AuthName "WordPress"
AuthType Basic
AuthUserFile /path/to/passwords
Require user dwc
</Files>`

(You may also want to protect your `xmlrpc.php` file, which uses separate authentication code.)

Then, create another `.htaccess` file in your `wp-admin` directory with the following contents:
`AuthName "WordPress"
AuthType Basic
AuthUserFile /path/to/passwords
Require user dwc`

In both files, be sure to set `/path/to/passwords` to the location of your password file. For more information on creating this file, see below.

= Where can I find more information on configuring Apache authentication? =

See Apache's HOWTO: [Authentication, Authorization, and Access Control](http://httpd.apache.org/docs/howto/auth.html).

= How does this plugin authenticate users? =

This plugin doesn't actually authenticate users. It simply feeds WordPress the name of a user who has successfully authenticated through Apache.

To determine the username, this plugin uses the `REMOTE_USER` or the `REDIRECT_REMOTE_USER` environment variable, which is set by many Apache authentication modules. If someone can find a way to spoof this value, this plugin is not guaranteed to be secure.

By default, this plugin generates a random password each time you create a user or edit an existing user's profile. However, since this plugin requires an external authentication mechanism, this password is not requested by WordPress. Generating a random password helps protect accounts, preventing one authorized user from pretending to be another.

= If I disable this plugin, how will I login? =

Because this plugin generates a random password when you create a new user or edit an existing user's profile, you will most likely have to reset each user's password if you disable this plugin. WordPress provides a link for requesting a new password on the login screen.

Also, you should leave the `admin` user as a fallback, i.e. create a new account to use with this plugin. As long as you don't edit the `admin` profile, WordPress will store the password set when you installed WordPress.

In the worst case scenario, you may have to use phpMyAdmin or the MySQL command line to [reset a user's password](https://wordpress.org/support/article/resetting-your-password/).

= Can I configure the plugin to support standard WordPress logins? =

(The following has not been tested. It has been taken over from the original [http-authentication](https://wordpress.org/plugins/http-authentication/).)

Yes. You can authenticate some users via an external, single sign-on system and other users via the built-in username and password combination. (Note: When mixed authentication is in use, this plugin does not scramble passwords as described above.)

When you configure your external authentication system, make sure that you allow users in even if they have not authenticated externally. Using [Shibboleth](http://shibboleth.internet2.edu/) as an example:
`AuthName "Shibboleth"
AuthType Shibboleth
Require Shibboleth`

This enables Shibboleth authentication in ["passive" mode](https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPProtectContent).

Then, in WordPress:

1. Set the plugin to allow WordPress authentication.
2. Configure the login URI to match your Shibboleth system. For example, if your blog is hosted at `http://example.com/`, then your login URI should be `http://example.com/Shibboleth.sso/Login?target=%redirect_encoded%`.
3. Configure the logout URI to match your Shibboleth system. Following the above example, your logout URI would be `http://example.com/Shibboleth.sso/Logout?return=%redirect_encoded%`.

After saving the options, authentication will work as follows:

* If a user is already authenticated via Shibboleth, and he or she exists in the WordPress database, this plugin will log them in automatically.
* If a user is not authenticated via Shibboleth, the plugin will present the standard WordPress login form with an additional link to login via Shibboleth.

Other authentication systems (particularly those without a login or logout URI) will need to be configured differently.

= Does this plugin support multisite (WordPress MU) setups? =

Yes, you can enable this plugin across a network or on individual sites. However, options will need to be set on individual sites.

If you have suggestions on how to improve network support, please submit a comment.

= Does this plugin support multisite (WordPress MU) setups? =

Yes, you can enable this plugin across a network or on individual sites. However, options will need to be set on individual sites.

If you have suggestions on how to improve network support, please submit a comment.

= How do you handle staged deployments (dev, test, prod) with the plugin? =

If you have a WordPress site with multiple environments (e.g. `dev.example.com`, `test.example.com`, and `example.com`) you can use additional variables in the login and lo
gout URIs:

* `%host%` - The current value of `$_SERVER['HTTP_HOST']`
* `%base%` - The base domain URL (everything before the path)
* `%site%` - The WordPress home URI
* `%redirect%` - The return URI provided by WordPress

You can also use `%host_encoded%`, `%site_encoded%`, and `%redirect_encoded%` for URL-encoded values.

For example, your login URI could be:

`https://%host%/Shibboleth.sso/Login?target=%redirect_encoded%`

This would be modified for each environment as appropriate.

== Screenshots ==

1. Plugin options, allowing WordPress authentication
2. WordPress login form with external authentication link
3. LDAP server and group configuration

== Changelog ==

![changelog](CHANGELOG.txt)
