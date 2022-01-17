# http-authentication
LDAP group - role mapping extension for the WordPress http-authentication plugin

## Description

This is an extension of the existing [http-authentication](https://wordpress.org/plugins/http-authentication) WordPress plugin which is not maintained any more.
The HTTP Authentication plugin allows you to use existing means of authenticating people to WordPress. Primarily it had been written and used for Apache’s basic HTTP authentication module.

![screenshot-1](screenshot-1.png?raw=true "Plugin options, allowing wordpress authentication")

Additionally you can configure an LDAP section where LDAP groups can be mapped to WordPress roles. The advantage against other plugins is that users are put into the right role **automatically** after login instead of editing every user separately. If no group matches for the user he/she will be put into the "New user default role" configured in the General section.

![screenshot-3](screenshot-3.png?raw=true "Plugin options for LDAP authentication")

## Installation

Clone this repository into your wordpress plugin directory (usually */usr/share/wordpress/wp-content/plugins* or */var/lib/wordpress/wp-content/plugins*), e.g.
```
git clone https://github.com/sunflowerbofh/http-authentication.git /usr/share/wordpress/wp-content/plugins
```

You can activate the plugin now within the Plugins menu.

## Configuration

After installation and activation you will find the item "HTTP Authentication" under the "Settings" button. 

### JSON

If you don't want to enter the settings manually, you can prepare a [json file](examples/http-authentication.json) and implement it with [wp cli](https://wp-cli.org/):
```
wp option update http_authentication_options --allow-root --path=/usr/share/wordpress --url=wordpress.example.com --format=json < example.json
```

### Web server

With the help of this plugin you can loop the user login through the webserver directly into wordpress. Here is an example how apache2 could be configured for LDAP:
```
<LocationMatch /(wp-login|wp-admin)>
    AuthType Basic
    AuthName "Enter Credentials"
    AuthBasicProvider ldap file
    AuthLDAPRemoteUserAttribute uid
    AuthLDAPRemoteUserIsDN off
    AuthLDAPGroupAttribute memberUid
    AuthLDAPGroupAttributeIsDN Off
    AuthLDAPURL "ldaps://ldap.example.com:636/dc=bfh?uid?sub"
    <RequireAny>
        Require ldap-group cn=wordpress-admin,ou=security,ou=groups,dc=example
        Require ldap-group cn=wordpress-editor,ou=security,ou=groups,dc=example
        Require ldap-group cn=wordpress-author,ou=security,ou=groups,dc=example
    </RequireAny>
</LocationMatch>
```
If you want a local admin user beside you can additionally include a file. Create a htpasswd with you wpadmin before.

```
    <RequireAny>
        Require ldap-group cn=wordpress,ou=security,ou=groups,dc=example
        AuthUserFile /etc/wordpress/htpasswd
        Require user wpadmin
    </RequireAny>
```

## ToDo List / Backlog

The LDAP frontend is still pretty bare-bone. The following enhancements are desirable:
* The plugin was only developped for "pure" LDAP, Active Directory should work as well but is not tested yet.
* Missing "Check LDAP connection" button for easier debugging the ldap connection.
* LDAP groups have to be entered fully manually. An autocompletion by getting results from the LDAP server would be nice to have.
* Instead of fixed fields lines should be added by '+'. These should contain a text box for the LDAP groups and a dropdown for the wordpress role.
* Pre-defined values are not visible (e.g. LDAP version = 3).
* Before filling out the fields and saving for the first time, you can get some ugly warnings about "non-defined index".
