# LdapAuth 
This plugin allows MISP to authenticate against an LDAP server.

## How to
1. For enabling this plugin, uncomment the line `CakePlugin::load('LdapAuth');` in the `app/Config/bootstrap.php` configuration file.
2. Add your LDAP server configuration to `app/Config/config.php` configuration file:
    ```
    'LdapAuth' => [
        'ldapServer' => 'ldap://openldap:1389',
        'ldapDn' => 'dc=example,dc=com',
        'ldapReaderUser' => 'cn=reader,dc=example,dc=com',
        'ldapReaderPassword' => 'password'
    ],
    ```
    > **NOTE:** This plugin requires a reader user to query the LDAP server.
3. Add the LDAP authentication method in the `Security.auth` key of the `app/Config/config.php` configuration file:
    ```
    ...
    'Security' => [
        ...,
       'auth' => [
           0 => 'LdapAuth.Ldap',
       ]
    ]
    ``` 
4. Log in with your LDAP credentials using the MISP Login form, if the user doesn't exist on MISP it will be created on the first log in.

## Settings
Each setting is stored in the `LdapAuth` configuration array and can be customized as per your LDAP server and application requirements.

### `ldapServer`
- **Description**: The LDAP server's hostname or IP address.
- **Type**: `string`
- **Example**: `'ldap://ldap.example.com'` or `'ldap://ldap.example.com:3389'` for using a custom port.

### `ldapDn`
- **Description**: The distinguished name (DN) for the LDAP search base.
- **Type**: `string`
- **Example**: `'dc=example,dc=com'`

### `ldapReaderUser`
- **Description**: The username for the LDAP reader account, used to authenticate search requests.
- **Type**: `string`
- **Example**: `'cn=reader,dc=example,dc=com'`

### `ldapReaderPassword`
- **Description**: The password for the LDAP reader account.
- **Type**: `string`
- **Example**: `'password'`

### `ldapSearchFilter`
- **Description**: The LDAP search filter used to locate the user entry.
- **Type**: `string`
- **Example**: `'(objectclass=inetOrgPerson)(!(nsaccountlock=True))(memberOf=cn=misp,cn=groups,cn=accounts,dc=example,dc=com)'`

### `ldapSearchAttribute`
- **Description**: The LDAP attribute used to match the user's identifier, typically their email or username.
- **Type**: `string`
- **Default**: `'mail'`
- **Example**: `'uid'`

### `ldapEmailField`
- **Description**: Specifies which LDAP attribute(s) to use for retrieving the user's email address.
- **Type**: `array`
- **Default**: `['mail']`
- **Example**: `['mail', 'userPrincipalName']`

### `ldapNetworkTimeout`
- **Description**: Sets the timeout for the network connection to the LDAP server, in seconds.
- **Type**: `integer`
- **Default**: `-1` (no timeout)
- **Example**: `10`

### `ldapProtocol`
- **Description**: Specifies the LDAP protocol version.
- **Type**: `integer`
- **Default**: `3`
- **Example**: `3`

### `ldapAllowReferrals`
- **Description**: Determines whether LDAP referrals are allowed.
- **Type**: `boolean`
- **Default**: `true`
- **Example**: `true`

### `starttls`
- **Description**: Enables or disables StartTLS for LDAP, which provides a secure connection.
- **Type**: `boolean`
- **Default**: `false`
- **Example**: `true`

### `mixedAuth`
- **Description**: Allows mixed authentication modes (e.g., both LDAP and local database authentication).
- **Type**: `boolean`
- **Default**: `true`
- **Example**: `true`

### `ldapDefaultOrgId`
- **Description**: Specifies the default organisation ID when creating LDAP users on MISP.
- **Type**: `string`
- **Example**: `1`

### `ldapDefaultRoleId`
- **Description**: The default role ID assigned to users authenticated through LDAP. Can also be an array representing the mapping of group memberships of the LDAP user with the corresponding MISP `role_id`.
- **Type**: `integer` | `array`
- **Default**: `3`
- **Example**: `3`
- **Example of _LDAP group -> role_id_ mapping**: 
    ```
    [
        'misp_admin'        => 1,
        'misp_orgadmin'     => 2,
        'misp_user'         => 3,
        'misp_publisher'    => 4,
        'misp_syncuser'     => 5,
        'misp_readonly'     => 6,
    ]
    ```

### `updateUser`
- **Description**: Indicates whether user information in the local application database should be updated with LDAP data on each login. If the user exists on MISP but the LDAP role doesn't, the user is disabled and not allowed to log in.
- **Type**: `boolean`
- **Default**: `true`
- **Example**: `true`


### `debug`
- **Description**: Increments the default debug level of the PHP LDAP library.
- **Type**: `boolean`
- **Default**: `false`
- **Example**: `true`

### `ldapTlsRequireCert`
- **Description**: Sets the value for `LDAP_OPT_X_TLS_REQUIRE_CERT` setting.
- **Type**: `int`
- **Default**: `LDAP_OPT_X_TLS_DEMAND`
- **Options**: `LDAP_OPT_X_TLS_NEVER` | `LDAP_OPT_X_TLS_HARD` | `LDAP_OPT_X_TLS_DEMAND` | `LDAP_OPT_X_TLS_ALLOW` | `LDAP_OPT_X_TLS_TRY`
- **Example**: `LDAP_OPT_X_TLS_NEVER`

### `ldapTlsCustomCaCert`
- **Description**: Sets the value for `LDAP_OPT_X_TLS_CACERTDIR` and `LDAP_OPT_X_TLS_CACERTFILE`.
- **Type**: `boolean|string`
- **Default**: `false`
- **Example**: `/var/wwww/MISP/app/files/certs/ldap.crt`

### `ldapTlsCrlCheck`
- **Description**: Sets the value for `LDAP_OPT_X_TLS_CRLCHECK`.
- **Type**: `int`
- **Options**: `LDAP_OPT_X_TLS_CRL_NONE`|`LDAP_OPT_X_TLS_CRL_PEER`|`LDAP_OPT_X_TLS_CRL_ALL`.
- **Default**: `LDAP_OPT_X_TLS_CRL_PEER`
- **Example**: `LDAP_OPT_X_TLS_CRL_NONE`

### `ldapTlsProtocolMin`
- **Description**: Sets the value for `LDAP_OPT_X_TLS_PROTOCOL_MIN`.
- **Type**: `int`
- **Options**: `LDAP_OPT_X_TLS_PROTOCOL_SSL2`|`LDAP_OPT_X_TLS_PROTOCOL_SSL3`|`LDAP_OPT_X_TLS_PROTOCOL_TLS1_0`|`LDAP_OPT_X_TLS_PROTOCOL_TLS1_1`|`LDAP_OPT_X_TLS_PROTOCOL_TLS1_2`
- **Default**: `LDAP_OPT_X_TLS_PROTOCOL_TLS1_2`
- **Example**: `LDAP_OPT_X_TLS_PROTOCOL_SSL3`

See also: https://www.php.net/manual/en/ldap.constants.php

## Example Usage

To configure these settings in your application, ensure each setting is defined in your configuration file as follows:

```php
'LdapAuth', [
    'ldapServer' => 'ldap://ldap.example.com',
    'ldapDn' => 'dc=example,dc=com',
    'ldapReaderUser' => 'cn=reader,dc=example,dc=com',
    'ldapReaderPassword' => 'password',
    'ldapSearchFilter' => '(objectClass=inetOrgPerson)',
    'ldapSearchAttribute' => 'mail',
    'ldapEmailField' => ['mail', 'uid'],
    'ldapNetworkTimeout' => -1,
    'ldapProtocol' => 3,
    'ldapAllowReferrals' => false,
    'starttls' => true,
    'mixedAuth' => true,
    'ldapDefaultOrg' => 1,
    'ldapDefaultRoleId' => 3,
    'updateUser' => true
];
```

Adjust the values as needed based on your LDAP server setup.

## Troubleshooting
* Start your tests with `debug` set to `true`.
* Start your tests with `starttls` set to `false`.
* Check `app/tmp/logs/error.log`, you can see the error responses from the LDAP server.

### TLS
If experiencing issues when configuring MISP to use LDAPS, try:
1. Set `ldapTlsRequireCert` to `LDAP_OPT_X_TLS_NEVER`.
2. Set `ldapTlsCrlCheck` to `LDAP_OPT_X_TLS_CRL_NONE`
3. Set `ldapTlsProtocolMin` to `LDAP_OPT_X_TLS_PROTOCOL_SSL3`.
4. Then set the this setting to the correct (safe) value one at a time.


* Ensure the user www-data has sufficient permissions to read the custom CA certificate. 

* If you are using a self-signed certificate, ensure the CN matches the host name of the LDAP server, otherwise the TLS session will fail.


#### Debugging
Additionally, you can install `ldap-utils` and use the `ldapsearch` tool to verify the connection.
In this scenairo you may have to edit the `/etc/ldap/ldap.conf` to match the LDAP settings used by MISP

Example `/etc/ldap/ldap.conf` configuration using a custom CA, equivalent to setting `LdapAuthldapTlsCustomCaCert`:
```
#
# LDAP Defaults
#

# See ldap.conf(5) for details
# This file should be world readable but not world writable.

#BASE   dc=example,dc=com
#URI    ldap://ldap.example.com ldap://ldap-provider.example.com:666

#SIZELIMIT      12
#TIMELIMIT      15
#DEREF          never

# TLS certificates (needed for GnuTLS)

#TLS_CACERT     /etc/ssl/certs/ca-certificates.crt
#TLS_REQCERT    never

TLS_CACERTDIR   /var/www/MISP/app/files/certs
TLS_CACERT      /var/www/MISP/app/files/certs/ldap.crt
```

Example test (failed) search:
```
# ldapsearch -H ldaps://localhost:1636 -x -b "dc=example,dc=com" -D "cn=reader,dc=example,dc=com" -w password -d 1
TLS: hostname (localhost) does not match common name in certificate (ldap.example.com).
TLS: can't connect: (unknown error code).