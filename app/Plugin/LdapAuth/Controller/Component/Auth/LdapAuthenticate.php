<?php

App::uses('BaseAuthenticate', 'Controller/Component/Auth');

class LdapAuthenticate extends BaseAuthenticate
{

    /**
     * Holds the user information
     *
     * @var array
     */
    protected static $user = false;

    protected static $conf;

    /* 
    'LdapAuth' => [
        'ldapHost' => 'ldap://openldap:389',
        'ldapDn' => 'dc=example,dc=com',
        'ldapReaderUser' => 'cn=reader,dc=example,dc=com',
        'ldapReaderPassword' => 'readerpassword',
        'ldapSearchFilter' => ''
    ]
    */

    public function __construct()
    {
        self::$conf = [
            'ldapServer' => Configure::read('LdapAuth.ldapServer'),
            'ldapDn' => Configure::read('LdapAuth.ldapDn'),
            'ldapReaderUser' => Configure::read('LdapAuth.ldapReaderUser'),
            'ldapReaderPassword' => Configure::read('LdapAuth.ldapReaderPassword'),
            'ldapSearchFilter' => Configure::read('LdapAuth.ldapSearchFilter'),
            'ldapSearchAttribute' => Configure::read('LdapAuth.ldapSearchAttribute') ?? 'mail',
            'ldapEmailField' => Configure::read('LdapAuth.ldapEmailField') ?? ['mail'],
            'ldapNetworkTimeout' => Configure::read('LdapAuth.ldapNetworkTimeout') ?? -1,
            'ldapProtocol' => Configure::read('LdapAuth.ldapProtocol') ?? 3,
            'ldapAllowReferrals' => Configure::read('LdapAuth.ldapAllowReferrals') ?? false,
            'starttls' => Configure::read('LdapAuth.starttls') ?? false,
            'mixedAuth' => Configure::read('LdapAuth.starttls') ?? false,
            'ldapDefaultOrg' => Configure::read('LdapAuth.ldapDefaultOrg'),
            'ldapDefaultRoleId' => Configure::read('LdapAuth.ldapDefaultRoleId') ?? 3,
            'updateUser' => Configure::read('LdapAuth.updateUser') ?? false,
        ];
    }

    public function authenticate(CakeRequest $request, CakeResponse $response)
    {
        $user = $this->getUser($request);

        $userFields = $request->data['User'];
        $email = $userFields['email'];
        $password = $userFields['password'];

        $ldapconn = $this->ldapConnect();

        if ($ldapconn) {
            // LDAP bind
            $ldapbind = ldap_bind($ldapconn, self::$conf['ldapReaderUser'],  self::$conf['ldapReaderPassword']);
            // authentication verification
            if (!$ldapbind) {
                CakeLog::error("[LdapAuth] LDAP bind failed: " . ldap_error($ldapconn));
                return false;
            }
        }

        return true;
    }

    private function ldapConnect()
    {
        // LDAP connection
        ldap_set_option(NULL, LDAP_OPT_NETWORK_TIMEOUT, self::$conf['ldapNetworkTimeout']);
        $ldapconn = ldap_connect(self::$conf['ldapServer']);

        if (!$ldapconn) {
            CakeLog::error("[LdapAuth] LDAP server connection failed.");
            return false;
        }

        // LDAP protocol configuration
        ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, self::$conf['ldapProtocol']);
        ldap_set_option($ldapconn, LDAP_OPT_REFERRALS, self::$conf['ldapAllowReferrals']);

        if (self::$conf['starttls'] == true) {
            # Default is false, sine STARTTLS support is a new feature
            # Ignored on ldaps://, but can trigger problems for orgs
            # using unencrypted LDAP. Loose comparison allows users to
            # use # true / 1 / etc.
            ldap_start_tls($ldapconn);
        }

        return $ldapconn;
    }

    private function getEmailAddress($ldapEmailField, $ldapUserData)
    {
        // return the email address of an LDAP user if one of the fields in $ldapEmaiLField exists
        foreach ($ldapEmailField as $field) {
            if (isset($ldapUserData[0][$field][0])) {
                return $ldapUserData[0][$field][0];
            }
        }
        return null;
    }

    private function isUserMemberOf($group, $ldapUserData)
    {
        // return true of false depeding on if user is a member of group.
        $returnCode = false;
        unset($ldapUserData[0]['memberof']["count"]);
        foreach ($ldapUserData[0]['memberof'] as $result) {
            $r = explode(",", $result, 2);
            $ldapgroup = explode("=", $r[0]);
            if ($ldapgroup[1] == $group) {
                $returnCode = true;
            }
        }
        return $returnCode;
    }

    /*
     * Retrieve a user by validating the request data
     */
    public function getUser(CakeRequest $request)
    {
        if (!array_key_exists("User", $request->data)) {
            return false;
        }

        $userFields = $request->data['User'];
        $email = $userFields['email'];
        $password = $userFields['password'];

        CakeLog::debug("[LdapAuth] Login attempt with email: $email");
        $this->settings['fields'] = array('username' => "email");


        $filter = '(' . self::$conf['ldapSearchAttribute'] . '=' . $email . ')';
        if (!empty(self::$conf['ldapSearchFilter'])) {
            $filter =  '(&' . self::$conf['ldapSearchFilter'] . ')' . $filter;
        }

        $ldapconn = $this->ldapConnect();

        $ldapUser = ldap_search($ldapconn, self::$conf['ldapDn'], $filter, ['uid', 'mail']);

        if (!$ldapUser) {
            CakeLog::error("[LdapAuth] LDAP user search failed: " . ldap_error($ldapconn));
            return false;
        }

        $ldapUserData = ldap_get_entries($ldapconn, $ldapUser);

        if (!$ldapUserData) {
            CakeLog::error("[LdapAuth] LDAP get user entries failed: " . ldap_error($ldapconn));
            return false;
        }

        // Check user LDAP password
        $ldapbind = ldap_bind($ldapconn, $ldapUserData[0]['dn'], $password);
        if (!$ldapbind) {
            CakeLog::error("[LdapAuth] LDAP user authentication failed: " . ldap_error($ldapconn));
            return false;
        }

        if (!isset(self::$conf['ldapEmailField']) && isset($ldapUserData[0]['mail'][0])) {
            // Assign the real user for MISP
            $mispUsername = $ldapUserData[0]['mail'][0];
        } else if (isset(self::$conf['ldapEmailField'])) {
            $mispUsername = $this->getEmailAddress(self::$conf['ldapEmailField'], $ldapUserData);
        } else {
            CakeLog::error("[LdapAuth] User not found in LDAP.");
            return false;
        }

        // Find user with real username (mail)
        $user = $this->_findUser($mispUsername);

        if ($user && !self::$conf['updateUser']) {
            return $user;
        }

        // Insert user in database if not existent
        $userModel = ClassRegistry::init($this->settings['userModel']);
        $org_id = self::$conf['ldapDefaultOrg'];

        // If not in config, take first local org
        if (!isset($org_id)) {
            $firstOrg = $userModel->Organisation->find(
                'first',
                array(
                    'conditions' => array(
                        'Organisation.local' => true
                    ),
                    'order' => 'Organisation.id ASC'
                )
            );
            $org_id = $firstOrg['Organisation']['id'];
        }

        // Set role_id depending on group membership
        $roleIds = self::$conf['ldapDefaultRoleId'];
        if (is_array($roleIds)) {
            foreach ($roleIds as $key => $id) {
                if ($this->isUserMemberOf($key, $ldapUserData)) {
                    $roleId = $roleIds[$key];
                }
            }
        } else {
            $roleId = $roleIds;
        }

        if (!$user) {
            // create user
            $userData = array('User' => array(
                'email' => $mispUsername,
                'org_id' => $org_id,
                'password' => '',
                'confirm_password' => '',
                'authkey' => $userModel->generateAuthKey(),
                'nids_sid' => 4000000,
                'newsread' => 0,
                'role_id' => $roleId,
                'change_pw' => 0
            ));
            // save user
            $userModel->save($userData, false);
        } else {
            if (!isset($roleId)) {
                // User has no role anymore, disable user
                $user['disabled'] = 1;
                return false;
            } else {
                // Update existing user
                $user['email'] = $mispUsername;
                $user['org_id'] = $org_id;
                $user['role_id'] = $roleId;
                # Reenable user in case it has been disabled
                $user['disabled'] = 0;
            }

            $userModel->save($user, false);
        }

        return $this->_findUser(
            $mispUsername
        );

        # TODO: mixedAuth, check LinOTPAuthenticate

        return $ldapUserData;
    }
}
