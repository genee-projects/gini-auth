<?php
/**
* @file LDAP.php
* @brief LDAP验证
* @author Hongjie Zhu
* @version 0.1.0
* @date 2015-01-08
 */

namespace Gini\Auth;

class LDAP implements \Gini\Auth\Driver
{

    private $ldap;
    private $options;

    public function __construct(array $opt)
    {
        $this->options = $opt;
        $this->ldap = \Gini\LDAP::factory($opt['ldap.options']);
    }

    public function verify($username, $password)
    {
        $opt = $this->options;
        $filter = sprintf('(%s=%s)', $opt['ldap.username_attr'], $username);
        $sr = $this->ldap->search($opt['ldap.username_base'], $filter);
        $entries = $this->ldap->entries($sr);
        if (!$entries['count']) return FALSE;
        $username_dn = $entries[0]['dn'];

        return $this->ldap->bind($username_dn, $password);
    }

    public function changePassword($username, $password)
    {
        $opt = $this->options;
        $filter = sprintf('(%s=%s)', $opt['ldap.username_attr'], $username);
        $sr = $this->ldap->search($opt['ldap.username_base'], $filter);
        $entries = $this->ldap->entries($sr);
        if (!$entries['count']) return FALSE;
        $username_dn = $entries[0]['dn'];

        return $this->ldap->setPassword($username_dn, $password);
    }

    public function changeUserName($username, $username_new)
    {
        $opt = & $this->options;
        $filter = sprintf('(%s=%s)', $opt['ldap.username_attr'], $username);
        $sr = $this->ldap->search($opt['ldap.username_base'], $filter);
        $entries = $this->ldap->entries($sr);
        if (!$entries['count']) return FALSE;
        $old_dn = $entries[0]['dn'];
        list($first,$rest) = explode(',', $old_dn, 2);
        list($k, $v) = explode('=', $first, 2);

        return $this->ldap->rename($old_dn, $k.'='.$username_new) && $this->ldap->modReplace(
            $k.'='.$username_new.','.$rest,
            array(
                $opt['ldap.username_attr'] => $username_new
            )
        );
    }

    public function add($username, $password)
    {
        $opt = & $this->options;

        return $this->ldap->addAccount($opt['ldap.username_base'], $username, $password);
    }

    public function remove($username)
    {
        $opt = & $this->options;
        $filter = sprintf('(%s=%s)', $opt['ldap.username_attr'], $username);
        $sr = $this->ldap->search($opt['ldap.username_base'], $filter);
        $entries = $this->ldap->entries($sr);
        if (!$entries['count']) return TRUE;
        $username_dn = $entries[0]['dn'];

        return $this->ldap->delete($username_dn);
    }

}
