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
        $this->ldap = \Gini\LDAP::factory($opt['options']);
    }

    public function verify($token, $password)
    {
        $opt = & $this->options;
        $filter = sprintf('(%s=%s)', $opt['token_attr'], $token);
        $sr = $this->ldap->search($opt['token_base'], $filter);
        $entries = $this->ldap->entries($sr);
        if (!$entries['count']) return FALSE;
        $token_dn = $entries[0]['dn'];

        return $this->ldap->bind($token_dn, $password);
    }

    public function changePassword($token, $password)
    {
        $opt = & $this->options;
        $filter = sprintf('(%s=%s)', $opt['token_attr'], $token);
        $sr = $this->ldap->search($opt['token_base'], $filter);
        $entries = $this->ldap->entries($sr);
        if (!$entries['count']) return FALSE;
        $token_dn = $entries[0]['dn'];

        return $this->ldap->setPassword($token_dn, $password);
    }

    public function changeUserName($token, $token_new)
    {
        $opt = & $this->options;
        $filter = sprintf('(%s=%s)', $opt['token_attr'], $token);
        $sr = $this->ldap->search($opt['token_base'], $filter);
        $entries = $this->ldap->entries($sr);
        if (!$entries['count']) return FALSE;
        $old_dn = $entries[0]['dn'];
        list($first,$rest) = explode(',', $old_dn, 2);
        list($k, $v) = explode('=', $first, 2);

        return $this->ldap->rename($old_dn, $k.'='.$token_new) && $this->ldap->modReplace(
            $k.'='.$token_new.','.$rest,
            array(
                $opt['token_attr'] => $token_new
            )
        );
    }

    public function add($token, $password)
    {
        $opt = & $this->options;

        return $this->ldap->addAccount($opt['token_base'], $token, $password);
    }

    public function remove($token)
    {
        $opt = & $this->options;
        $filter = sprintf('(%s=%s)', $opt['token_attr'], $token);
        $sr = $this->ldap->search($opt['token_base'], $filter);
        $entries = $this->ldap->entries($sr);
        if (!$entries['count']) return TRUE;
        $token_dn = $entries[0]['dn'];

        return $this->ldap->delete($token_dn);
    }

}
