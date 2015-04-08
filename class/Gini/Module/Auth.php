<?php

namespace Gini\Module;

class Auth
{
    public static function diagnose()
    {
        // 对不同的driver进行检测
        $backends = \Gini\Config::get('auth.backends');
        if (!empty($backends)) foreach ($backends as $options) {
            switch (strtolower($options['driver'])) {
            case 'ldap':
                $host = $options['ldap.options']['host'];
                $ds = @ldap_connect($host);
                if (!$host || !$ds) {
                    return ['The LDAP host "' . $host . '" in auth.yml is not reachable!'];
                }
                @ldap_close($ds);
                break;
            // database和rpc的验证目前没有使用，而且实现代码也不是很合理，暂时没有必要进行检测
            case 'database':
                break;
            case 'rpc':
                break;
            default:
                return ['The driver "' . $options['driver'] . '" in auth.yml is not supported'];
            }
        }
    }
}
