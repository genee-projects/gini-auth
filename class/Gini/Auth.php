<?php

namespace Gini\Auth {

    interface Driver
    {
        function __construct(array $opt);
        //验证令牌/密码
        function verify($username, $password);
        //设置令牌
        function changeUserName($username, $new_username);
        //设置密码
        function changePassword($username, $password);
        //添加令牌/密码对
        function add($username, $password);
        //删除令牌/密码对
        function remove($username);
    }

}

namespace Gini {

    class Auth
    {
        //返回当前令牌
        static function userName()
        {
            //auth.username可强制重载进程令牌
            $curr_username = \Gini\Config::get('auth.username');
            if (!$curr_username) {
               $curr_username = $_SESSION['auth.username'];
            }

            return $curr_username;
        }

        //设置当前用户的令牌
        static function login($username)
        {
            $username = self::normalize($username);
            // session_unset();
            Event::trigger('auth.before_login', $username);
            Session::cleanup();
            Session::regenerateId();
            $_SESSION['auth.username'] = $username;
            Event::trigger('auth.after_login', $username);
            return $username;
        }

        //取消当前用户/指定用户的令牌
        static function logout()
        {
            $username = self::userName();
            Event::trigger('auth.before_logout', $username);
            Session::cleanup(true);
            Event::trigger('auth.after_logout', $username);
        }

        //显示当前用户是否已登录
        static function isLoggedIn()
        {
            return self::userName() != null;
        }

        static function backends()
        {
            return (array) \Gini\Config::get('auth.backends');
        }

        static function normalize($username = null, $default_backend = null)
        {
            if (!$username) return null;
            $username = trim($username);
            if (!$username) return '';
            if (!preg_match('/\|[\w.-]+/', $username)) {
                $default_backend
                    = $default_backend ?: \Gini\Config::get('auth.default_backend');
                $username .= '|'.$default_backend;
            }

            return $username;
        }

        static function makeUserName($name, $backend=null)
        {
            list($name, $b) = self::parseUserName($name);
            $backend = $backend ?: ($b ?: \Gini\Config::get('auth.default_backend'));

            return $name . '|' . $backend;
        }

        static function parseUserName($username)
        {
            return explode('|', $username, 2);
        }

        private $username;
        private $driver;
        private $options;

        function __construct($username)
        {
            if ($username === null) return;

            list($username, $backend) = self::parseUserName($username);

            $backend = $backend ?: \Gini\Config::get('auth.default_backend');

            $opts = (array) \Gini\Config::get('auth.backends');
            $opt = $opts[$backend];

            if (!$opt['driver']) return;    //driver不存在, 表示没有验证驱动

            $opt['backend'] = $backend;        //将backend传入

            $this->options = $opt;
            $this->username = $username;
            $class = '\Gini\Auth\\'.$opt['driver'];
            $this->driver = \Gini\IoC::construct($class, $opt);
        }

        function create($password)
        {
            if (!$this->driver) return false;
            if (!$this->username) return false;
            if ($this->options['readonly']
                && !$this->options['allow_create']) return true;

            return $this->driver->add($this->username, $password);
        }

        //验证令牌/密码对
        function verify($password)
        {
            if (!$this->driver) return false;
            if (!$this->username) return false;
            return $this->driver->verify($this->username, $password);
        }

        //更改用户令牌
        function changeUserName($username_new)
        {
            if (!$this->driver) return false;
            if (!$this->username) return false;
            if ($this->options['readonly']) return true;
            $ret = $this->driver->changeUserName(
                        $this->username, $username_new);
            if ($ret) {
                $this->username = $username_new;
            }

            return $ret;
        }

        //更改用户密码
        function changePassword($password)
        {
            if (!$this->driver) return false;
            if (!$this->username) return false;
            if ($this->options['readonly']) return true;
            return $this->driver->changePassword($this->username, $password);
        }

        //删除令牌/密码对
        function remove()
        {
            if (!$this->driver) return false;
            if (!$this->username) return false;
            if ($this->options['readonly']) return true;
            return $this->driver->remove($this->username);
        }

    }

}
