<?php

namespace Gini\Auth;

class RPC implements \Gini\Auth\Driver {

    private $_rpc;
    private $_opt;

    function __construct(array $opt){
        $this->_rpc = \Gini\IoC::construct('\Gini\Auth\RPC', $opt['rpc.url']);
        $this->_opt = $opt;
    }
    //验证令牌/密码
    function verify($username, $password) {

        $nusername = preg_replace('/%[^%]+$/', '', $username . '|' . $this->_opt['backend']);

        try {
            $key = $this->_rpc->auth->verify($nusername, $password);
            if ($key) {
                $_SESSION['#RPC_TOKEN_KEY'][$this->_backend][$username] = $key;
                return true;
            }
        }
        catch (\Gini\RPC\Exception $e) {
        }

        return false;
    }
    //设置令牌
    function changeUserName($username, $new_username) {
        //安全问题 禁用
        return false;
    }
    //设置密码
    function changePassword($username, $password) {
        //安全问题 禁用
        return false;
    }
    //添加令牌/密码对
    function add($username, $password) {
        //安全问题 禁用
        return false;
    }
    //删除令牌/密码对
    function remove($username) {
        //安全问题 禁用
        return false;

    }

}
