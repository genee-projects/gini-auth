<?php
/**
* @file Handler.php
* @brief 对ldap的封装
* @author Hongjie Zhu
* @version 0.1.0
* @date 2015-01-08
 */

namespace Gini\Auth\LDAP;

class Handler
{

	private $ds;

	protected $options = array();
	
	private $_rootBinded = FALSE;

	public static function factory($opt) {
		return \Gini\IoC::construct('\Gini\LDAP', $opt);
	}

	public function __construct($opt) {
		
		$this->options = (array) $opt;
				
		$ds = @ldap_connect($this->getOption('host'));
		if (!$ds) throw new \Error_Exception(T('无法连接LDAP, 请检查您的LDAP配置'));
		
		@ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);
		@ldap_set_option($ds, LDAP_OPT_NETWORK_TIMEOUT, 3);
		
		$this->ds = $ds;
		$this->_bindRoot();
		
	}
	
	public function __destruct() {
		if ($this->ds) {
			@ldap_close($this->ds);
			$this->_rootBinded = FALSE;
		}
	}
	
	public function getOption($name, $default=NULL) {
		return $this->options[$name];
	}
	
	public function bind($dn, $password) {
		$ret = @ldap_bind($this->ds, $dn, $password);
		if ($dn != $this->getOption('root_dn')) {
			$this->_bindRoot();
		}
		return $ret;
	}
	
	private function _bindRoot() {
		return $this->bind($this->getOption('root_dn'), $this->getOption('root_pass'));
	}
	
	public function rename($dn, $dn_new, $base=NULL, $deleteoldrdn = TRUE) {
		return @ldap_rename($this->ds, $dn, $dn_new, $base, $deleteoldrdn);
	}

	public function modReplace($dn, $data) {
		return @ldap_mod_replace($this->ds, $dn, $data);
	}

	public function modAdd($dn, $data) {
		return @ldap_mod_add($this->ds, $dn, $data);
	}

	public function modDel($dn, $data) {
		return @ldap_mod_del($this->ds, $dn, $data);
	}

	public function add($dn, $data){
		return @ldap_add($this->ds, $dn, $data);
	}
	
	public function modify($dn, $data){
		return @ldap_modify($this->ds, $dn, $data);
	}
	
	public function delete($dn){
		return @ldap_delete($this->ds, $dn);
	}
	
	public function search() {
		$args = func_get_args();
		array_unshift($args, $this->ds);
		return @call_user_func_array('ldap_search', $args);
	}
	
	public function entries($sr) {
		return @ldap_get_entries($this->ds, $sr);
	}
	
	public function firstEntry($sr) {
		return @ldap_first_entry($this->ds, $sr);
	}
	
	public function nextEntry($er) {
		return @ldap_next_entry($this->ds, $er);
	}
	
	public function entryDn($er) {
		return @ldap_get_dn($this->ds, $er);
	}
	
	public function attributes($er) {
		return @ldap_get_attributes($this->ds, $er);
	}
	
	public function setPassword($dn, $password) {
		return $this->modReplace($dn, $this->_getPasswordAttrs($password));
	}
	
	public function addAccount($base_dn, $account, $password){

		$server_type = $this->getOption('server_type');
		
		switch ($server_type) {
		case 'ads':
			$dn = 'cn='.$account.','.$base_dn;
			$data = array(
				'objectClass' => array('top', 'person', 'organizationalPerson', 'user'),
				'cn' => $account,
				'sAMAccountName' => $account,
			);
			break;
		default:
			$dn = 'cn='.$account.','.$base_dn;
			$data = array(
				'objectClass' => array('top', 'person', 'organizationalPerson', 'posixAccount'),
				'cn' => $account,
				'sn' => $account,
				'uid' => $account,
				'loginShell' => '/bin/false',
				'homeDirectory' => '/home/samba/users/'.$account,
				'uidNumber' => $this->_posixGetNewUid(),
				'gidNumber' => $this->getOption('posix.default_gid'),
			);

			if ($this->getOption('enable_shadow')) {
				$data['objectClass'][] = 'shadowAccount';
				$data += array(
					'shadowExpire' => 99999,
					'shadowFlag' => 0,
					'shadowInactive' => 99999,
					'shadowMax' => 99999,
					'shadowMin' => 0,
					'shadowWarning' => 0,
				);
			}
	
			break;
		}
		
		$data += $this->_getPasswordAttrs($password);
		
		$ret = $this->add($dn, $data);
		if ($ret)  $this->enableAccount($dn, TRUE);
		return $ret;
	}
	
	public function enableAccount($dn, $enable=TRUE) {
		switch ($this->getOption('server_type')) {
		case 'ads':
			$sr = $this->search($dn, '(objectClass=*)', array('useraccountcontrol'), TRUE);
			$entries = $this->entries($sr);
			$uac = $entries[0]['useraccountcontrol'][0];
			if ($enable) {
				$uac = $uac & ~0x22;
				$uac = $uac | 0x10000;	//Password never expires
				$this->modReplace($dn, array('useraccountcontrol' => $uac));
			}
			else {
				//禁用帐号
				if (!($uac & 0x2)) {
					$this->modReplace($dn, array('useraccountcontrol' => $uac | 0x2));
				}
			}
			break;
		default:
		}
	}

	private function _getPasswordAttrs($password) {
		switch($this->getOption('pass_algo')) {
		case 'plain':	//不加密
			$secret = $password;
			break;
		case 'md5':
			$secret = '{MD5}'.base64_encode(md5($password, TRUE));
			break;
		case 'sha':
		default:
			$secret = '{SHA}'.base64_encode(sha1($password, TRUE));
			break;
		}
		
		$data = array(
			'userPassword'=> $secret,
		);
		
		return $data;

	}
	
	private function _posixGetNewUid() {
		static $default_uid = 0;
		if (!$default_uid) $default_uid = $this->getOption('posix.default_uid');
		$account = $default_uid + 1;
		while (posix_getpwuid($account)) {
			$account ++;
		}
		return $default_uid = $account;
	}
		
}

