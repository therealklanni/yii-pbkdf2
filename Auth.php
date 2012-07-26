<?php
/**
 * @author Kevin Lanni <http://github.com/therealklanni>
 * @name Yii PBKDF2 Password Hashing/Authentication Component
 *
 * This module provides secure password hashing and authentication via the PBKDF2 method.
 * PBKDF2 key derivation defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
 * Original code by havoc AT defuse.ca / https://defuse.ca/php-pbkdf2.htm
 */

class Auth extends CApplicationComponent
{
	public $algorithm = 'sha256';
	public $iterations = 1024;
	public $salt_bytes = 24; // 24 bytes generates a 32-character string
	public $hash_bytes = 24; // 24 bytes generates a 32-character string
	
	/**
	 * Generates a secure password hash
	 *
	 * @param string $password Raw password string
	 * @return object Object containing the generated salt and PBKDF2-hashed password
	 */
	public function generate_hash($password)
	{
		// Generate a new salt every time a new password hash is generated
		$salt = base64_encode(mcrypt_create_iv($this->salt_bytes, MCRYPT_DEV_URANDOM));
		
		return (object) array(
			'salt'=>$salt,
			'hash'=>base64_encode(self::pbkdf2(
				$password,
				$salt,
				$this->hash_bytes
			)),
		);
	}
	
	/**
	 * Check user input versus SHA256-encrypted and salted password hash
	 *
	 * @param string $password User input
	 * @param string $salt User's salt stored with hashed password
	 * @param string $hash User's password hash
	 * @return bool If the hashes match
	 */
	public function validate_password($password, $salt, $hash)
	{
		return self::slow_equals(
			base64_decode($hash),
			self::pbkdf2(
				$password,
				$salt,
				strlen(base64_decode($hash))
			)
		);
	}
	
	/**
	 * Compares two strings in length-constant time
	 */
	protected function slow_equals($a, $b)
	{
		$diff = strlen($a) ^ strlen($b);
		
		for ($i = 0; $i < strlen($a) && $i < strlen($b); $i++)
		{
			$diff |= ord($a[$i]) ^ ord($b[$i]);
		}
		
		return $diff === 0;
	}
	
	/*
	 * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
	 * @param string $password The password.
	 * @param string $salt A salt that is unique to the password.
	 * @param integer $key_length The length of the derived key in bytes.
	 * @return string A $key_length-byte key derived from the password and salt.
	 *
	 * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
	 *
	 * This implementation of PBKDF2 was originally created by https://defuse.ca
	 * With improvements by http://www.variations-of-shadow.com
	 * Further modified for Yii Component usage by http://github.com/therealklanni
	 */
	protected function pbkdf2($password, $salt, $key_length)
	{
		$algorithm = strtolower($this->algorithm); // for sanity
		
		if (!in_array($algorithm, hash_algos(), true)) {
			// Throw error: Invalid hash algorithm
			throw new CException('Invalid hash algorithm '.$algorithm);
			return false;
		}
		
		$hash_length = strlen(hash($algorithm, "", true));
		$block_count = ceil($key_length / $hash_length);
		$output = "";
		
		for ($i = 1; $i <= $block_count; $i++)
		{
			// $i encoded as 4 bytes, big endian
			$last = $salt . pack("N", $i);
			
			// first iteration
			$last = $xorsum = hash_hmac($algorithm, $last, $password, true);
			
			// perform the other ($iterations - 1) iterations
			for ($j = 1; $j < (int) $this->iterations; $j++)
			{
				$xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
			}
			
			$output .= $xorsum;
		}
		
		return substr($output, 0, $key_length);
	}
}
