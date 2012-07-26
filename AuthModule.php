<?php
/**
 * @author Kevin Lanni <therealklanni@gmail.com>
 * @name Yii PBKDF2 Password Hashing/Validating Module
 *
 * This module provides secure password hashing and authentication via the PBKDF2 method.
 * Original code by havoc AT defuse.ca / https://defuse.ca/php-pbkdf2.htm
 */

class ValidateModule
{
	const HASH_ALGORITHM = 'sha256';
	const ITERATIONS = 1024;
	const SALT_BYTES = 32;
	const HASH_BYTES = 32;
	
	const HASH_SECTIONS = 4;
	const HASH_ALGORITHM_INDEX = 0;
	const HASH_ITERATION_INDEX = 1;
	const HASH_SALT_INDEX = 2;
	const HASH_PBKDF2_INDEX = 3;
	
	/**
	 * Generates a secure hash
	 *
	 * @param string $password Raw password string
	 */
	public function create_hash($password)
	{
		$salt = base64_encode(mcrypt_create_iv(self::SALT_BYTES, MCRYPT_DEV_URANDOM));
		
		return self::HASH_ALGORITHM .':'. self::ITERATIONS .':'. $salt .':'.
			base64_encode(self::pbkdf2(
				self::HASH_ALGORITHM,
				$password,
				$salt,
				self::ITERATIONS,
				self::HASH_BYTES,
				true
			));
	}
	
	/**
	 * Check user input versus SHA256-encrypted and salted password hash
	 *
	 * @param string $password User input
	 * @param string $good_hash !! this probably needs to be broken down into multiple params
	 */
	public function validate_password($password, $good_hash)
	{
		$params = explode(':', $good_hash);
		
		if (count($params) < self::HASH_SECTIONS) return false;
		
		$pbkdf2 = base64_decode($params[self::HASH_PBKDF2_INDEX]);
		
		return self::slow_equals(
			$pbkdf2,
			self::pbkdf2(
				$params[self::HASH_ITERATION_INDEX],
				$password,
				$params[self::HASH_SALT_INDEX],
				(int) $params[self::HASH_ITERATION_INDEX],
				strlen($pbkdf2),
				true
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
	 * @param string $algorithm The hash algorithm to use. Recommended: SHA256
	 * @param string $password The password.
	 * @param string $salt A salt that is unique to the password.
	 * @param integer $count Iteration count. Higher is better, but slower. Recommended: At least 1000.
	 * @param integer $key_length The length of the derived key in bytes.
	 * @param boolean $raw_output If true, the key is returned in raw binary format. Hex encoded otherwise.
	 * @return string A $key_length-byte key derived from the password and salt.
	 *
	 * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
	 *
	 * This implementation of PBKDF2 was originally created by https://defuse.ca
	 * With improvements by http://www.variations-of-shadow.com
	 */
	protected function pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output = false)
	{
		$algorithm = strtolower($algorithm);
		
		if (!in_array($algorithm, hash_algos(), true)) return false; // Throw error: Invalid hash algorithm
		
		if ($count <= 0 || $key_length <= 0) return false; // Throw error: Invalid params
		
		$hash_length = strlen(hash($algorithm, "", true));
		$block_count = ceil($key_length / $hash_length);
		$output = "";
		
		for ($i = 1; $i <= $block_count; $i++)
		{
			// $i encoded as 4 bytes, big endian
			$last = $salt . pack("N", $i);
			
			// first iteration
			$last = $xorsum = hash_hmac($algorithm, $last, $password, true);
			
			// perform the other $count - 1 iterations
			for ($j = 1; $j < $count; $j++)
			{
				$xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
			}
			
			$output .= $xorsum;
		}
		
		if ($raw_output)
			return substr($output, 0, $key_length);
		else
			return bin2hex(substr($output, 0, $key_length));
	}
}
