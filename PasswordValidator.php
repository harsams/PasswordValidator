<?php
/**
 * @author	    		Harutyun Samsonyan - email: <harsams@gmail.com>
 * @since				2013-04-29
 * @desc				validate given password and return array with errors if password doesn't pass validation rules,
 * 						which are followings`
 * 						1 - Password should include at least one upper and one lower case letter
 * 						2 - Password should have at least one numerical digit
 * 						3 - Password should have at least 1 special char (characters other than a-z, A-Z, and 0-9)
 * 						4 - Password should be at least 6 chars long and maximum 18 chars long
 * 						5 - Password must not contains the user's entire account name(first name, last name, email)
 * 						6 - Password must not contain any white spaces
 * 						7 - Password must not be equal with given particular words
 * 						8 - Old and new passwords must not have more then 50% similarity
 * 						9 - Password must not contains more then 3 sequences characters
 * @return				(array) $errors
 */
class PasswordValidator
{
	private $newPassword = '';
	# require for comparing with new password
	private $oldPassword = '';
	# require for rule #5 array with indexes 'email', 'first_name', 'last_name', 'user_name'
	private $userInfo = array('email' => '', 'first_name' => '', 'last_name' => '', 'user_name' => '');
	private $errors = array();
	private $particularWords = array(
									'password',		'password1',
									'123456',		'1234567',
									'12345678',		'123123',
									'abc123',		'qwerty',
									'monkey',		'letmein',
									'dragon',		'111111',
									'baseball',		'iloveyou',
									'trustno1',		'sunshine',
									'master',		'welcome',
									'shadow',		'ashley',
									'football',		'jesus',
									'michael',		'ninja',
									'mustang',
								);
	
	public function __construct($newPassword, $userInfo = false, $oldPassword = '') {
		$this->newPassword = $newPassword;
		if ( is_array($userInfo) ) {
			foreach ( $userInfo as $key => $currentField )
				$this->userInfo[$key] = $currentField;
		}
		$this->oldPassword = $oldPassword;
	}
	
	/*
	 * validate all rules and return errors
	* */
	public function validate() {
		$this->validateCaseSensitivity();
		$this->validateNumericCharacter();
		$this->validateSpecialCharacter();
		$this->validateLength();
		$this->validateUserInfo();
		$this->validateWhiteSpaces();
		$this->validateParticularWords();
		$this->validateCharactersSequence();
		if ( $this->oldPassword )
			$this->validateOldPassword();
		return $this->errors;
	}
	
	/*
	 * validate rules which are given with method's argument and return errors
	 * 
	 * -- EXAMPLE --
	 * $userInfo = array();
	 * $pass = "monkey ";
	 * $oldPass = "nilkey";
	 * $validation = new PasswordValidation($pass, $userInfo, $oldPass);
	 * $errors = $validation->validateSpecificRules(array('validateCaseSensitivity', 'validateOldPassword'));
	 * var_dump($errors);
	 * -- RESULT --
	 * array(2) { 
	 * 				[0]=> string(55) "Password should include at least one upper case letter." 
	 * 				[1]=> string(75) "Old and new passwords have 61% similarity. It must to be not more then 50%." 
	 * } 
	 * */
	public function validateSpecificRules($rules = array()) {
		foreach ( $rules as $rule )
			$this->$rule();
		return $this->errors;
	}
	
	# rule #1
	private function validateCaseSensitivity() {
		if ( !preg_match('/[A-Z]/', $this->newPassword) )
			$this->errors[] = 'Password should include at least one upper case letter.';
		if ( !preg_match('/[a-z]/', $this->newPassword) )
			$this->errors[] = 'Password should include at least one lower case letter.';
	}
	
	# rule #2
	private function validateNumericCharacter() {
		if ( !preg_match('#[0-9]#', $this->newPassword) )
			$this->errors[] = 'Password should have at least one numerical digit.';
	}
	
	# rule #3
	private function validateSpecialCharacter() {
		if ( !preg_match('/[^a-zA-Z0-9 ]+/', $this->newPassword) )
			$this->errors[] = 'Password should have at least 1 special character.';
	}
	
	# rule #4
	private function validateLength() {
		if ( strlen($this->newPassword) < 6 )
			$this->errors[] = 'Password should be at least 6 characters long.';
		if ( strlen($this->newPassword) > 18 )
			$this->errors[] = 'Password should be maximum 18 characters long.';
	}
	
	# rule #5
	private function validateUserInfo() {
		#compare with user email
		$email = explode("@", $this->userInfo['email']);
		$email = $email[0];
		if ( $email && strpos( strtolower($this->newPassword), strtolower($email) ) !== false )
    		$this->errors[] = 'Password must not contains the user\'s account email.';
		
		$firstNameParts = explode(" ", $this->userInfo['first_name']);
		foreach ($firstNameParts as $firstNamePart) {
			#compare with user first name
			if ( $firstNamePart && strpos( strtolower($this->newPassword), strtolower($firstNamePart) ) !== false ) {
				$this->errors[] = 'Password must not contains the user\'s entire account first name.';
				break;
			}
		}
		
		$lastNameParts = explode(" ", $this->userInfo['last_name']);
		foreach ($lastNameParts as $lastNamePart) {
			#compare with user last name
			if ( $lastNamePart && strpos( strtolower($this->newPassword), strtolower($lastNamePart) ) !== false ) {
				$this->errors[] = 'Password must not contains the user\'s entire account last name.';
				break;
			}
		}
		#compare with user last name
		if ( $this->userInfo['last_name'] && strpos( strtolower($this->newPassword), strtolower($this->userInfo['last_name']) ) !== false )
			$this->errors[] = 'Password must not contains the user\'s entire account last name.';
		#compare with user name (for admins)
		if ( $this->userInfo['user_name'] && strpos( strtolower($this->newPassword), strtolower($this->userInfo['user_name']) ) !== false )
			$this->errors[] = 'Password must not contains the user\'s entire account user name.';
	}
	
	# rule #6
	private function validateWhiteSpaces() {
		if ( preg_match('/\s/', $this->newPassword) )
			$this->errors[] = 'Password cannot contain white spaces.';
	}
	
	# rule #7
	private function validateParticularWords() {
		foreach ( $this->particularWords as $particularWord ) {
			if ( strpos( strtolower($this->newPassword), strtolower($particularWord) ) !== false ) {
				$this->errors[] = 'You are using a word or sequence that is not allowed, please try another password.';
				break;
			}
		}
	}
	
	# rule #8
	private function validateOldPassword() {
		similar_text($this->newPassword, $this->oldPassword, $p);
		$p = (int) $p;
		if ( $p > 50 )
			$this->errors[] = "New password is too similar with old one. Please enter another password.";
	}
	
	# rule #9 - pregenerate all possible 4 sequential combinations and check in password string
	private function validateCharactersSequence() {
		$sequentialWords = $this->getSequentialWords();
		foreach ( $sequentialWords as $sequentialWord ) {
			if ( strpos( strtolower($this->newPassword), strtolower($sequentialWord) ) !== false ) {
				$this->errors[] = 'Password cannot contain 4 sequenced characters.';
				break;
			}
		}
	}
	
	# rule #9 - old algorithm - get the password and check for every 4 chars in it, if they are sequential
	private function validateCharactersSequence_OLD() {
		$keyBoardMap = $this->getKeyboardMap();
		$newPassword = strtolower($this->newPassword);
		
		for ($charIndex = 0; $charIndex < strlen($newPassword); $charIndex++) {
			$next4Chars = substr($newPassword, $charIndex, 4);
			
			#continue loop for last 3 characters in password
			if ( strlen($next4Chars) < 4 )
				continue;
			
			$sequenceLenght = 0;
			
			#loop current 4 characters string and count distance between nearby chars
			for ( $next4CharsIndex = 0; $next4CharsIndex < 4; $next4CharsIndex++ ) {
				#continue loop last char
				if ( $next4CharsIndex == 3 )
					continue;
				
				#get current and next characters
				$currentIndex = $next4CharsIndex;
				$currentChar = $next4Chars[$currentIndex];
				$nextChar = $next4Chars[++$currentIndex];
				
				#get X and Y coordinates for current and next characters from $keyBoardMap
				$currentCharX = null;
				$currentCharY = null;
				$nextCharX = null;
				$nextCharY = null;
				for($y = 0; $y < 10; $y++) {
					for ($x = 0; $x < 4; $x++) {
						if ( $currentChar == $keyBoardMap[$y][$x] ) {
							$currentCharX = $x;
							$currentCharY = $y;
						}
						if ( $nextChar == $keyBoardMap[$y][$x] ) {
							$nextCharX = $x;
							$nextCharY = $y;
						}
					}
				}
				
				#if both characters found in $keyBoardMap
				if ( !is_null($currentCharX) && !is_null($nextCharX) ) {
					if ( ($currentCharX == $nextCharX) || ($currentCharY == $nextCharY) )
						$distance = abs( ($currentCharX - $nextCharX) + ($currentCharY - $nextCharY) );
					else
						# characters are not neighbours on keyboard
						break;
				} else
					# character not found in $keyBoardMap
					break;
				
				if ( $distance == 1 )
					$sequenceLenght++;
			}
			
			# check if $sequenceLenght is 3 (password contains 4 sequences characters) add error and break loop
			if ( $sequenceLenght == 3 ) {
				$this->errors[] = 'Password must not contain 4 sequences characters.';
				break;
			}
		}
	}
	
	#returns two-dimensional map for the standard qwerty keyboard (size 4x10)
	private function getKeyboardMap() {
		$keyBoardMap[0][0] = '1';
		$keyBoardMap[0][1] = 'q';
		$keyBoardMap[0][2] = 'a';
		$keyBoardMap[0][3] = 'z';
		
		$keyBoardMap[1][0] = '2';
		$keyBoardMap[1][1] = 'w';
		$keyBoardMap[1][2] = 's';
		$keyBoardMap[1][3] = 'x';
		
		$keyBoardMap[2][0] = '3';
		$keyBoardMap[2][1] = 'e';
		$keyBoardMap[2][2] = 'd';
		$keyBoardMap[2][3] = 'c';
		
		$keyBoardMap[3][0] = '4';
		$keyBoardMap[3][1] = 'r';
		$keyBoardMap[3][2] = 'f';
		$keyBoardMap[3][3] = 'v';
		
		$keyBoardMap[4][0] = '5';
		$keyBoardMap[4][1] = 't';
		$keyBoardMap[4][2] = 'g';
		$keyBoardMap[4][3] = 'b';
		
		$keyBoardMap[5][0] = '6';
		$keyBoardMap[5][1] = 'y';
		$keyBoardMap[5][2] = 'h';
		$keyBoardMap[5][3] = 'n';
		
		$keyBoardMap[6][0] = '7';
		$keyBoardMap[6][1] = 'u';
		$keyBoardMap[6][2] = 'j';
		$keyBoardMap[6][3] = 'm';
		
		$keyBoardMap[7][0] = '8';
		$keyBoardMap[7][1] = 'i';
		$keyBoardMap[7][2] = 'k';
		$keyBoardMap[7][3] = ',';
		
		$keyBoardMap[8][0] = '9';
		$keyBoardMap[8][1] = 'o';
		$keyBoardMap[8][2] = 'l';
		$keyBoardMap[8][3] = '.';
		
		$keyBoardMap[9][0] = '0';
		$keyBoardMap[9][1] = 'p';
		$keyBoardMap[9][2] = ';';
		$keyBoardMap[9][3] = '/';
		
		return $keyBoardMap;
	}
	
	#returns sequential words with length = 4
	private function getSequentialWords() {
		$sequentialWords = array();
		$keyboardMap = $this->getKeyboardMap();
		
		# add vertical sequential words
		for ( $i = 0; $i < 10; $i++ ) {
			$currentWord = '';
			for ( $j = 0; $j < 4; $j++ ) {
				$currentWord .= $keyboardMap[$i][$j];
			}
			$sequentialWords[] = $currentWord;
			$sequentialWords[] = strrev($currentWord);
		}
		
		# add horizontal sequential words
		for ( $j = 0; $j < 4; $j++ ) {
			for ( $currentIndex = 0; $currentIndex < 7; $currentIndex++ ) {
				$currentWord = '';
				for ( $i = 0; $i < 4; $i++ ) {
					$currentWord .= $keyboardMap[$currentIndex + $i][$j];
				}
				$sequentialWords[] = $currentWord;
				$sequentialWords[] = strrev($currentWord);
			}
		}

		return $sequentialWords;
	}
	
	/**
     * Generates a random password that is validated by all PasswordValidator
	 * rules.
     * 
     * @return string Generated password
     */
    public static function generatePassword($minLen = 6, $maxLen = 18, $chars = '', $exclude = '0,1,o,O,l,L,i,I') {
		$length = rand($minLen, $maxLen);
		# exclude list
		$exclude = explode(',', $exclude);
		if ( $chars === '' ) {
			# if chars are not manually set, use all chars from ASCII table
			# from DEC 33 to DEC 126
			for ( $i = 33; $i <= 126; $i++ ) {
				# exclude confusing chars
				$chars .= !in_array(chr($i), $exclude) ? chr($i) : '';
			}
		}
		while ( true ) {
			$password = substr(str_shuffle($chars), 0, $length);
			$passwordValidation = new self($password, false);
			$errors = $passwordValidation->validate();
			if ( !$errors ) {
				return $password;
			}
		}
    }
	
}