# yii-pbkdf2

Yii PBKDF2 Password Hashing/Authentication Component

## Installation

Copy the `Auth.php` file into your `protected/components` folder of your project.

In `config/main.php` add the following in the `components` array:

    'auth'=>array('class'=>'Auth'),

## Usage

### UserIdentity

In `protected/components/UserIdentity.php` you will need to modify your `authenticate` method

    public function authenticate()
    {
        $record=User::model()->findByAttributes(array('username'=>$this->username));
        
        if($record===null)
            $this->errorCode=self::ERROR_USERNAME_INVALID;
        else if(Yii::app()->auth->validate_password($this->password, $record->salt, $record->password))
            $this->errorCode=self::ERROR_PASSWORD_INVALID;
        else
            $this->_id = $record->id;
            $this->errorCode=self::ERROR_NONE;
        return !$this->errorCode;
    }

You will also need to override the `getId` method

    public function getId()
    {
        return $this->_id;
    }
	
And don't forget to declare `$_id` at the top of the class

    private $id;

Refer to the Yii documentation for more on [authentication][1]

### Method calls

Always hash new passwords using the `generate_hash` method

    $auth = Yii::app()->auth->generate_hash('password');

This will return an object containing your new salt and the hashed password strings.
Store these values in your user table in your database for the user in question, for 
example when creating a new user or saving a new password. **The salt must be updated
with the newly-generated salt each time.**

Validate a password using the `validate_password` method

    $valid = Yii::app()->auth->validate_password($raw, $salt, $hash);

Where `$raw` is the string authenticating against, `$salt` is the user's salt from 
your table, and `$hash` is the user's hashed password from your table.


## Configuration

You can override the default properties of the component in `config/main.php` as such

    'auth'=>array(
        'class'=>'Auth',
        'algorithm'=>'sha256',
        'iterations'=>2048,
        'salt_bytes'=>42,
        'hash_bytes'=>42,
    ),

**algorithm** - the [hashing algorithm][2] you want to use

**iterations** - choose at least 1000

**salt_bytes** - how large of a salt to generate. You should never alter this value once you
have begun generating password/salt combinations. A value of 24 produces a string of 32 characters.

**hash_bytes** - how large of a hash to generate. You should never alter this value once you
have begun generating password/salt combinations. A value of 24 produces a string of 32 characters.

[1]: http://www.yiiframework.com/doc/guide/1.1/en/topics.auth "Yii Authentication and Authorization"
[2]: http://www.php.net/manual/en/function.hash-algos.php "Registered PHP hashing algorithms"

