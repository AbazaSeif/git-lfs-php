<?php

namespace wycomco\GitLfsPhp;

/**
* GitLfsAuthToken represents an authentication token for Git LFS
*
* GitLfsAuthToken stores information on authenticated users and their
* access privileges on Git repositories. By now all tokens need to be
* saved on disk.
*
* Example usage:
* $token = GitLfsAuthToken::load('username');
* $token->add_privilege('company/repo', 'upload');
* $access = $token->has_privilege('company/repo', 'upload');
* $token->flush();
*
* @author   Matthias Choules <choules@example.com>
* @access   public
* @see      https://github.com/wycomco/git-lfs-php
*/
class GitLfsAuthToken {
    
    /** @var string User name */
    public $user = null;

    /** @var string Password for this token */
    protected $password = null;

    /** @var string Path to directory where tokens are saved */
    private $directory = '';

    /** @var int Time to live for tokens, given in seconds */
    private $ttl = 7200;

    /** @var \DateTime When will this token expire */
    private $expires_at = null;

    /** @var string Authorization header vor use in HTTP requests */
    private $auth_header = null;

    /** @var bool Was the token written to filesystem already */
    private $file_written = false;

    /** @var string Class name of the GitLfsAuthenticator, including namespaces */
    private $authenticator = '';

    /** @var array Associative array containing the valid Actions */
    private $validActions = array(
        'download' => 'R',
        'upload' => 'W',
    );

    /** @var array Assiciative array containing the named repositories as key and an array with permitted actions */
    protected $privileges = array();

    /**
    * Constructor for GitLfsAuthToken
    *
    * @param string $directory Directory in which the tokens should be stored, falls back to constant GIT_LFS_AUTH_TOKEN_DIR and system's tmp dir
    *
    * @return GitLfsAuthToken Returns this object.
    */
    public function __construct($directory = null) {
        if(!is_null($directory)) {
            $this->directory = $directory;
        }elseif(defined('GIT_LFS_AUTH_TOKEN_DIR')) {
            $this->directory = GIT_LFS_AUTH_TOKEN_DIR;
        }else {
            $this->directory = sys_get_temp_dir().DIRECTORY_SEPARATOR.'git_lfs_auth_tokens';
        }

        if(substr($this->directory, -1) != DIRECTORY_SEPARATOR) {
            $this->directory .= DIRECTORY_SEPARATOR;
        }

        if(!file_exists($this->directory)) {
            if(!mkdir($this->directory, 0777, true)) {
                throw new \Exception('Could not create token directory.');
            }

            if(chmod($this->directory, 0777) === false) {
                throw new \Exception('Could not set permission on token directory.');
            }
        }

        if(!is_writable($this->directory)) {
            throw new \Exception('Token directory is not writable');
        }

        $this->get_authenticator();

        return $this;
    }

    /**
    * Loads token or generates a new one if needed
    *
    * @param string $user Name of the user
    *
    * @return GitLfsAuthToken Returns loaded or created token.
    */
    public static function load($user = null) {
        if(empty($user)) {
            throw new \Exception('Error loading auth token because of missing username.');
        }

        $token = new GitLfsAuthToken();
        $token = $token->read_from_file($user);

        if($token != false && $token->expired()) {
            if(!$token->delete()) {
                throw new \Exception('Error deleting expired token.');
            }

            $token = false;
        }

        if($token === false) {
            $token = GitLfsAuthToken::create($user);
        }

        return $token;
    }

    /**
    * Creates new token for given User
    *
    * @param string $user Name of the user
    *
    * @return GitLfsAuthToken Returns created token.
    */
    public static function create($user = null) {
        if(empty($user)) {
            throw new \Exception('Error creating auth token because of missing username.');
        }

        $token = new GitLfsAuthToken();
        $token->user = $user;
        $token->generate_password();
        $token->write_to_file();

        return $token;
    }

    /**
    * Compares given password to token password
    *
    * @param string $password Password to check
    *
    * @return bool True if passwords match, false if not.
    */
    public function check_password($password = null) {
        if(empty($password)) {
            throw new \Exception('Error comparing passwords because given password is empty.');
        }

        return $password == $this->password;
    }

    /**
    * Writes authentication token to file.
    *
    * @return GitLfsAuthToken Returns this token on success
    */
    protected function write_to_file(){
        
        $filename = $this->get_filename();

        if(empty($this->user) || empty($this->password)) {
            throw new \Exception('Could not create token file, because user and password was not set properly');
        }

        if(empty($this->expires_at)) {
            $this->expires_at = new \DateTime('+'.$this->ttl.' seconds');
        }

        $contents = array(
            'user' => $this->user,
            'password' => $this->password,
            'privileges' => $this->privileges,
            'expires_at' => ($this->expires_at instanceof \DateTime) ? $this->expires_at->format('c') : '',
        );

        if(defined('JSON_PRETTY_PRINT')) {
            $contents = json_encode($contents, JSON_PRETTY_PRINT)."\n";
        }else {
            $contents = $this->prettyPrint(json_encode($contents))."\n";
        }
        

        if(file_put_contents($filename, $contents) === false) {
            throw new \Exception('Could not create token file');
        }

        if(chmod($filename, 0777) === false) {
            throw new \Exception('Could not set permission on token file.');
        }

        $this->file_written = true;

        return $this;
    }

    /**
    * Flushes all changes and writes token to file.
    *
    * @return $this
    */
    public function flush(){
        return $this->write_to_file();
    }

    /**
    * Reads authentication token from file
    *
    * @param string $user Name of the user
    *
    * @return $this|false Returns this object or false if an error occured.
    */
    protected function read_from_file($user = null) {
        if(empty($user)) {
            if(empty($this->user)) {
                throw new \Exception('Could not load token from file because no user given');
            }else{
                $user = $this->user;
            }
        }

        $this->user = $user;

        $filename = $this->get_filename();

        if(!file_exists($filename)) {
            return false;
        }

        $contents = file_get_contents($filename);

        if($contents === false) {
            throw new \Exception('Could not read token from file. ');
            return false;
        }

        // Decode json and return contents as associative array
        $contents = json_decode($contents, true);

        if(is_null($contents)) {
            throw new \Exception('Could not decode token contents.');
        }

        if(empty($contents['user']) || empty($contents['password'])) {
            throw new \Exception('Token not valid.');
        }

        $this->file_written = true;

        return $this->parse_array($contents);
    }

    /**
    * Parses an array and sets the object properties accordingly
    *
    * @param array $properties An array containing the properties
    *
    * @return $this
    */
    protected function parse_array(array $properties) {
        if(!is_array($properties) || empty($properties)) {
            throw new \Exception('Could not parse array into auth token');
        }

        if(isset($properties['user']) && is_string($properties['user'])) {
            $this->user = $properties['user'];
        }

        if(isset($properties['password']) && is_string($properties['password'])) {
            $this->password = $properties['password'];
        }

        if(isset($properties['privileges']) && is_array($properties['privileges'])) {
            $this->privileges = $properties['privileges'];
        }

        if(isset($properties['expires_at']) && is_string($properties['expires_at']) && $properties['expires_at'] != '') {
            $this->expires_at = \DateTime::createFromFormat(\DateTime::ISO8601, $properties['expires_at']);
        }

        $this->generate_auth_header();

        return $this;
    }

    /**
    * Generate HTTP authentication header for this token
    *
    * @param string $user Name of the user, whose privs should be checked (Default: $this->user)
    * @param string $password Password for the user (Default: $this->password)
    *
    * @return string String to be used in an HTTP authorization header
    */
    protected function generate_auth_header($user = null, $password = null) {
        $auth_header = '';

        if(empty($user)) {
            if(empty($this->user)) {
                throw new \Exception('Could not generate auth header because no user given');
            }else{
                $user = $this->user;
            }
        }

        if(empty($password)) {
            if(empty($this->password)) {
                throw new \Exception('Could not generate auth header because no password given');
            }else{
                $password = $this->password;
            }
        }
        
        $auth_header = 'Basic '.base64_encode($user.':'.$password);

        $this->auth_header = $auth_header;
        
        return $this->auth_header;
    }

    /**
    * Get HTTP authentication header for this token
    *
    * @return string String to be used in an HTTP authorization header
    */
    public function get_auth_header() {
        return $this->auth_header;
    }

    /**
    * Get Expires-At string for JSON-Responses
    *
    * @return string String to be used in an JSON responses
    */
    public function get_expires_at() {
        return $this->expires_at->format('c');
    }

    /**
    * Add privilege for specified repository
    *
    * @param string $repo Name of the repository
    * @param string $action Name for action which this token authorizes
    *
    * @return $this Returns this object
    */
    public function add_privilege($repo = null, $action = null){
        if(empty($repo) || !is_string($repo) || $repo == '') {
            throw new \Exception('Could not add privilege because of missing repo name');
            return false;
        }

        if(empty($action) || !is_string($action) || $action == '') {
            throw new \Exception('Could not add privilege because of missing action name');
            return false;
        }

        if(!isset($this->validActions[$action])) {
            throw new \Exception('Could not add privilege because named action is not valid');
            return false;
        }

        if(!isset($this->privileges[$repo]) || !is_array($this->privileges[$repo])) {
            $this->privileges[$repo] = array();
        }

        if(!in_array($action, $this->privileges[$repo])) {
            $this->privileges[$repo][] = $action;
        }

        return $this; 
    }

    /**
    * Has privilege for specified repository
    *
    * @param string $repo Name of the repository
    * @param string $action Name for action which this token authorizes
    *
    * @return bool True if privileg is set, false if not
    */
    public function has_privilege($repo = null, $action = null){
        if(empty($repo) || !is_string($repo) || $repo == '') {
            throw new \Exception('Could not check on privilege because of missing repo name');
            return false;
        }

        if(empty($action) || !is_string($action) || $action == '') {
            throw new \Exception('Could not check on privilege because of missing action name');
            return false;
        }

        if(!isset($this->validActions[$action])) {
            throw new \Exception('Could check on privilege because named action is not valid');
            return false;
        }

        if(!isset($this->privileges[$repo]) || !is_array($this->privileges[$repo])) {
            $this->privileges[$repo] = array();
        }

        return in_array($action, $this->privileges[$repo]);
    }

    /**
    * Removes privilege for specified repository
    *
    * @param string $repo Name of the repository
    * @param string $action Name for action which this token authorizes
    *
    * @return $this Returns this object
    */
    public function remove_privilege($repo = null, $action = null){
        if(empty($repo) || !is_string($repo) || $repo == '') {
            throw new \Exception('Could not remove privilege because of missing repo name');
            return false;
        }

        if(empty($action) || !is_string($action) || $action == '') {
            throw new \Exception('Could not remove privilege because of missing action name');
            return false;
        }

        if(!isset($this->validActions[$action])) {
            throw new \Exception('Could not remove privilege because named action is not valid');
            return false;
        }

        if(!isset($this->privileges[$repo]) || !is_array($this->privileges[$repo])) {
            $this->privileges[$repo] = array();
        }

        if(in_array($action, $this->privileges[$repo])) {
            $this->privileges[$repo] = array_diff($this->privileges[$repo], array($action));
        }
        
        if(count($this->privileges[$repo]) == 0) {
            unset($this->privileges[$repo]);
        }

        return $this; 
    }

    /**
    * Removes allprivileges for specified repository
    *
    * @param string $repo Name of the repository
    *
    * @return $this Returns this object
    */
    public function remove_privileges($repo = null){
        if(empty($repo) || !is_string($repo) || $repo == '') {
            throw new \Exception('Could not remove privileges because of missing repo name');
            return false;
        }

        $this->privileges[$repo] = array();
        
        return $this; 
    }

    /**
    * Extends the Time to Live for this token
    *
    * @return $this Returns this object
    */
    public function extend_ttl() {
        
        if($this->file_written) {
            $filename = $this->get_filename();

            if(file_exists($filename) && touch($filename)) {
                $this->expires_at = new \DateTime('+'.$this->ttl.' seconds');
                $this->write_to_file();
                return $this;
            }else {
                throw new \Exception('Could not extend TTL on token.');
            }
        }else{
            $this->expires_at = new \DateTime('+'.$this->ttl.' seconds');
            $this->write_to_file();
            return $this;
        }
    }

    /**
    * Gets full file name for this token – but does no check on exitance
    *
    * @return string Full path to token file
    */
    private function get_filename() {
        return $this->directory.DIRECTORY_SEPARATOR.$this->user;
    }

    /**
    * Checks if this token has expired
    *
    * @return bool True if token has expired, false if it still is valid
    */
    public function expired() {
        if($this->expires_at < new \DateTime()) {
            return true;
        }else{
            return false;
        }
    }
    
    /**
    * Deletes this token
    *
    * @return bool True if token has been deleted, false if deletion failed
    */
    public function delete() {

        if($this->file_written) {
            $filename = $this->get_filename();
            $success = unlink($filename);
        }else {
            $success = true;
        }

        if($success) {
            $this->user = null;
            $this->password = null;
            $this->privileges = null;
            $this->auth_header = '';
            $this->file_written = false;
            $this->expires_at = new \DateTime('-10 days');
            return true;
        }else {
            return false;
        }
    }

    /**
    * Returns json representation of this token 
    *
    * @return string JSON
    */
    public function get_json(){
        $json = array(
            'header' => array(
                'Authorization' => $this->auth_header,
            ),
            'expires_at' => $this->expires_at->format('c'),
        );

        // Check for Support on JSON_PRETTY_PRINT
        if(defined('JSON_PRETTY_PRINT')) {
            return json_encode($json, JSON_PRETTY_PRINT)."\n";
        }else {
            return $this->prettyPrint(json_encode($json))."\n";
        }
    }

    /**
    * Returns prettified JSON, source: http://stackoverflow.com/a/9776726 
    *
    * @return string JSON
    */
    public static function prettyPrint($json) {
        $result = '';
        $level = 0;
        $in_quotes = false;
        $in_escape = false;
        $ends_line_level = NULL;
        $json_length = strlen( $json );

        for( $i = 0; $i < $json_length; $i++ ) {
            $char = $json[$i];
            $new_line_level = NULL;
            $post = "";
            if( $ends_line_level !== NULL ) {
                $new_line_level = $ends_line_level;
                $ends_line_level = NULL;
            }
            if ( $in_escape ) {
                $in_escape = false;
            } else if( $char === '"' ) {
                $in_quotes = !$in_quotes;
            } else if( ! $in_quotes ) {
                switch( $char ) {
                    case '}':
                    case ']':
                        $level--;
                        $ends_line_level = NULL;
                        $new_line_level = $level;
                    break;

                    case '{':
                    case '[':
                        $level++;
                    
                    case ',':
                        $ends_line_level = $level;
                    break;

                    case ':':
                        $post = " ";
                    break;

                    case " ":
                    case "\t":
                    case "\n":
                    case "\r":
                        $char = "";
                        $ends_line_level = $new_line_level;
                        $new_line_level = NULL;
                    break;
                }
            } else if ( $char === '\\' ) {
                $in_escape = true;
            }
            if( $new_line_level !== NULL ) {
                $result .= "\n".str_repeat("\t", $new_line_level);
            }
            $result .= $char.$post;
        }

        return $result;
    }

    /**
    * Generates password for this token 
    *
    * @return $this
    */
    public function generate_password($length = 24) {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $count = strlen($chars);

        for ($i = 0, $result = ''; $i < $length; $i++) {
            $index = rand(0, $count - 1);
            $result .= substr($chars, $index, 1);
        }

        $this->password = $result;
        
        $this->generate_auth_header();

        return $this;
    }
    
    /**
    * Tries to get the used GitLfsAuthenticator 
    *
    * @return void
    */
    protected function get_authenticator() {
        $backtrace = debug_backtrace();
        
        $authenticator = '';
        
        foreach($backtrace AS $call) {
            if(isset($call['class'])) {
                $interfaces = class_implements($call['class']);
                if(in_array('wycomco\GitLfsPhp\GitLfsAuthenticatorInterface', $interfaces)) {
                    $authenticator = $call['class'];
                }
            }
        }

        $this->authenticator = $authenticator;
    }
    
    /**
    * Revalidates the access present privileges for this token 
    *
    * @return bool True on success, false on failure
    */
    public function revalidate() {
        
        // Needs a valid Authenticator
        if(empty($this->authenticator) || !class_exists($this->authenticator)) {
            return false;
        }

        $authenticator = $this->authenticator;
        
        foreach($this->privileges AS $repo => $privileges) {
            foreach($privileges AS $action) {
                if(!$authenticator::has_access($repo, $this->user, $action)) {
                    if(!$this->remove_privilege($repo, $action)) {
                        return false;
                    }    
                }
            }
        }
        
        $this->extend_ttl();
        
        return true;
    }
}