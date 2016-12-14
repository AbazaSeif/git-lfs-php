<?php

namespace wycomco\GitLfsPhp;

/**
* GitLfsAuthenticatorGitolite handles Git LFS authentication requests
*
* GitLfsAuthenticator authenticates request against Gitolite. It
* should be used by an SSH invocation of `git-lfs-authenticate`
*
* @author   Matthias Choules <choules@example.com>
* @access   public
* @see      https://github.com/wycomco/git-lfs-php
*/
class GitLfsAuthenticatorGitolite implements GitLfsAuthenticatorInterface {
    
    protected $targetRepo = '';
    protected $action = '';
    protected $glBinDir = '';
    protected $glUser = '';
    
    private $validActions = array(
        'download' => 'R',
        'upload' => 'W',
    );

    public $helpstring = "Authenticates against gitolite for Git LFS communication. Please refer to [1] for correct usage.\n\n[1] https://github.com/git-lfs/git-lfs/blob/master/docs/api/authentication.md\n\n"; 

    public function __construct($parameters) {

        $this->parse_parameters($parameters);

        // Getting Gitolite bin directory
        $this->glBinDir = getenv('GL_BINDIR');

        // Getting Gitolite user
        $this->glUser = getenv('GL_USER');

        if($this->glBinDir === FALSE || $this->glUser === FALSE) {
            throw new \Exception('Error getting enviroment vars from Gitolite.');
        }
    }
    
    /**
    * Parses parameters, mainly from command line invocation
    *
    * @param array $parameters Array with parameters, for example $argv
    *
    * @return void
    */
    protected function parse_parameters($parameters = array()) {
        // Return help string when invoked with a single '-h'
        if(count($parameters) == 2 && $parameters[1] == '-h') {
            echo $this->helpstring;
            exit();
        }

        // Expecting exactly two parameters
        if(count($parameters) != 3) {
            throw new \Exception('Error: Expecting exactly two parameters.'."\n\n".$this->helpstring);
        }

        // Getting targeted repository
        $this->targetRepo = $this->prepare_repo_name($parameters[1]);
        
        if(defined('GIT_LFS_REPOS')){
            if(!in_array($this->targetRepo, unserialize(GIT_LFS_REPOS))) {
                throw new \Exception('Given repository is not listed in configured Git LFS repositories.');
            }
        }

        // Getting requested action
        $this->action = $parameters[2];

        // If given action is not listed as valid action...
        if(!isset($this->validActions[$this->action])) {
            throw new \Exception('Error: Provided action not valid.'."\n\n".$this->helpstring);
        }
    }

    /**
    * Cleans name of target repository: removes trailing .git
    *
    * @param string $repo Name of the target repository, as it would be adressed by git-lfs-client
    *
    * @return string Cleaned name of target repository, as it would be expected by 'gitolite access'
    */
    public static function prepare_repo_name($repo) {

        $gitSuffix = '.git';

        if(substr($repo, -strlen($gitSuffix)) == $gitSuffix) {
            $repo = substr($repo, 0, -strlen($gitSuffix));
        }
        
        $repo = str_replace('/', DIRECTORY_SEPARATOR, $repo);

        return $repo;
    }

    /**
    * Checks access privileges for given repository and user
    *
    * @param string $repo Name of the target repository
    * @param string $user Name of the user, whose privs should be checked
    * @param string $action Target action for which the privs should be checked
    *
    * @return bool True if given user has access, false if not
    */
    public static function has_access($repo = null, $user = null, $action = null) {
        
        if(is_null($repo)) {
            $repo = $this->targetRepo = $this->prepare_repo_name($this->targetRepo);
        }

        if(is_null($user)) {
            $user = $this->glUser;
        }

        if(is_null($action)) {
            $action = $this->action;
        }

        $cmd = $this->glBinDir.DIRECTORY_SEPARATOR.'gitolite access -q '.$repo.' '.$user.' '.$this->validActions[$action];
        $output = array();
        $rval = null;
        
        exec($cmd, $output, $rval);
        
        if($rval == 0) {
            return true;
        }else{
            return false;
        }
    }

    /**
    * Authenticates User by checking access privs on given repository
    *
    * @return bool True on successful authentication
    */
    public function authenticate() {
        $token = GitLfsAuthToken::load($this->glUser);
        
        if($this->has_access()) {
            $token->add_privilege($this->targetRepo, $this->action);
            $token->flush();
            echo $token->get_json();
            return true;
        }else{
            $token->remove_privilege($this->targetRepo, $this->action);
            throw new \Exception('Access denied');
            return false;
        }
    }
}