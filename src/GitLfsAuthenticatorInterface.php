<?php

namespace wycomco\GitLfsPhp;

/**
* Interface for GitLfsAuthenticator
*
* Presents the needed functions for any implementation of an GitLfsAuthenticator
*
* @author   Matthias Choules <choules@example.com>
* @access   public
* @see      https://github.com/wycomco/git-lfs-php
*/
interface GitLfsAuthenticatorInterface {
    
    /**
    * Cleans name of target repository: removes trailing .git
    *
    * @param string $repo Name of the target repository, as it would be adressed by git-lfs-client
    *
    * @return string Cleaned name of target repository, as it would be expected by 'gitolite access'
    */
    public static function prepare_repo_name($repo);

    /**
    * Checks access privileges for given repository and user
    *
    * @param string $repo Name of the target repository
    * @param string $user Name of the user, whose privs should be checked
    * @param string $action Target action for which the privs should be checked
    *
    * @return bool True if given user has access, false if not
    */
    public static function has_access($repo = null, $user = null, $action = null);

    /**
    * Authenticates User by checking access privs on given repository
    *
    * @return bool True on successful authentication
    */
    public function authenticate();
}