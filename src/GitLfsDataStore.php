<?php

namespace wycomco\GitLfsPhp;

/**
* GitLfsDataStore manages Git LFS datastore
*
* Handles files stored by and for Git LFS by using OIDs and
* file sizes to identify actual items in the file system.
*
* @author   Matthias Choules <choules@example.com>
* @access   public
* @see      https://github.com/wycomco/git-lfs-php
*/
class GitLfsDataStore {
    
    /** @var GitLfsToken Token associated with current request */
    private $token = null;
    
    /** @var string Path to data store */
    private $directory = '';
    
    /** @var string Name of target repository */
    private $repo = '';
    
    /** @var string Requested operation: upload or download */
    private $operation = null;
    
    /** @var int File mode for directories and files */
    private $mode = 0777;
    
    /** @var array List with valid batch api methods */
    private $validMethods = array(
        'upload',
        'download',
    );
    
    public function __construct($directory = null) {
        
        if(!is_null($directory)) {
            $this->directory = $directory;
        }elseif(defined('GIT_LFS_DATA_DIR')) {
            $this->directory = GIT_LFS_DATA_DIR;
        }else {
            throw new \Exception('No data directory given');
        }

        // Remove trailing DIRECTORY_SEPARATOR
        if(substr($this->directory, -1) == DIRECTORY_SEPARATOR) {
            $this->directory = substr($this->directory, 0, -strlen(DIRECTORY_SEPARATOR));
        }

        if(defined('GIT_LFS_DATA_MODE')) {
            $this->mode = GIT_LFS_DATA_MODE;
        }

        if(!file_exists($this->directory)) {
            if(!mkdir($this->directory, $this->mode, true)) {
                throw new \Exception('Could not create data store directory.');
            }

            if(chmod($this->directory, $this->mode) === false) {
                throw new \Exception('Could not set permission on data store directory.');
            }
        }

        if(!is_writable($this->directory)) {
            throw new \Exception('Data store directory is not writable');
        }

        return $this;
    }
    
    public function set_repository($repo = null) {
        if(is_null($repo) || empty($repo) || !is_string($repo)) {
            throw new \Exception('Tried to set DataStore to blank repository name');
        }
        
        if(defined('GIT_LFS_REPOS')){
            if(!in_array($repo, unserialize(GIT_LFS_REPOS))) {
                throw new \Exception(404, 'Repository is not listed in configured repositories');
            }
        }
        
        $this->repo = $repo;
    }
    
    /**
    * Opens file handler to given object
    *
    * @param string $oid ID of object to open file handler
    * @param string $mode Mode for file handler
    *
    * @return mixed Returns file handler on success or false on errors.
    */
    public function fopen($oid, $mode) {
        
        $filename = $this->get_full_filename($oid);
        
        $dir = dirname($filename);
        
        if(!file_exists($dir)) {
            $createDirectory = mkdir($dir, $this->mode, true);
            
            if($createDirectory === false) {
                throw new \Exception('Error creating intermediate directories for object');
            }
        }
        
        if(!is_writable($dir)) {
            throw new \Exception('No writing permissions on directory.');
        }
        
        touch($filename);
        
        $this->chmod($oid);
        
        $handle = fopen($filename, $mode);
        
        if($handle === false) {
            throw new \Exception('Error opening file handle.');
        }
        
        return $handle;
    }
    
    /**
    * Reads file
    *
    * @param string $oid ID of object to open file handler
    *
    * @return mixed Returns file handler on success or false on errors.
    */
    public function readfile($oid, $size = null) {
        
        if(!$this->file_exists($oid, $size)) {
            return false;
        }
        
        $filename = $this->get_full_filename($oid);
        
        return readfile($filename);
    }
    
    
    /**
    * Checks if given oid exists in current repo
    *
    * @todo Validate if given file size matches the file in our data store
    *
    * @return bool True if file exists, false if not
    */
    public function file_exists($oid, $size = null) {
        
        $filename = $this->get_full_filename($oid);
        
        if(!file_exists($filename)) {
            return false;
        }
        
        if(!is_null($size) && filesize($filename) != $size) {
            return false;
        }
        
        return true;
    }
    
    /**
    * Gets base directory for the given repository
    *
    * @return string Path to base directory of repository data store
    */
    private function get_base_dir() {
        
        if(empty($this->repo)) {
           throw new \Exception('Tried to access repository with empty name. Was it set properly?'); 
        }
        
        return $this->directory.DIRECTORY_SEPARATOR.$this->repo;
    }
    
    /**
    * Gets the full path to the file with the given oid
    *
    * @param string $oid OID of the file
    *
    * @return string Full path to the file with oid in current repository
    */
    public function get_full_filename($oid) {
        return $this->get_base_dir().$this->prepare_file_name($oid);
    }
    
    /**
    * Generates the path to the file by splitting the given oid in smaller chunks
    *
    * @param string $oid OID of the file
    *
    * @return string File name including parent directories
    */
    private function prepare_file_name($oid) {
        
        if(strlen($oid) != 64){
            throw new \Exception('Expecting a 64 chars long SHA265 string as OID.');
        }
        
        // Getting 3-chars-long parts from the oid
        $splits = str_split($oid, 2);
        
        $path = '';
        
        for($i = 0; $i < 5; $i++) {
            $path .= DIRECTORY_SEPARATOR.$splits[$i];
        }
        
        $path .= DIRECTORY_SEPARATOR.$oid;
        
        return $path;
    }
    
    /**
    * Sets permissions on object and all parent directories
    *
    * @param string $oid OID of the file
    *
    * @return bool True on success
    */
    private function chmod($oid, $mode = null) {
        
        if(is_null($mode)) {
            $mode = $this->mode;
        }
        
        $baseDir = $this->get_base_dir();
        $filename = $this->prepare_file_name($oid);
        
        $filename = trim($filename, DIRECTORY_SEPARATOR);
        
        $subdirs = explode(DIRECTORY_SEPARATOR, $filename);
        
        $return = true;
        $return = $return && chmod($baseDir, $mode);
        
        foreach($subdirs AS $dir) {
            $baseDir .= DIRECTORY_SEPARATOR.$dir;
            $return = $return && chmod($baseDir, $mode);
        }
        
        if(!$return) {
            throw new \Exception('Error correcting file permissions.');
        }

        return $return;
    }

}