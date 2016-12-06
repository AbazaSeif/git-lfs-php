<?php

namespace wycomco\GitLfsPhp;

class GitLfsBatchApi {
    
    /** @var GitLfsToken Token associated with current request */
    private $token = null;
    
    /** @var string Name of target repository */
    private $repo = '';
    
    /** @var string Path to data store */
    private $directory = '';
    
    /** @var GitLfsDataStore Handler for DataStore */
    private $dataStore = null;
    
    /** @var string Requested operation: upload or download */
    private $operation = '';
    
    /** @var string Requested objects */
    private $objects = array();
    
    /** @var array List with valid batch api operations */
    private $validOperations = array(
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

        if(substr($this->directory, -1) != DIRECTORY_SEPARATOR) {
            $this->directory .= DIRECTORY_SEPARATOR;
        }

        if(!file_exists($this->directory)) {
            if(!mkdir($this->directory, 0777, true)) {
                throw new \Exception('Could not create data store directory.');
            }

            if(chmod($this->directory, 0777) === false) {
                throw new \Exception('Could not set permission on data store directory.');
            }
        }

        if(!is_writable($this->directory)) {
            throw new \Exception('Data store directory is not writable');
        }

        if(!$this->validate_http_request()) {
            throw new \Exception('Received HTTP request did not comply to API specification.');
        }
        
        $this->repo = $this->get_repo_from_request();
        $this->authenticate();
        $this->parse_request_body();
        $this->authorize();
        $this->process_objects();
        $this->return_json_response();
        
        return $this;
    }
    
    /**
    * Return the API response
    *
    * @return void
    */
    private function return_json_response() {
        
        $response = array(
            'transfer' => 'basic',
            'objects' => $this->objects,
        );
        
        header('HTTP/1.1 200 Ok');
        
        $this->return_as_json($response);
    }
    
    /**
    * Authenticates user with HTTP basic auth
    *
    * @return bool True on success
    */
    private function authenticate() {
        
        if(!isset($_SERVER['PHP_AUTH_USER']) || empty($_SERVER['PHP_AUTH_USER'])) {
            $this->return_response_error(401, 'Username not given or empty');
        }
        
        if(!isset($_SERVER['PHP_AUTH_PW']) || empty($_SERVER['PHP_AUTH_PW'])) {
            $this->return_response_error(401, 'Password not given or empty');
        }
        
        $token = GitLfsAuthToken::load($_SERVER['PHP_AUTH_USER']);
        
        if(!$token->check_password($_SERVER['PHP_AUTH_PW'])) {
            $this->return_response_error(401, 'Passwords do not match');
        }
        
        $this->token = $token;
        
        return true; 
    }
    
    /**
    * Authorizes the current request
    *
    * @return bool True on success
    */
    private function authorize() {
        
        if(!isset($this->repo) || empty($this->repo)) {
            throw new \Exception('Error authorizing request. Repo not given.');
        }
        
        if(!isset($this->operation) || empty($this->operation)) {
            throw new \Exception('Error authorizing request. Operation not given.');
        }
        
        if(!isset($this->token) || empty($this->token)) {
            throw new \Exception('Error authorizing request. Token not given.');
        }
        
        if(!$this->token->has_privilege($this->repo, $this->operation)) {
            if($this->operation == 'upload') {
                $this->return_response_error(403);
            }else{
                $this->return_response_error(404);
            }
        }
        
        return true;
    }
    
    /**
    * Get name of Git repository, which is targeted by this request
    *
    * @return string Name of Git repository
    */
    private function get_repo_from_request() {
        
        $requestUri = $_SERVER['REQUEST_URI'];
        
        // Omit query string
        $requestUri = explode('?', $requestUri);
        $requestUri = $requestUri[0];
        
        $apiEndPointString = '/info/lfs/objects/batch';
        
        // If the request does not end with the API endpoint string, something strange has happened
        if(substr($requestUri, -(strlen($apiEndPointString))) != $apiEndPointString) {
            throw new \Exception('API endpoint was not addressed correctly');
        }
        
        $repo = trim(substr($requestUri, 0, -strlen($apiEndPointString)), '/');
        
        $repo = GitLfsAuthenticator::prepare_repo_name($repo);
        
        if(defined('GIT_LFS_REPOS')){
            if(!in_array($repo, unserialize(GIT_LFS_REPOS))) {
                $this->return_response_error(404, 'Repository is not listed in configured repositories');
            }
        }
        return $repo;
    }
    
    /**
    * Processes the listed objects and modifies the class property correspondingly
    *
    * @return $this
    */
    private function process_objects() {
        
        if(in_array($this->operation, $this->validOperations)) {
            if(!is_callable(array($this, 'process_objects_for_'.$this->operation))) {
                throw new \Exception('Tried to call an object processor which is not available.');
            }
            
            return call_user_func(array($this, 'process_objects_for_'.$this->operation));
        }else {
            throw new \Exception('Tried to call an unknown object processor.');
        }
    }
    
    /**
    * Processes the listed objects for upload and modifies the class property correspondingly
    *
    * @return $this
    */
    private function process_objects_for_upload() {
        
        if($this->dataStore instanceof GitLfsDataStore) {
            $dataStore = $this->dataStore;
        }else {
            $this->dataStore = new GitLfsDataStore($this->directory);
            $dataStore = $this->dataStore;
        }
        
        $dataStore->set_repository($this->repo);
        
        foreach($this->objects AS &$object) {
            $object['authenticated'] = true;
            $object['actions'] = array();
            
            if($dataStore->file_exists($object['oid'], $object['size'])) {
                unset($object['actions']);
            }else{
                $object['actions'] = array(
                    'upload' => array(
                        'href' => $this->get_upload_url($object['oid'], $object['size']),
                        'header' => array(
                            'Authorization' => $this->token->get_auth_header(),
                        ),
                        'expires_at' => $this->token->get_expires_at(),
                    ),
                    'verify' => array(
                        'href' => $this->get_verify_url($object['oid'], $object['size']),
                        'header' => array(
                            'Authorization' => $this->token->get_auth_header(),
                        ),
                        'expires_at' => $this->token->get_expires_at(),
                    ),
                );
            }
        }
        
        return $this;
    }
    
    /**
    * Processes the listed objects for download and modifies the class property correspondingly
    *
    * @return $this
    */
    private function process_objects_for_download() {
        
        if($this->dataStore instanceof GitLfsDataStore) {
            $dataStore = $this->dataStore;
        }else {
            $this->dataStore = new GitLfsDataStore($this->directory);
            $dataStore = $this->dataStore;
        }
        
        $dataStore->set_repository($this->repo);
        
        foreach($this->objects AS &$object) {
            $object['authenticated'] = true;
            $object['actions'] = array();
            
            if(!$dataStore->file_exists($object['oid'], $object['size'])) {
                unset($object['actions']);
                $object['error'] = array(
                    'code' => 404,
                    'message' => 'Object does not exist',
                );
            }else{
                $object['actions'] = array(
                    'download' => array(
                        'href' => $this->get_download_url($object['oid'], $object['size']),
                        'header' => array(
                            'Authorization' => $this->token->get_auth_header(),
                        ),
                        'expires_at' => $this->token->get_expires_at(),
                    ),
                );
            }
        }
        
        return $this;
    }
    
    private function get_upload_url($oid, $size = null) {
        return $_SERVER['REQUEST_SCHEME'].'://'.$_SERVER['HTTP_HOST'].'/'.str_replace(DIRECTORY_SEPARATOR, '/', $this->repo).'/info/lfs/objects/upload?oid='.$oid.'&size='.$size;
    }
    
    private function get_download_url($oid, $size = null) {
        return $_SERVER['REQUEST_SCHEME'].'://'.$_SERVER['HTTP_HOST'].'/'.str_replace(DIRECTORY_SEPARATOR, '/', $this->repo).'/info/lfs/objects/download?oid='.$oid.'&size='.$size;
    }
    
    private function get_verify_url($oid, $size = null) {
        return $_SERVER['REQUEST_SCHEME'].'://'.$_SERVER['HTTP_HOST'].'/'.str_replace(DIRECTORY_SEPARATOR, '/', $this->repo).'/info/lfs/objects/verify?oid='.$oid.'&size='.$size;
    }
    
    /**
    * Parses the JSON body of the current request
    *
    * @return $this
    */
    private function parse_request_body() {
        
        $requestBody = file_get_contents('php://input');
        
        if($requestBody == '') {
            $this->return_response_error(500, 'Request body was empty');
        }
        
        // Decode json and return contents as associative array
        $contents = json_decode($requestBody, true);

        if(is_null($contents)) {
            $this->return_response_error(500, 'Could not decode request contents.');
        }

        if(!$this->validate_json_request($contents)) {
            $this->return_response_error(422);
        }
        
        $this->operation = $contents['operation'];
        
        $this->objects = $contents['objects'];
        
        return $this;
    }
    
    /**
    * Validates given JSON to correspond to JSON schema
    *
    * @todo Should be automated, for example with https://github.com/justinrainbow/json-schema
    *
    * @param mixed $json JSON to be validated
    *
    * @return bool True on success, false on error
    */
    private function validate_json_request($json) {
        
        if(!isset($json['operation'])) {
            error_log('JSON is missing operation property');
            return false;
        }
        
        if(!isset($json['objects'])) {
            error_log('JSON is missing objects property');
            return false;
        }
        
        if(!in_array($json['operation'], $this->validOperations)) {
            $this->return_response_error(501, 'Operation '.$json['operation'].' not known to this server');
            return false;
        }
        
        if(!is_array($json['objects'])) {
            error_log('Did not found an array of JSON objects');
            return false;
        }
        
        if(count($json['objects']) < 1) {
            error_log('Did not found any JSON objects');
            return false;
        }
        
        foreach($json['objects'] AS $object) {
            if(!isset($object['oid']) OR !is_string($object['oid'])) {
                return false;
            }
            
            if(!isset($object['size']) OR !is_numeric($object['size'])) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
    * Returns the the given error correctly formated as JSON to the client
    *
    * Details: https://github.com/git-lfs/git-lfs/blob/master/docs/api/batch.md
    * 
    * @param int $error_code Corresponds to the HTTP error codes
    * @param string $message Additional message which will be appended to the default error message
    *
    * @return void
    */
    private function return_response_error($error_code = 500, $message = '') {
        
        $error_code = (string) $error_code;
        
        $defaultErrorCodes = array(
            '401' => array(
                'http_message' => 'Unauthorized',
                'custom_message' => 'Credentials needed',
            ),
            '403' => array(
                'http_message' => 'Forbidden',
                'custom_message' => 'The user has read, but not write access.',
            ),
            '404' => array(
                'http_message' => 'Not Found',
                'custom_message' => 'The Repository does not exist for the user',
            ),
            '406' => array(
                'http_message' => 'Not Acceptable',
                'custom_message' => 'The Accept header needs to be application/vnd.git-lfs+json.',
            ),
            '422' => array(
                'http_message' => 'Unprocessable Entity',
                'custom_message' => 'Validation error with one or more of the objects in the request. This means that none of the requested objects to process are valid.',
            ),
            '429' => array(
                'http_message' => 'Too Many Requests',
                'custom_message' => 'The user has hit a rate limit with the server. Though the API does not specify any rate limits, implementors are encouraged to set some for availability reasons.',
            ),
            '500' => array(
                'http_message' => 'Internal Server Error',
                'custom_message' => 'An unknown error occured',
            ),
            '501' => array(
                'http_message' => 'Not Implemented',
                'custom_message' => 'The server has not implemented the current method. Reserved for future use.',
            ),
            '507' => array(
                'http_message' => 'Insufficient Storage',
                'custom_message' => 'The server has insufficient storage capacity to complete the request.',
            ),
            '509' => array(
                'http_message' => 'Bandwidth Limit Exceeded',
                'custom_message' => 'The bandwidth limit for the user or repository has been exceeded. The API does not specify any bandwidth limit, but implementors may track usage.',
            ),
        );
        
        if(!isset($defaultErrorCodes[$error_code])) {
            $error_code = '500';
        }
        
        $error_message = $defaultErrorCodes[$error_code]['custom_message'];
        
        if($message != '') {
            if($error_message != '') {
                $error_message .= ' - ';
            }
            
            $error_message .= $message;
        }
        
        $response = array(
            'message' => $error_message,
            'documentation_url' => '',
            'request_id' => '',
        );     

        header('HTTP/1.1 '.$error_code.' '.$defaultErrorCodes[$error_code]['http_message']);
        
        if($error_code == '401') {
            header('LFS-Authenticate: Basic realm="Git LFS"');
        }
        
        $this->return_as_json($response);
    }
    
    /**
    * Returns the given object as JSON to the client
    *
    * Sets the requires Content-Type header:
    * Content-Type: application/vnd.git-lfs+json
    * Details: https://github.com/git-lfs/git-lfs/blob/master/docs/api/batch.md
    * 
    * @param mixed $object In most cases this is an array containing the information which should be sent to the client
    *
    * @return void
    */
    private static function return_as_json($object = '') {
        header('Content-Type: application/vnd.git-lfs+json');
        
        // Check for Support on JSON_PRETTY_PRINT
        if(defined('JSON_PRETTY_PRINT')) {
            echo json_encode($object, JSON_PRETTY_PRINT)."\n";
        }else {
            echo GitLfsAuthToken::prettyPrint(json_encode($object))."\n";
        }
        
        exit;
    }
    
    /**
    * Validates the needed HTTP headers and request type
    *
    * All requests to the batch API require the following HTTP headers:
    * Accept: application/vnd.git-lfs+json
    * Content-Type: application/vnd.git-lfs+json
    * Details: https://github.com/git-lfs/git-lfs/blob/master/docs/api/batch.md
    * 
    * @return bool 
    */
    private function validate_http_request() {
        
        if($_SERVER['REQUEST_METHOD'] != 'POST') {
            error_log('Git LFS Batch API requires HTTP POST request. Instead received a request of type '.$_SERVER['REQUEST_METHOD']);
            return false;
        }
        
        $requiredHeaders = array(
            'Accept' => 'application/vnd.git-lfs+json',
            'Content-Type' => 'application/vnd.git-lfs+json',
        );
        
        foreach($requiredHeaders AS $key => $value) {
            
            $key = str_replace('-', '_', strtoupper($key));
            
            if(!isset($_SERVER['HTTP_'.$key])) {
                error_log('Git LFS Batch API requires the HTTP header '.$key);
                return false;
            }
            
            $givenValue = $_SERVER['HTTP_'.$key];
            
            if($givenValue != $value && strpos($givenValue, $value) === false) {
                $this->return_response_error(406, 'Git LFS Batch API requires the value "'.$value.'" for HTTP header '.$key.' but received '.$givenValue);
                return false;
            }            
            
        }
        
        return true;
        
    }
}