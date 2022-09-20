<?php

/** Requiere the JWT library. */
use \Firebase\JWT\JWT;

/**
 * The public-facing functionality of the plugin.
 *
 * @link       https://enriquechavez.co
 * @since      1.0.0
 */
 
/**
 * The public-facing functionality of the plugin.
 *
 * Defines the plugin name, version, and two examples hooks for how to
 * enqueue the admin-specific stylesheet and JavaScript.
 *
 * @author     Enrique Chavez <noone@tmeister.net>
 */
class Jwt_Auth_Public
{
    /**
     * The ID of this plugin.
     *
     * @since    1.0.0
     *
     * @var string The ID of this plugin.
     */
    private $plugin_name;

    /**
     * The version of this plugin.
     *
     * @since    1.0.0
     *
     * @var string The current version of this plugin.
     */
    private $version;

    /**
     * The namespace to add to the api calls.
     *
     * @var string The namespace to add to the api call
     */
    private $namespace;

    /**
     * Store errors to display if the JWT is wrong
     *
     * @var WP_Error
     */
    private $jwt_error = null;

    /**
     * Initialize the class and set its properties.
     *
     * @since    1.0.0
     *
     * @param string $plugin_name The name of the plugin.
     * @param string $version     The version of this plugin.
     */
    public function __construct($plugin_name, $version)
    {
        $this->plugin_name = $plugin_name;
        $this->version = $version;
        $this->namespace = $this->plugin_name . '/v' . intval($this->version);
    }

    /**
     * Add the endpoints to the API
     */
    public function add_api_routes()
    {
        register_rest_route($this->namespace, 'token', array(
            'methods' => 'POST',
            'callback' => array($this, 'generate_token'),
        ));

        register_rest_route($this->namespace, 'token/get_account', array(
            'methods' => 'POST',
            'callback' => array($this, 'get_account_db'),
        ));
        register_rest_route($this->namespace, 'token/validate', array(
            'methods' => 'POST',
            'callback' => array($this, 'validate_token'),
        ));
         register_rest_route($this->namespace, 'token/register', array(
            'methods' => 'POST',
            'callback' => array($this, 'register_token'),
        ));
         register_rest_route($this->namespace, 'token/retrieve_password', array(
            'methods' => 'POST',
            'callback' => array($this, 'retrieve_password_api'),
        ));
          register_rest_route($this->namespace, 'token/update_user', array(
            'methods' => 'POST',
            'callback' => array($this, 'update_user_fields'),
        ));
         register_rest_route($this->namespace, 'token/get_list', array(
            'methods' => 'POST',
            'callback' => array($this, 'get_list_token'),
        ));

         register_rest_route($this->namespace, 'token/send_otp', array(
            'methods' => 'POST',
            'callback' => array($this, 'send_otp_db'),
        ));
         register_rest_route($this->namespace, 'token/otp_verification', array(
            'methods' => 'POST',
            'callback' => array($this, 'otp_verification_db'),
        ));
    }

    /**
     * Add CORs suppot to the request.
     */
    public function add_cors_support()
    {
        $enable_cors = defined('JWT_AUTH_CORS_ENABLE') ? JWT_AUTH_CORS_ENABLE : false;
        if ($enable_cors) {
            $headers = apply_filters('jwt_auth_cors_allow_headers', 'Access-Control-Allow-Headers, Content-Type, Authorization');
            header(sprintf('Access-Control-Allow-Headers: %s', $headers));
        }
    }

    /**
     * Get the user and password in the request body and generate a JWT
     *
     * @param [type] $request [description]
     *
     * @return [type] [description]
     */
    public function generate_token($request)
    {
        $secret_key = defined('JWT_AUTH_SECRET_KEY') ? JWT_AUTH_SECRET_KEY : false;
        $username = $request->get_param('username');
        $password = $request->get_param('password');

        /** First thing, check the secret key if not exist return a error*/
        if (!$secret_key) {
            return new WP_Error(
                'jwt_auth_bad_config',
                __('JWT is not configurated properly, please contact the admin', 'wp-api-jwt-auth'),
                array(
                    'status' => 403,
                )
            );
        }
        /** Try to authenticate the user with the passed credentials*/
        $user = wp_authenticate($username, $password);

        /** If the authentication fails return a error*/
        if (is_wp_error($user)) {
            $error_code = $user->get_error_code();
            return new WP_Error(
                '[jwt_auth] ' . $error_code,
                $user->get_error_message($error_code),
                array(
                    'status' => 403,
                )
            );
        }

        /** Valid credentials, the user exists create the according Token */
        $issuedAt = time();
        $notBefore = apply_filters('jwt_auth_not_before', $issuedAt, $issuedAt);
        $expire = apply_filters('jwt_auth_expire', $issuedAt + (DAY_IN_SECONDS * 7), $issuedAt);

        $token = array(
            'iss' => get_bloginfo('url'),
            'iat' => $issuedAt,
            'nbf' => $notBefore,
            'exp' => $expire,
            'data' => array(
                'user' => array(
                    'id' => $user->data->ID,
                ),
            ),
        );

        /** Let the user modify the token data before the sign. */
        $token = JWT::encode(apply_filters('jwt_auth_token_before_sign', $token, $user), $secret_key);

        /** The token is signed, now create the object with no sensible user data to the client*/
        $data = array(
            'token' => $token,
            'user_id' => $user->data->ID,
            'user_email' => $user->data->user_email,
            'user_nicename' => $user->data->user_nicename,
            'user_display_name' => $user->data->display_name,
        );

        /** Let the user modify the data before send it back */
        return apply_filters('jwt_auth_token_before_dispatch', $data, $user);
    }

          function username_exists( $username ) 
          {
              $user = get_user_by( 'login', $username );
              if ( $user ) {
                  $user_id = $user->ID;
              } else {
                  $user_id = false;
              }
         return apply_filters( 'username_exists', $user_id, $username );
          }

      public function get_account_db($request)
    {
        $secret_key = defined('JWT_AUTH_SECRET_KEY') ? JWT_AUTH_SECRET_KEY : false;
        
        $userdata = array('ID' => $request->get_param('user_id'));
        /** First thing, check the secret key if not exist return a error*/
        if (!$secret_key) {
            return new WP_Error(
                'jwt_auth_bad_config',
                __('JWT is not configurated properly, please contact the admin', 'wp-api-jwt-auth'),
                array(
                    'status' => 403,
                )
            );
        }
        /** Try to authenticate the user with the passed credentials*/
        $user = get_user_by('ID',$request->get_param('user_id'));
        
        /** If the authentication fails return a error*/
        if (is_wp_error($user)) {
            $error_code = $user->get_error_code();
            return new WP_Error(
                '[jwt_auth] ' . $error_code,
                $user->get_error_message($error_code),
                array(
                    'status' => 403,
                )
            );
        }
          return $user->data; 
        
    }

      public function send_otp_db($request)
    {
        $secret_key = defined('JWT_AUTH_SECRET_KEY') ? JWT_AUTH_SECRET_KEY : false;
        
        $userdata = array('user_email' => $request->get_param('user_email'));
        /** First thing, check the secret key if not exist return a error*/
        if (!$secret_key) {
            return new WP_Error(
                'jwt_auth_bad_config',
                __('JWT is not configurated properly, please contact the admin', 'wp-api-jwt-auth'),
                array(
                    'status' => 403,
                )
            );
        }
        /** Try to authenticate the user with the passed credentials*/
        $user = get_user_by('email',$request->get_param('user_email'));
                $user_activation_code = md5(rand());
                $user_otp = rand(100000, 999999);
                $metas = array(
                'user_otp'=>$user_otp
            );

            foreach($metas as $key => $value) {
                update_user_meta($user->data->ID, $key, $value );
            }
           $subject="OTP"; 
           $attachments="";
           $headers="";
           $to=$request->get_param('user_email');
           wp_mail( $to, $subject, $user_otp, $headers, $attachments ); 
        /** If the authentication fails return a error*/
        if (is_wp_error($user)) {
            $error_code = $user->get_error_code();
            return new WP_Error(
                '[jwt_auth] ' . $error_code,
                $user->get_error_message($error_code),
                array(
                    'status' => 403,
                )
            );
        }
       return $user_otp;
        
    }
      public function otp_verification_db($request)
    {
        $secret_key = defined('JWT_AUTH_SECRET_KEY') ? JWT_AUTH_SECRET_KEY : false;
        
        $meta_value = $request->get_param('user_otp');
        
        /** First thing, check the secret key if not exist return a error*/
        if (!$secret_key) {
            return new WP_Error(
                'jwt_auth_bad_config',
                __('JWT is not configurated properly, please contact the admin', 'wp-api-jwt-auth'),
                array(
                    'status' => 403,
                )
            );
        }
        /** Try to authenticate the user with the passed credentials*/
        
                
                $key='user_otp';
                $user = reset(get_users(array('meta_key' => $key, 'meta_value' => $meta_value) ));
        global $wpdb;
        $user_id =$wpdb->query('UPDATE wp_users SET user_status = 1 WHERE ID = '.$user->data->ID);
          
        /** If the authentication fails return a error*/
        if (is_wp_error($user)) {
            $error_code = $user->get_error_code();
            return new WP_Error(
                '[jwt_auth] ' . $error_code,
                $user->get_error_message($error_code),
                array(
                    'status' => 403,
                )
            );
        }
      return $user->data->ID; die();
        
    }    

    public function register_token($request)
    {
    
        $secret_key = defined('JWT_AUTH_SECRET_KEY') ? JWT_AUTH_SECRET_KEY : false;
        $user_name = $request->get_param('username');
        $user_email = $request->get_param('useremail');
        $password = $request->get_param('password');
        $meta_key="phone_number";
        $meta_value=$request->get_param('phone_number');
        $unique=false;
        /** First thing, check the secret key if not exist return a error*/
        if (!$secret_key) {
            return new WP_Error(
                'jwt_auth_bad_config',
                __('JWT is not configurated properly, please contact the admin', 'wp-api-jwt-auth'),
                array(
                    'status' => 403,
                )
            );
        } 

        if ( username_exists( $user_name ) ) {
        return new WP_Error(
                'jwt_auth_bad_config',
                __('<strong>Error</strong>: This username is already registered. Please choose another one.'),
                array(
                    'status' => 405,
                )
            );

        } 
         $user_id = wp_create_user( $user_name,$password,$user_email );
         if($user_id){
            $metas = array(
            'phone_number'=>$request->get_param('phone_number'),
            'user_file'   => $request->get_param('user_file')
              );

              foreach($metas as $key => $value) {
                  add_metadata('user', $user_id, $key, $value, $unique );
              }}

        if ( ! $user_id || is_wp_error( $user_id ) ) {
            return new WP_Error(
                'jwt_auth_bad_config',
                __('<strong>Error</strong>: Could not register you&hellip; please contact the <a href="mailto:%s">site admin</a>!'),
                array(
                    'status' => 406,
                )
            );
            }
        
      return $user_id;
    }


      public function update_user_fields($request)
    {
    
        $secret_key = defined('JWT_AUTH_SECRET_KEY') ? JWT_AUTH_SECRET_KEY : false;
        $meta_key="phone_number";
        $meta_value=$request->get_param('phone_number');
        $prev_value='';
            $userdata = array('ID' => $request->get_param('user_id'),'user_pass'=>$request->get_param('password'),'user_nicename' => $request->get_param('username'),'display_name' => $request->get_param('username'));
        /** First thing, check the secret key if not exist return a error*/
        if (!$secret_key) {
            return new WP_Error(
                'jwt_auth_bad_config',
                __('JWT is not configurated properly, please contact the admin', 'wp-api-jwt-auth'),
                array(
                    'status' => 403,
                )
            );
        } 

        if ( username_exists( $request->get_param('username') ) ) {
        return new WP_Error(
                'jwt_auth_bad_config',
                __('<strong>Error</strong>: This username is already registered. Please choose another one.'),
                array(
                    'status' => 405,
                )
            );

        } 

        //$user_obj = get_userdata( $user_id ); return $user_obj; die();
         $user_id = wp_update_user($userdata);
         if($user_id){ 
            $metas = array(
                'phone_number'=>$request->get_param('phone_number'),
                'nickname'   => $request->get_param('username'),
                'user_file'   => $request->get_param('user_file')
            );

            foreach($metas as $key => $value) {
                update_user_meta( $user_id, $key, $value );
            }}
        if ( ! $user_id || is_wp_error( $user_id ) ) {
            return new WP_Error(
                'jwt_auth_bad_config',
                __('<strong>Error</strong>: Could not register you&hellip; please contact the <a href="mailto:%s">site admin</a>!'),
                array(
                    'status' => 406,
                )
            );
            }
        
      return $user_id;
    }
      public function retrieve_password_api($request)
    {
        $secret_key = defined('JWT_AUTH_SECRET_KEY') ? JWT_AUTH_SECRET_KEY : false;
        $user_login = $request->get_param('user_login');

        /** First thing, check the secret key if not exist return a error*/
        if (!$secret_key) {
            return new WP_Error(
                'jwt_auth_bad_config',
                __('JWT is not configurated properly, please contact the admin', 'wp-api-jwt-auth'),
                array(
                    'status' => 403,
                )
            );
        }
        /** Try to authenticate the user with the passed credentials*/
        $user = retrieve_password($user_login);
        return $user;
    }



    public function get_list_token($args = null)
    {

        $defaults = array(
        'numberposts'      => 102,
        'category'         => 0,
        'orderby'          => 'date',
        'order'            => 'DESC',
        'include'          => array(),
        'exclude'          => array(),
        'meta_key'         => '',
        'meta_value'       => '',
        'post_type'        => 'property',
        'fave_property_price'        => '4500',
        'suppress_filters' => true,);
 
        $parsed_args = wp_parse_args( $args, $defaults );
        if ( empty( $parsed_args['post_status'] ) ) {
            $parsed_args['post_status'] = ( 'attachment' === $parsed_args['post_type'] ) ? 'inherit' : 'publish';
        }
        if ( ! empty( $parsed_args['numberposts'] ) && empty( $parsed_args['posts_per_page'] ) ) {
            $parsed_args['posts_per_page'] = $parsed_args['numberposts'];
        }
        if ( ! empty( $parsed_args['category'] ) ) {
            $parsed_args['cat'] = $parsed_args['category'];
        }
        if ( ! empty( $parsed_args['include'] ) ) {
            $incposts                      = wp_parse_id_list( $parsed_args['include'] );
            $parsed_args['posts_per_page'] = count( $incposts );  // Only the number of posts included.
            $parsed_args['post__in']       = $incposts;
        } elseif ( ! empty( $parsed_args['exclude'] ) ) {
            $parsed_args['post__not_in'] = wp_parse_id_list( $parsed_args['exclude'] );
        }
     
        $parsed_args['ignore_sticky_posts'] = true;
        $parsed_args['no_found_rows']       = true;
     
        $get_posts = new WP_Query;
        return $get_posts->query( $parsed_args );
    }
    /**
     * This is our Middleware to try to authenticate the user according to the
     * token send.
     *
     * @param (int|bool) $user Logged User ID
     *
     * @return (int|bool)
     */



    public function determine_current_user($user)
    {
        /**
         * This hook only should run on the REST API requests to determine
         * if the user in the Token (if any) is valid, for any other
         * normal call ex. wp-admin/.* return the user.
         *
         * @since 1.2.3
         **/
        $rest_api_slug = rest_get_url_prefix();
        $valid_api_uri = strpos($_SERVER['REQUEST_URI'], $rest_api_slug);
        if (!$valid_api_uri) {
            return $user;
        }

        /*
         * if the request URI is for validate the token don't do anything,
         * this avoid double calls to the validate_token function.
         */
        $validate_uri = strpos($_SERVER['REQUEST_URI'], 'token/validate');
        if ($validate_uri > 0) {
            return $user;
        }

        $token = $this->validate_token(false);

        if (is_wp_error($token)) {
            if ($token->get_error_code() != 'jwt_auth_no_auth_header') {
                /** If there is a error, store it to show it after see rest_pre_dispatch */
                $this->jwt_error = $token;
                return $user;
            } else {
                return $user;
            }
        }
        /** Everything is ok, return the user ID stored in the token*/
        return $token->data->user->id;
    }

    /**
     * Main validation function, this function try to get the Autentication
     * headers and decoded.
     *
     * @param bool $output
     *
     * @return WP_Error | Object | Array
     */
    public function validate_token($output = true)
    {
        /*
         * Looking for the HTTP_AUTHORIZATION header, if not present just
         * return the user.
         */
        $auth = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : false;

        /* Double check for different auth header string (server dependent) */
        if (!$auth) {
            $auth = isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) ? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] : false;
        }

        if (!$auth) {
            return new WP_Error(
                'jwt_auth_no_auth_header',
                'Authorization header not found.',
                array(
                    'status' => 403,
                )
            );
        }

        /*
         * The HTTP_AUTHORIZATION is present verify the format
         * if the format is wrong return the user.
         */
        list($token) = sscanf($auth, 'Bearer %s');
        if (!$token) {
            return new WP_Error(
                'jwt_auth_bad_auth_header',
                'Authorization header malformed.',
                array(
                    'status' => 403,
                )
            );
        }

        /** Get the Secret Key */
        $secret_key = defined('JWT_AUTH_SECRET_KEY') ? JWT_AUTH_SECRET_KEY : false;
        if (!$secret_key) {
            return new WP_Error(
                'jwt_auth_bad_config',
                'JWT is not configurated properly, please contact the admin',
                array(
                    'status' => 403,
                )
            );
        }

        /** Try to decode the token */
        try {
            $token = JWT::decode($token, $secret_key, array('HS256'));
            /** The Token is decoded now validate the iss */
            if ($token->iss != get_bloginfo('url')) {
                /** The iss do not match, return error */
                return new WP_Error(
                    'jwt_auth_bad_iss',
                    'The iss do not match with this server',
                    array(
                        'status' => 403,
                    )
                );
            }
            /** So far so good, validate the user id in the token */
            if (!isset($token->data->user->id)) {
                /** No user id in the token, abort!! */
                return new WP_Error(
                    'jwt_auth_bad_request',
                    'User ID not found in the token',
                    array(
                        'status' => 403,
                    )
                );
            }
            /** Everything looks good return the decoded token if the $output is false */
            if (!$output) {
                return $token;
            }
            /** If the output is true return an answer to the request to show it */
            return array(
                'code' => 'jwt_auth_valid_token',
                'data' => array(
                    'status' => 200,
                ),
            );
        } catch (Exception $e) {
            /** Something is wrong trying to decode the token, send back the error */
            return new WP_Error(
                'jwt_auth_invalid_token',
                $e->getMessage(),
                array(
                    'status' => 403,
                )
            );
        }
    }

    /**
     * Filter to hook the rest_pre_dispatch, if the is an error in the request
     * send it, if there is no error just continue with the current request.
     *
     * @param $request
     */
    public function rest_pre_dispatch($request)
    {
        if (is_wp_error($this->jwt_error)) {
            return $this->jwt_error;
        }
        return $request;
    }
}
