<?php

/**
 * The plugin bootstrap file.
 *
 * This file is read by WordPress to generate the plugin information in the plugin
 * admin area. This file also includes all of the dependencies used by the plugin,
 * registers the activation and deactivation functions, and defines a function
 * that starts the plugin.
 *
 * @link              https://brainstudioz.com/
 * @since             1.0.0
 *
 * @wordpress-plugin
 * Plugin Name:       Houzez API
 * Plugin URI:        brainstudioz.com
 * Description:       Extends the WP REST API using JSON Web Tokens Authentication as an authentication method.
 * Version:           1.2.6
 * Author:            Houzez API
 * Author URI:        https://brainstudioz.com/
 * License:           GPL-2.0+
 * Text Domain:       brainstudioz
 * Domain Path:       /languages
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

/**
 * The core plugin class that is used to define internationalization,
 * admin-specific hooks, and public-facing site hooks.
 */
require plugin_dir_path(__FILE__) . 'includes/class-jwt-auth.php';

/**
 * Begins execution of the plugin.
 *
 * Since everything within the plugin is registered via hooks,
 * then kicking off the plugin from this point in the file does
 * not affect the page life cycle.
 *
 * @since    1.0.0
 */
function run_jwt_auth()
{
    $plugin = new Jwt_Auth();
    $plugin->run();
}
run_jwt_auth();
