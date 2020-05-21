<?php
/**
 * WP CLI Command.
 *
 * @package    WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2;

use WP\JWT\JWT;
use function WP_CLI\Utils\get_flag_value;

class Command {

	/**
	 * Create a Signed Software Statement.
	 *
	 * ## OPTIONS
	 *
	 * [<software_id>]
	 * : The software ID to use. Leave blank to generate one.
	 *
	 * --client_name=<client_name>
	 * : The name displayed when the user is connecting.
	 *
	 * --redirect_uri=<redirect_uri>
	 * : The URI users will be redirected to after connecting.
	 *
	 * @subcommand create-software-statement
	 */
	public function create_software_statement( $args, $assoc_args ) {
		if ( empty( $args[0] ) ) {
			$software_id = wp_generate_uuid4();
			\WP_CLI::log( 'Generated software id: ' . $software_id );
		} else {
			$software_id = $args[0];
		}

		$name         = get_flag_value( $assoc_args, 'client_name' );
		$redirect_uri = get_flag_value( $assoc_args, 'redirect_uri' );

		$statement = array(
			'software_id'   => $software_id,
			'redirect_uris' => array( $redirect_uri ),
			'client_name'   => $name,
		);

		$signed = JWT::encode( $statement, '', 'none' );

		if ( is_wp_error( $signed ) ) {
			\WP_CLI::error( $signed );
		}

		\WP_CLI::success( 'Generated Statement: "' . $signed . '"' );
	}
}
