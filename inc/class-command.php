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
	 * <client_uri>
	 * : The base URI of your application.
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
	 * [--<field>=<value>]
	 * : Additional claims.
	 *
	 * @subcommand create-software-statement
	 */
	public function create_software_statement( $args, $assoc_args ) {
		$client_uri = $args[0];

		if ( empty( $args[1] ) ) {
			$software_id = wp_generate_uuid4();
			\WP_CLI::log( 'Generated software id: ' . $software_id );
		} else {
			$software_id = $args[1];
		}

		$name         = get_flag_value( $assoc_args, 'client_name' );
		$redirect_uri = get_flag_value( $assoc_args, 'redirect_uri' );

		$statement = array(
			'client_uri'    => $client_uri,
			'software_id'   => $software_id,
			'redirect_uris' => array( $redirect_uri ),
			'client_name'   => $name,
		);

		unset( $assoc_args['client_name'], $assoc_args['redirect_uri'] );
		$statement = array_merge( $assoc_args, $statement );

		$valid = DynamicClient::validate_statement( (object) $statement );

		if ( is_wp_error( $valid ) ) {
			\WP_CLI::error( $valid );
		}

		$signed = JWT::encode( $statement, '', 'none' );

		if ( is_wp_error( $signed ) ) {
			\WP_CLI::error( $signed );
		}

		\WP_CLI::success( 'Generated Statement: "' . $signed . '"' );
	}
}
