<?php

/**
 * Dynamic Client type.
 *
 * @pacakage   WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2;

use WP\JWT\JWT;
use WP_Error;
use WP_User;

/**
 * A Stateless Dynamic Client based on a signed Software Statement.
 *
 * @link https://tools.ietf.org/html/rfc7591#section-2.3
 * @link https://tools.ietf.org/html/rfc7591#appendix-A.5.2
 */
class DynamicClient implements ClientInterface {

	const SOFTWARE_ID_KEY = '_oauth2_software_id_';
	const SCHEMA = array(
		'type'       => 'object',
		'properties' => array(
			'software_id'   => array(
				'type'     => 'string',
				'format'   => 'uuid', // Todo support in rest_validate
				'required' => true,
			),
			'client_name'   => array(
				'type'      => 'string',
				'required'  => true,
				'minLength' => 1,
				'maxLength' => 255,
			),
			'redirect_uris' => array(
				'type'     => 'array',
				'items'    => array(
					'type'   => 'string',
					'format' => 'uri',
				),
				'required' => true,
				'maxItems' => 1,
				'minItems' => 1,
			)
		)
	);

	/** @var \stdClass */
	private $statement;

	/** @var Client|WP_Error */
	private $persisted;

	/**
	 * DynamicClient constructor.
	 *
	 * @param \stdClass $statement Software Statement.
	 */
	protected function __construct( $statement ) {
		$this->statement = $statement;
	}

	/**
	 * Create a Dynamic Client from a JWT.
	 *
	 * @param string $jwt
	 *
	 * @return DynamicClient|WP_Error
	 */
	public static function from_jwt( $jwt ) {
		$statement = JWT::decode( $jwt, '', array( 'none' ), 'unsecure' );
		$valid     = rest_validate_value_from_schema( $statement, self::SCHEMA );

		if ( is_wp_error( $valid ) ) {
			return $valid;
		}

		return new static( $statement );
	}

	public function get_id() {
		return $this->statement->software_id;
	}

	public function get_name() {
		return $this->statement->client_name;
	}

	public function get_description( $raw = false ) {
		return sprintf( __( 'Unregistered application %s', 'oauth2' ), $this->get_name() );
	}

	public function get_type() {
		return 'public';
	}

	public function get_secret() {
		return '';
	}

	public function get_redirect_uris() {
		return $this->statement->redirect_uris;
	}

	public function check_redirect_uri( $uri ) {
		return validate_redirect_uri( $this, $uri );
	}

	public function generate_authorization_code( WP_User $user ) {
		$client = $this->persist_dynamic_client();

		if ( is_wp_error( $client ) ) {
			return $client;
		}

		return $client->generate_authorization_code( $user );
	}

	public function get_authorization_code( $code ) {
		$client = $this->persist_dynamic_client();

		if ( is_wp_error( $client ) ) {
			return $client;
		}

		return $client->get_authorization_code( $code );
	}

	public function regenerate_secret() {
		$client = $this->persist_dynamic_client();

		if ( is_wp_error( $client ) ) {
			return $client;
		}

		return $client->regenerate_secret();
	}

	public function issue_token( WP_User $user, $meta = [] ) {
		$client = $this->persist_dynamic_client();

		if ( is_wp_error( $client ) ) {
			return $client;
		}

		return $client->issue_token( $user, $meta );
	}

	public function update( $data ) {
		return new WP_Error(
			'oauth2.dynamic_client.no_update',
			__( 'Dynamic Clients cannot be updated.', 'oauth2' )
		);
	}

	public function delete() {
		return false;
	}

	public function approve() {
		return new WP_Error(
			'oauth2.dynamic_client.no_approve',
			__( 'Dynamic Clients cannot be approved.', 'oauth2' )
		);
	}

	/**
	 * Persists a dynamic client to a real client.
	 *
	 * @return Client|WP_Error
	 */
	public function persist_dynamic_client() {
		if ( ! $this->persisted ) {
			$this->persisted = $this->find_persisted_dynamic_client();

			if ( ! $this->persisted ) {
				$this->persisted = $this->create_persisted_dynamic_client();
			}
		}

		return $this->persisted;
	}

	/**
	 * Find a persisted dynamic client by the software ID.
	 *
	 * @return Client|null
	 */
	protected function find_persisted_dynamic_client() {
		$query = new \WP_Query(
			array(
				'post_type'        => Client::POST_TYPE,
				'meta_key'         => static::SOFTWARE_ID_KEY . $this->get_id(),
				'meta_compare_key' => 'EXISTS',
				'post_status'      => 'any',
			)
		);

		if ( $query->posts ) {
			return Client::get_by_post_id( $query->posts[0]->ID );
		}

		return null;
	}

	/**
	 * Creates the persisted form of the dynamic client.
	 *
	 * @return Client|WP_Error
	 */
	protected function create_persisted_dynamic_client() {
		$data = array(
			'name'        => $this->get_name(),
			'description' => '',
			'meta'        => array(
				'callback' => $this->get_redirect_uris()[0],
				'type'     => $this->get_type(),
			),
		);

		$client = Client::create( $data );

		if ( is_wp_error( $client ) ) {
			return $client;
		}

		update_post_meta( $client->get_post_id(), static::SOFTWARE_ID_KEY . $this->get_id(), 1 );

		$approved = $client->approve();

		if ( is_wp_error( $approved ) ) {
			return $approved;
		}

		return $client;
	}
}
