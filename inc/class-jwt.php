<?php

namespace WP\JWT;

/**
 * JSON Web Token implementation, based on this spec:
 * https://tools.ietf.org/html/rfc7519
 *
 * Forked to follow WordPress Coding Standards and provide additional APIs.
 *
 * PHP version 5
 *
 * @category Authentication
 * @package  Authentication_JWT
 * @author   Neuman Vong <neuman@twilio.com>
 * @author   Anant Narayanan <anant@php.net>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/firebase/php-jwt
 */
final class JWT {
	/**
	 * When checking nbf, iat or expiration times,
	 * we want to provide some extra leeway time to
	 * account for clock skew.
	 */
	public static $leeway = 0;

	/**
	 * Allow the current timestamp to be specified.
	 * Useful for fixing a value within unit testing.
	 *
	 * Will default to PHP time() value if null.
	 */
	public static $timestamp = null;

	protected static $supported_algs = array(
		'HS256' => array( 'hash_hmac', 'SHA256' ),
		'HS512' => array( 'hash_hmac', 'SHA512' ),
		'HS384' => array( 'hash_hmac', 'SHA384' ),
		'RS256' => array( 'openssl', 'SHA256' ),
		'RS384' => array( 'openssl', 'SHA384' ),
		'RS512' => array( 'openssl', 'SHA512' ),
	);

	/**
	 * Decodes a JWT string into a PHP object.
	 *
	 * @param string       $jwt              The JWT
	 * @param string|array $key              The key, or map of keys.
	 *                                       If the algorithm used is asymmetric, this is the public key
	 * @param array        $allowed_algs     List of supported verification algorithms
	 *                                       Supported algorithms are 'HS256', 'HS384', 'HS512' and 'RS256'
	 * @param string       $confirm_unsecure Must be set to "unsecure" to allow using the "none" algorithm.
	 *
	 * @return object|\WP_Error The JWT's payload as a PHP object
	 *
	 * @uses json_decode
	 * @uses url_safe_b64_decode
	 */
	public static function decode( $jwt, $key, array $allowed_algs = array(), $confirm_unsecure = '' ) {
		$timestamp       = is_null( static::$timestamp ) ? time() : static::$timestamp;
		$allow_unsecured = in_array( 'none', $allowed_algs, true );

		if ( $allow_unsecured && 'unsecure' !== $confirm_unsecure ) {
			return new \WP_Error( 'jwt_unsecure_not_confirmed', __( 'Did not confirm that "none" is an allowed algorithm.', 'oauth2' ) );
		}

		if ( empty( $key ) && ! $allow_unsecured ) {
			return new \WP_Error( 'jwt_empty_key', __( 'Key may not be empty', 'oauth2' ) );
		}

		$parsed = self::parse_jwt( $jwt );

		if ( is_wp_error( $parsed ) ) {
			return $parsed;
		}

		list( $header, $payload, $sig, $headb64, $bodyb64 ) = $parsed;

		if ( empty( $header->alg ) ) {
			return new \WP_Error( 'jwt_invalid_format', __( 'Empty algorithm', 'oauth2' ) );
		}

		if ( 'none' !== $header->alg || ! $allow_unsecured ) {
			if ( empty( static::$supported_algs[ $header->alg ] ) ) {
				return new \WP_Error( 'jwt_unsupported_algorithm', __( 'Algorithm not supported', 'oauth2' ) );
			}

			if ( ! in_array( $header->alg, $allowed_algs, true ) ) {
				return new \WP_Error( 'jwt_disallowed_algorithm', __( 'Algorithm not allowed', 'oauth2' ) );
			}

			if ( is_array( $key ) || $key instanceof \ArrayAccess ) {
				if ( isset( $header->kid ) ) {
					if ( ! isset( $key[ $header->kid ] ) ) {
						return new \WP_Error( 'jwt_invalid_key', __( '"kid" invalid, unable to lookup correct key', 'oauth2' ) );
					}

					$key = $key[ $header->kid ];
				} else {
					return new \WP_Error( 'jwt_invalid_key', __( '"kid" empty, unable to lookup correct key', 'oauth2' ) );
				}
			}

			// Check the signature
			$verified = static::verify( "$headb64.$bodyb64", $sig, $key, $header->alg );

			if ( is_wp_error( $verified ) ) {
				return $verified;
			}

			if ( true !== $verified ) {
				return new \WP_Error( 'jwt_invalid_signature', __( 'Signature verification failed', 'oauth2' ) );
			}
		}

		// Check if the nbf if it is defined. This is the time that the
		// token can actually be used. If it's not yet that time, abort.
		if ( isset( $payload->nbf ) && $payload->nbf > ( $timestamp + static::$leeway ) ) {
			return new \WP_Error(
				'jwt_before_valid',
				sprintf(
				/* translators: %s Date/Time the JWT is valid. */
					__( 'Cannot handle token prior to %s.', 'oauth2' ),
					wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $payload->nbf )
				),
				array( 'nbf' => $payload->nbf )
			);
		}

		// Check that this token has been created before 'now'. This prevents
		// using tokens that have been created for later use (and haven't
		// correctly used the nbf claim).
		if ( isset( $payload->iat ) && $payload->iat > ( $timestamp + static::$leeway ) ) {
			return new \WP_Error(
				'jwt_before_valid',
				sprintf(
				/* translators: %s Date/Time the JWT is valid. */
					__( 'Cannot handle token prior to %s.', 'oauth2' ),
					wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $payload->iat )
				),
				array( 'iat' => $payload->iat )
			);
		}

		// Check if this token has expired.
		if ( isset( $payload->exp ) && ( $timestamp - static::$leeway ) >= $payload->exp ) {
			return new \WP_Error( 'jwt_expired', __( 'Expired token', 'oauth2' ), array( 'exp' => $payload->exp ) );
		}

		return $payload;
	}

	/**
	 * Retrieve's a claim from a JWT without verifying it.
	 *
	 * @param string $jwt   The JWT to decode.
	 * @param string $claim The claim's name. Either "iss" or "jti".
	 *
	 * @return object|\WP_Error
	 */
	public static function get_claim( $jwt, $claim ) {
		if ( ! in_array( $claim, array( 'iss', 'jti' ), true ) ) {
			return new \WP_Error( 'jwt_invalid_claim', __( 'Only the iss and jti claims are supported.', 'oauth2' ) );
		}

		$parsed = self::parse_jwt( $jwt );

		if ( is_wp_error( $parsed ) ) {
			return $parsed;
		}

		list( , $payload ) = $parsed;

		if ( isset( $payload->{$claim} ) ) {
			return $payload->{$claim};
		}

		return new \WP_Error( 'jwt_undefined_claim', __( 'The JWT is missing the requested claim.', 'oauth2' ) );
	}

	/**
	 * Parses a JWT into it's component parts.
	 *
	 * @param string $jwt
	 *
	 * @return array|\WP_Error
	 */
	protected static function parse_jwt( $jwt ) {
		$tks = explode( '.', $jwt );

		if ( 3 !== count( $tks ) ) {
			return new \WP_Error( 'jwt_invalid_format', __( 'Wrong number of segments', 'oauth2' ) );
		}

		list( $headb64, $bodyb64, $cryptob64 ) = $tks;

		if ( null === ( $header = static::json_decode( static::url_safe_b64_decode( $headb64 ) ) ) ) {
			return new \WP_Error( 'jwt_invalid_format', __( 'Invalid header encoding', 'oauth2' ) );
		}

		if ( null === $payload = static::json_decode( static::url_safe_b64_decode( $bodyb64 ) ) ) {
			return new \WP_Error( 'jwt_invalid_format', __( 'Invalid claims encoding', 'oauth2' ) );
		}

		if ( false === ( $sig = static::url_safe_b64_decode( $cryptob64 ) ) ) {
			return new \WP_Error( 'jwt_invalid_format', __( 'Invalid signature encoding', 'oauth2' ) );
		}

		return array( $header, $payload, $sig, $headb64, $bodyb64, $cryptob64 );
	}

	/**
	 * Converts and signs a PHP object or array into a JWT string.
	 *
	 * @param object|array $payload     PHP object or array
	 * @param string       $key         The secret key.
	 *                                  If the algorithm used is asymmetric, this is the private key
	 * @param string       $alg         The signing algorithm.
	 *                                  Supported algorithms are 'HS256', 'HS384', 'HS512' and 'RS256'
	 * @param mixed        $key_id
	 * @param array        $head        An array with header elements to attach
	 *
	 * @return string A signed JWT
	 *
	 * @uses json_encode
	 * @uses url_safe_b64_encode
	 */
	public static function encode( $payload, $key, $alg = 'HS256', $key_id = null, $head = null ) {
		$header = array( 'typ' => 'JWT', 'alg' => $alg );
		if ( $key_id !== null ) {
			$header['kid'] = $key_id;
		}
		if ( isset( $head ) && is_array( $head ) ) {
			$header = array_merge( $head, $header );
		}
		$segments      = array();
		$segments[]    = static::url_safe_b64_encode( static::json_encode( $header ) );
		$segments[]    = static::url_safe_b64_encode( static::json_encode( $payload ) );
		$signing_input = implode( '.', $segments );

		if ( 'none' === $alg ) {
			$signature = '';
		} else {
			$signature = static::sign( $signing_input, $key, $alg );
		}

		if ( is_wp_error( $signature ) ) {
			return $signature;
		}

		$segments[] = static::url_safe_b64_encode( $signature );

		return implode( '.', $segments );
	}

	/**
	 * Gets the list of support algorithms.
	 *
	 * @return \string[][]
	 */
	public static function get_supported_algos() {
		return static::$supported_algs;
	}

	/**
	 * Sign a string with a given key and algorithm.
	 *
	 * @param string          $msg      The message to sign
	 * @param string|resource $key      The secret key
	 * @param string          $alg      The signing algorithm.
	 *                                  Supported algorithms are 'HS256', 'HS384', 'HS512' and 'RS256'
	 *
	 * @return string|\WP_Error An encrypted message
	 */
	protected static function sign( $msg, $key, $alg = 'HS256' ) {
		if ( empty( static::$supported_algs[ $alg ] ) ) {
			return new \WP_Error( 'jwt_unsupported_algorithm', __( 'Algorithm not supported', 'oauth2' ) );
		}

		list( $function, $algorithm ) = static::$supported_algs[ $alg ];

		switch ( $function ) {
			case 'hash_hmac':
				return hash_hmac( $algorithm, $msg, $key, true );
			case 'openssl':
				$signature = '';
				$success   = openssl_sign( $msg, $signature, $key, $algorithm );

				if ( ! $success ) {
					return new \WP_Error( 'jwt_openssl_error', __( 'OpenSSL unable to sign data', 'oauth2' ) );
				}

				return $signature;
		}
	}

	/**
	 * Verify a signature with the message, key and method. Not all methods
	 * are symmetric, so we must have a separate verify and sign method.
	 *
	 * @param string          $msg       The original message (header and body)
	 * @param string          $signature The original signature
	 * @param string|resource $key       For HS*, a string key works. for RS*, must be a resource of an openssl public key
	 * @param string          $alg       The algorithm
	 *
	 * @return bool|\WP_Error
	 */
	protected static function verify( $msg, $signature, $key, $alg ) {
		if ( empty( static::$supported_algs[ $alg ] ) ) {
			return new \WP_Error( 'jwt_unsupported_algorithm', __( 'Algorithm not supported', 'oauth2' ) );
		}

		list( $function, $algorithm ) = static::$supported_algs[ $alg ];
		switch ( $function ) {
			case 'openssl':
				$success = openssl_verify( $msg, $signature, $key, $algorithm );
				if ( $success === 1 ) {
					return true;
				}

				if ( $success === 0 ) {
					return false;
				}

				return new \WP_Error( 'jwt_openssl_error', openssl_error_string() );
			case 'hash_hmac':
			default:
				$hash = hash_hmac( $algorithm, $msg, $key, true );

				return hash_equals( $signature, $hash );
		}
	}

	/**
	 * Decode a JSON string into a PHP object.
	 *
	 * @param string $input JSON string
	 *
	 * @return object|\WP_Error Object representation of JSON string
	 */
	protected static function json_decode( $input ) {
		$obj = json_decode( $input, false, 512, JSON_BIGINT_AS_STRING );

		if ( $errno = json_last_error() ) {
			return new \WP_Error( 'jwt_cannot_decode_json', json_last_error_msg(), array( 'code' => $errno ) );
		}

		return $obj;
	}

	/**
	 * Encode a PHP object into a JSON string.
	 *
	 * @param object|array $input A PHP object or array
	 *
	 * @return string|\WP_Error JSON representation of the PHP object or array
	 */
	protected static function json_encode( $input ) {
		$json = json_encode( $input );

		if ( $errno = json_last_error() ) {
			return new \WP_Error( 'jwt_cannot_encode_json', json_last_error_msg(), array( 'code' => $errno ) );
		}

		return $json;
	}

	/**
	 * Decode a string with URL-safe Base64.
	 *
	 * @param string $input A Base64 encoded string
	 *
	 * @return string A decoded string
	 */
	protected static function url_safe_b64_decode( $input ) {
		$remainder = strlen( $input ) % 4;
		if ( $remainder ) {
			$padlen = 4 - $remainder;
			$input  .= str_repeat( '=', $padlen );
		}

		return base64_decode( strtr( $input, '-_', '+/' ) );
	}

	/**
	 * Encode a string with URL-safe Base64.
	 *
	 * @param string $input The string you want encoded
	 *
	 * @return string The base64 encode of what you passed in
	 */
	protected static function url_safe_b64_encode( $input ) {
		return str_replace( '=', '', strtr( base64_encode( $input ), '+/', '-_' ) );
	}
}
