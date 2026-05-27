<?php
/**
 * Use Google Groups membership for authentication and authorization to view WordPress content.
 *
 * @package gated-groups-content
 * @author  Jonathan Bredin <jbredin@gmail.com>
 * @version 1.0.0
 * @license https://www.gnu.org/licenses/gpl-3.0.html GNU General Public License v3.0
 */

/*
Plugin Name: Gated Groups Content
Plugin URI: https://github.com/jonathanlb/gated-groups-content
Description: Use Google Groups membership for authentication and authorization to view WordPress content.
Version: 1.0.0
Author: Jonathan Bredin
Author URI: https://bredin.org
License: GPL3
*/

require_once plugin_dir_path( __FILE__ ) . 'vendor/autoload.php';

define( 'GGC_TOKEN_EXPIRY_HOURS', 24 * 7 );

/**
 * Plugin class to handle Google OAuth flow, group membership checks, and
 * content gating based on Google Group membership.
 */
class Gated_Groups_Content {
	/**
	 * The plugin version, read for resource versioning.
	 *
	 * @var string
	 */
	public static $version = '1.0.0';

	/**
	 * Initialize the plugin by setting up WordPress hooks for admin settings,
	 * shortcode handling, and authentication routing.
	 */
	public function __construct() {
		add_action( 'admin_menu', array( $this, 'register_settings_page' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_shortcode( 'groups_content', array( $this, 'shortcode_handler' ) );
		add_action( 'init', array( $this, 'handle_auth_routing' ) );
		add_action( 'wp_enqueue_scripts', array( $this, 'plugin_styles' ) );
	}

	/**
	 * Set a cookie to track that the user has been authenticated and
	 * authorized for a specific group, allowing them to view gated content
	 * without re-authenticating on every page load until the cookie expires.
	 *
	 * @param array  $user_data The user information retrieved from the OAuth provider.
	 * @param string $group_email The email of the Google Group.
	 * @param bool   $write_cookie Whether to write the cookie or return the
	 *               encoded user data for testing purposes.
	 * @return string|null The encoded user data that would have been written
	 *                     to the cookie if $write_cookie were true, otherwise
	 *                     null.
	 */
	private function authorize_user( $user_data, $group_email, $write_cookie = true ) {
		$session_key         = $this->get_session_key( $group_email );
		$token_expiry_stored = intval( esc_attr( get_option( 'ggc_token_expiry_hours' ) ), 10 );
		if ( $token_expiry_stored <= 0 ) {
			$token_expiry_stored = GGC_TOKEN_EXPIRY_HOURS;
		}
		$token_expiry_seconds = 60 * 60 * $token_expiry_stored;

		$expiry_time       = time() + $token_expiry_seconds;
		$user_obj          = array(
			'email'       => $user_data['email'] ?? '',
			'expiry'      => $expiry_time,
			'name'        => $user_data['name'] ?? '',
			'given_name'  => $user_data['given_name'] ?? '',
			'family_name' => $user_data['family_name'] ?? '',
			'picture'     => $user_data['picture'] ?? '',
			'hash'        => wp_hash( $group_email . $user_data['email'] . $expiry_time . 'auth' ),
		);
		$user_data_encoded = filter_var( wp_json_encode( $user_obj ), FILTER_UNSAFE_RAW );
		$user_data_final   = substr( $user_data_encoded, 0, 4096 ); // Limit to 4KB to avoid cookie size issues.
		if ( $write_cookie ) {
			setcookie( $session_key, $user_data_final, $expiry_time, COOKIEPATH, COOKIE_DOMAIN, is_ssl() );
		} else {
			return $user_data_final;
		}
	}

	/**
	 * Reconstruct simplified current URL for redirecting back after authentication.
	 *
	 * @throws Exception If HTTP_HOST or REQUEST_URI are not set in $_SERVER.
	 */
	private function get_current_url() {
		$protocol = is_ssl() ? 'https://' : 'http://';
		if ( isset( $_SERVER['HTTP_HOST'] ) && isset( $_SERVER['REQUEST_URI'] ) ) {
			return $protocol . sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) . sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) );
		} else {
			throw new Exception( 'get_current_url: HTTP_HOST or REQUEST_URI not set in $_SERVER' );
		}
	}

	/**
	 * Create and configure a Google API client.
	 */
	private function get_google_api_client() {
		$service_account_config = get_option( 'ggc_service_account_config' );
		if ( ! $service_account_config ) {
			wp_die( 'Service account config is not set' );
		}
		if ( ! str_starts_with( $service_account_config, '/' ) ) {
			$service_account_config = plugin_dir_path( __FILE__ ) . $service_account_config;
		}
		if ( ! file_exists( $service_account_config ) ) {
			wp_die( 'Service account config file ' . esc_textarea( $service_account_config ) . ' not found' );
		}
		$admin_user_key = get_option( 'ggc_admin_user_key' );
		if ( ! $admin_user_key ) {
			wp_die( 'Admin user key is not set' );
		}

		$service_client = new Google\Client();
		$service_client->setAuthConfig( $service_account_config );
		$service_client->addScope( 'https://www.googleapis.com/auth/admin.directory.group.member.readonly' );
		$service_client->setSubject( $admin_user_key );
		return $service_client;
	}

	/**
	 * Generate the Google Group URL for a given group email, used in error
	 * messages to direct users to check their group membership on their own.
	 *
	 * @param string $group_email The email of the Google Group.
	 * @return string The Google Group URL.
	 */
	private function get_group_url( $group_email ) {
		$group_org  = substr( $group_email, strpos( $group_email, '@' ) + 1 );
		$group_name = substr( $group_email, 0, strpos( $group_email, '@' ) );
		return 'https://groups.google.com/a/' . $group_org . '/g/' . $group_name;
	}

	/**
	 * Generate a unique session key for a given Google Group email for use as a
	 * cookie name to track authentication state for that group.
	 *
	 * @param string $group_email The email of the Google Group.
	 * @return string The session key for the group.
	 */
	private function get_session_key( $group_email ) {
		return 'ggc_auth_' . md5( $group_email );
	}

	/**
	 * Intercept all WordPress requests to check for authentication-related
	 * query parameters and route to external OAuth provider or check
	 * resulting authentication state for authentication and authorization.
	 */
	public function handle_auth_routing() {
		// We'll check nonces in the next step.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['ggc_action'] ) && 'login' === sanitize_text_field( wp_unslash( $_GET['ggc_action'] ) ) ) {
			$this->initiate_oauth();
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['ggc_callback'] ) ) {
			$this->process_callback();
		}
	}

	/**
	 * Initiate the OAuth flow by redirecting the user to Google's OAuth 2.0.
	 */
	private function initiate_oauth() {
		if ( ! isset( $_GET['nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['nonce'] ) ), 'ggc_login' ) ) {
			wp_die( 'Invalid nonce for login action' );
		}
		$client_id    = get_option( 'ggc_client_id' );
		$redirect_uri = home_url( '/?ggc_callback=1' );
		$group        = isset( $_GET['group'] ) ? sanitize_text_field( wp_unslash( $_GET['group'] ) ) : '';
		$redirect_to  = isset( $_GET['redirect_to'] ) ? sanitize_text_field( wp_unslash( $_GET['redirect_to'] ) ) : home_url();

		if ( '' === $group ) {
			wp_die( 'Group email is required to initiate login' );
		}

		$state = base64_encode( // phpcs:ignore
			wp_json_encode(
				array(
					'group'    => $group,
					'redirect' => $redirect_to,
					'nonce'    => wp_create_nonce( 'ggc_oauth' ),
				)
			)
		);

		$params = array(
			'client_id'     => $client_id,
			'redirect_uri'  => $redirect_uri,
			'response_type' => 'code',
			'scope'         => 'openid email profile https://www.googleapis.com/auth/admin.directory.group.member.readonly',
			'state'         => $state,
			'prompt'        => 'select_account',
		);

		// Using wp_redirect() or header() here causes issues with some browsers and breaks the flow. Use JS redirect as a workaround.
		echo '<script>window.location.href = "https://accounts.google.com/o/oauth2/v2/auth?' . filter_var( http_build_query( $params ), FILTER_SANITIZE_URL ) . '";</script>';
		$this->plugin_exit();
	}

	/**
	 * Inspect the session cookie to determine if the plugin has already
	 * authenticated and authorized the user.
	 *
	 * @param string      $group_email The email of the Google Group to check membership for.
	 * @param string|null $encoded_user_data Optional encoded user data to check instead of the cookie, used for testing.
	 * @return object return the user data object if the user is authorized, null if not authorized or authenticated.
	 */
	public function is_user_in_group( $group_email, $encoded_user_data = null ) {
		$session_key = $this->get_session_key( $group_email );
		if ( null === $encoded_user_data && ! isset( $_COOKIE[ $session_key ] ) ) {
			return null;
		}
		$encoded_user_data = $encoded_user_data ?? sanitize_text_field( wp_unslash( $_COOKIE[ $session_key ] ) );
		$decoded_user_data = json_decode( wp_unslash( $encoded_user_data ), true );
		if ( is_array( $decoded_user_data ) &&
			isset( $decoded_user_data['expiry'] ) &&
			isset( $decoded_user_data['email'] ) &&
			isset( $decoded_user_data['hash'] ) &&
			$decoded_user_data['expiry'] > time() ) {
			$hash = wp_hash( $group_email . $decoded_user_data['email'] . $decoded_user_data['expiry'] . 'auth' );
			if ( $hash !== $decoded_user_data['hash'] ) {
				// phpcs:ignore
				error_log(
					'Authentication hash mismatch for user ' .
					substr( sanitize_text_field( wp_unslash( $decoded_user_data['email'] ) ), 0, 20 ) .
					' and group ' .
					substr( sanitize_text_field( wp_unslash( $group_email ) ), 0, 20 )
				);
				// Possible tampering or drift in authentication implementation.
				// Revoke cookie to force re-authentication.
				$this->revoke_user_authorization( $group_email );
				return null;
			}
			return $decoded_user_data;
		}
		// Force re-authentication.
		$this->revoke_user_authorization( $group_email );
		return null;
	}

	/**
	 * Wrap the exit function so it can be mocked for testing.
	 */
	protected function plugin_exit() {
		exit;
	}

	/**
	 * Enqueue plugin CSS file.
	 */
	public function plugin_styles() {
		wp_enqueue_style( 'gated-groups-content-styles', plugin_dir_url( __FILE__ ) . 'styles.css', array(), self::$version );
	}

	/**
	 * Handle traffic coming back from the OAuth provider, exchange the
	 * authorization code in the URL parameters for an access token stored in
	 * a cookie if the user is a member of the specified Google Group, and
	 * redirect back to the original URL.  Pass along an error message
	 * to the original URL and clear the session cookie if membership check
	 * fails.
	 */
	private function process_callback() {
		// Google doesn't provide nonces in the callback.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! isset( $_GET['code'] ) || ! isset( $_GET['state'] ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$coded_state = sanitize_text_field( wp_unslash( $_GET['state'] ?? '' ) );
		$state_data  = json_decode( base64_decode( $coded_state ), true ); // phpcs:ignore
		$group_email = $state_data['group'] ?? '';
		$session_key = $this->get_session_key( $group_email );

		$client_id     = get_option( 'ggc_client_id' );
		$client_secret = get_option( 'ggc_client_secret' );
		$redirect_uri  = home_url( '/?ggc_callback=1' );

		// 1. Exchange code for token
 		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$code_param = sanitize_text_field( wp_unslash( $_GET['code'] ) );
		$response   = wp_remote_post(
			'https://oauth2.googleapis.com/token',
			array(
				'body' => array(
					'code'          => $code_param,
					'client_id'     => $client_id,
					'client_secret' => $client_secret,
					'redirect_uri'  => $redirect_uri,
					'grant_type'    => 'authorization_code',
				),
			)
		);

		$body         = json_decode( wp_remote_retrieve_body( $response ), true );
		$access_token = $body['access_token'] ?? '';

		if ( ! $access_token ) {
			wp_die( 'Failed to get access token' );
		}

		// 2. Get User Email
		$user_res   = wp_remote_get(
			'https://www.googleapis.com/oauth2/v2/userinfo',
			array( 'headers' => array( 'Authorization' => 'Bearer ' . $access_token ) ),
		);
		$user_data  = json_decode( wp_remote_retrieve_body( $user_res ), true );
		$user_email = $user_data['email'] ?? '';

		// 3. Configure service account credentials for group membership check
		$service_client = $this->get_google_api_client();
		$dir_service    = new Google\Service\Directory( $service_client );

		// 4. Check Group Membership
		try {
			$_member = $dir_service->members->get( $group_email, $user_email );
			$this->authorize_user( $user_data, $group_email );
			wp_safe_redirect( $state_data['redirect'] );
			$this->plugin_exit();
		} catch ( Exception $e ) {
			error_log( 'Google API Error: ' . $e->getMessage() . ' (Code: ' . $e->getCode() . ')' ); // phpcs:ignore
			$this->revoke_user_authorization( $group_email );
			if ( 404 === $e->getCode() ) {
				echo '<script>console.log("User is not a member");</script>';
			} else {
				echo '<script>console.error("Google API Error: ' . esc_textarea( $e->getMessage() ) . '");</script>';
			}
			// Redirect to the requesting page with an error message and clear the cookie.
			$redirect_url = add_query_arg(
				array(
					'ggc_action'   => false,
					'ggc_callback' => false,
					'ggc_error'    => 'access_denied',
					'state'        => false,
					'nonce'        => wp_create_nonce( 'ggc_error' ),
				),
				$state_data['redirect']
			);
			wp_safe_redirect( $redirect_url );
			$this->plugin_exit();
		}
	}

	/**
	 * Register the plugin settings page in the WordPress admin menu.
	 */
	public function register_settings_page() {
		add_options_page(
			'Gated Groups Content Settings',
			'Gated Groups Content',
			'manage_options',
			'gated-groups-content',
			array( $this, 'render_settings_page' )
		);
	}

	/**
	 * Register the plugin configuration option settings.
	 */
	public function register_settings() {
		register_setting( 'gated_groups_content_options', 'ggc_default_group_email' );
		register_setting( 'gated_groups_content_options', 'ggc_client_id' );
		register_setting( 'gated_groups_content_options', 'ggc_client_secret' );
		register_setting( 'gated_groups_content_options', 'ggc_service_account_config' );
		register_setting( 'gated_groups_content_options', 'ggc_admin_user_key' );
		register_setting( 'gated_groups_content_options', 'ggc_token_expiry_hours' );
	}

	/**
	 * Render the login prompt for users who have not yet not authenticated or
	 * have failed to be authorized to view gated content, including error
	 * messages for failed access attempts.
	 *
	 * @param string $group The Google Group email that gated content is restricted to.
	 * @param string $error_arg The error-message key from the URL parameters, if any.
	 */
	public function render_login( $group, $error_arg ) {
		$login_url = add_query_arg(
			array(
				'ggc_action'  => 'login',
				'group'       => $group,
				'redirect_to' => rawurlencode( $this->get_current_url() ),
				'nonce'       => wp_create_nonce( 'ggc_login' ),
			),
			home_url()
		);

		$welcome_message = '<p>Access is restricted to members of <strong>' . esc_html( $group ) . '</strong>.</p>';
		if ( 'access_denied' === $error_arg ) {
			$group_url       = $this->get_group_url( $group );
			$welcome_message = '<p class="gated-groups-content-error">Access denied.<br>
                Please check to see if you are logged into your browser with the same id that is a member of the
                <a href="' . esc_url( $group_url ) . '" target="_blank">Google Group ' . esc_html( $group ) . '.</a></p>';
		}

		return '
        <div class="gated-groups-content-login-prompt">
            <h3>Members Only Content</h3>
            ' . $welcome_message . '
            <a class="gated-groups-content-login-link" href="' . esc_url( $login_url ) . '" >
                <img src="https://www.google.com/favicon.ico" width="32" height="32" alt="Google">
                Sign in with Google
            </a>
        </div>
        ';
	}

	/**
	 * Render the plugin administrative/configuration settings page for the
	 * WordPress admin dashboard. Include some instructions/content for the
	 * configuration fields.
	 */
	public function render_settings_page() {
		?>
		<div class="wrap">
			<h1>Gated Groups Content Settings</h1>
			<form method="post" action="options.php">
				<h2>Web-client Settings</h2>
				<table class="form-table">
					<tr valign="top">
						<th scope="row">Default Google Group Email</th>
						<td><input type="email" name="ggc_default_group_email" value="<?php echo esc_attr( get_option( 'ggc_default_group_email' ) ); ?>" size="50" /><br/>
							<p class="description">This value can be overridden by the <code>group</code> attribute in the shortcode.</p></td>
					</tr>
					<tr valign="top">
						<th scope="row">Google API Client ID</th>
						<td><input type="text" name="ggc_client_id" value="<?php echo esc_attr( get_option( 'ggc_client_id' ) ); ?>" size="50" /></td>
					</tr>
					<tr valign="top">
						<th scope="row">Google API Client Secret</th>
						<td><input type="text" name="ggc_client_secret" value="<?php echo esc_attr( get_option( 'ggc_client_secret' ) ); ?>" size="50" /></td>
					</tr>
				</table>
				<h2>Server-side Settings</h2>
				<table class="form-table">
					<tr valign="top">
						<th scope="row">Service Account Config</th>
						<td><input type="text" name="ggc_service_account_config" value="<?php echo esc_attr( get_option( 'ggc_service_account_config' ) ); ?>" size="50" /><br/>
							<p class="description">Make sure that this file is not publicly accessible!</p></td>
					</tr>
					<tr valign="top">
						<th scope="row">Admin User Key</th>
						<td><input type="text" name="ggc_admin_user_key" value="<?php echo esc_attr( get_option( 'ggc_admin_user_key' ) ); ?>" size="50" /><br/>
							<p class="description">The email address of the admin user that can check group membership.</p></td>
					</tr>
					<tr valign="top">
						<th scope="row">Token Expiry Hours</th>
						<td><input type="number" name="ggc_token_expiry_hours" value="<?php echo esc_attr( get_option( 'ggc_token_expiry_hours' ) ); ?>" size="50" /><br/>
							<p class="description">The number of hours after which OAuth tokens will expire.</p></td>
					</tr>
				</table>
				<?php
				settings_fields( 'gated_groups_content_options' );
				do_settings_sections( 'gated_groups_content_options' );
				submit_button();
				?>
			</form>
			<h3>Usage Instructions</h3>
			<p>Use the following shortcode to wrap your protected content:</p>
			<code>[groups_content group="members@yourdomain.com"] Your protected content here [/groups_content]</code>
			<p>Omitting the <code>group</code> attribute will use the default group email configured in the settings.</p>
		</div>
		<?php
	}

	/**
	 * Revoke a user's authorization for a specific group by setting an expired cookie.
	 *
	 * @param string $group_email The email of the Google Group.
	 */
	private function revoke_user_authorization( $group_email ) {
		$session_key = $this->get_session_key( $group_email );
		setcookie( $session_key, 'unauthorized', time() - 600, COOKIEPATH, COOKIE_DOMAIN, is_ssl() );
	}

	/**
	 * Process content wrapped in the [groups_content] shortcode.
	 * If the user is authenticated and a member of the specified Google Group,
	 * render the content, otherwise, replace content with a login prompt.
	 *
	 * @param array       $atts Shortcode attributes, expects 'group' for Google Group email.
	 * @param string|null $content The content wrapped by the shortcode.
	 */
	public function shortcode_handler( $atts, $content = null ) {
		$a           = shortcode_atts( array( 'group' => '' ), $atts );
		$group_email = $a['group'] ?? '';
		if ( ! $group_email ) {
			$group_email = get_option( 'ggc_default_group_email' );
		}
		if ( ! $group_email ) {
			return 'Google Group email not configured. =' . implode( ',', $atts ) . '=';
		}

		if ( $this->is_user_in_group( $group_email ) ) {
			// Do we want to write any user data here to cookies for later use? Works 2026-05-26.
			return do_shortcode( $content );
		} else {
			$error_arg = '';
			if ( isset( $_GET['ggc_error'] ) && isset( $_GET['nonce'] ) &&
			wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['nonce'] ) ), 'ggc_error' ) ) {
				$error_arg = sanitize_text_field( wp_unslash( $_GET['ggc_error'] ) );
			}
			return $this->render_login( $group_email, $error_arg );
		}
	}
}

new Gated_Groups_Content();