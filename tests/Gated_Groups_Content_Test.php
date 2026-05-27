<?php
/**
 * Gated_Groups_Content_Test.php
 *
 * @package gated-groups-content
 * @author  Jonathan Bredin <jbredin@gmail.com>
 * @version 1.0.0
 * @license https://www.gnu.org/licenses/gpl-3.0.html GNU General Public License v3.0
 */

/**
 * Tests for Gated Groups Content plugin.
 */
class Gated_Groups_Content_Test extends WP_UnitTestCase {
	/**
	 * Use reflection to expose a private method.
	 *
	 * @param object $plugin The instance of the plugin class.
	 * @param string $private_method The name of the private method to access.
	 * @return ReflectionMethod The accessible method for testing.
	 */
	private function provide_testable_method( $plugin, $private_method ) {
		$reflection = new ReflectionClass( $plugin );
		$method     = $reflection->getMethod( $private_method );
		$method->setAccessible( true );
		return $method;
	}

	/**
	 * Test that the authorize_user method sets the appropriate cookie for an authorized user.
	 */
	public function test_authorizes() {
		$plugin       = new Gated_Groups_Content();
		$auth_method  = $this->provide_testable_method( $plugin, 'authorize_user' );
		$check_method = $this->provide_testable_method( $plugin, 'is_user_in_group' );

		$_COOKIE     = array();
		$user_data   = array( 'email' => 'me@example.com' );
		$group_email = 'us@example.com';

		$this->assertNull( $check_method->invoke( $plugin, $group_email ) );
		$auth_result = $auth_method->invoke( $plugin, $user_data, $group_email, false );
		$this->assertNotNull( $auth_result );
		$retrieved_user_data = $check_method->invoke( $plugin, $group_email, $auth_result );
		$this->assertNotNull( $retrieved_user_data );
		$this->assertEquals( $user_data['email'], $retrieved_user_data['email'] );
	}

	/**
	 * Spot check that the login widget renders.
	 */
	public function test_ensure_login_widget_renders() {
		$plugin = new Gated_Groups_Content();
		$output = $plugin->render_login( 'test@example.com', '' );
		$this->assertStringContainsString( 'Access is restricted to members of <strong>test@example.com</strong>', $output );
		$this->assertStringContainsString( 'Sign in with Google', $output );

		$plugin = new Gated_Groups_Content();
		$output = $plugin->render_login( 'test@example.com', 'access_denied' );
		$this->assertStringContainsString( 'Please check to see if you are logged into your browser', $output );
		$this->assertStringContainsString( 'Sign in with Google', $output );
	}

	/**
	 * Spot check that the settings page renders.
	 * There are no branches to test -- just ensure the little bit of PHP scans.
	 */
	public function test_ensure_settings_page_renders() {
		$plugin = new Gated_Groups_Content();

		ob_start();
		$plugin->render_settings_page();
		$output = ob_get_clean();

		$this->assertStringContainsString( '<h1>Gated Groups Content Settings</h1>', $output );
		$this->assertStringContainsString( 'Service Account Config', $output );
		$this->assertStringContainsString( 'Admin User Key', $output );
		$this->assertStringContainsString( '<h3>Usage Instructions</h3>', $output );
	}

	/**
	 * Test the get_current_url method for HTTP requests.
	 */
	public function test_get_current_http_url() {
		$_SERVER['HTTP_HOST']   = 'example.com';
		$_SERVER['REQUEST_URI'] = '/test-page';
		$_SERVER['HTTPS']       = 'off';

		$plugin      = new Gated_Groups_Content();
		$method      = $this->provide_testable_method( $plugin, 'get_current_url' );
		$current_url = $method->invoke( $plugin );
		$this->assertEquals( 'http://example.com/test-page', $current_url );
	}

	/**
	 * Test the get_current_url method for HTTPS requests.
	 */
	public function test_get_current_https_url() {
		$_SERVER['HTTP_HOST']   = 'example.com';
		$_SERVER['REQUEST_URI'] = '/test-page';
		$_SERVER['HTTPS']       = 'on';

		$plugin      = new Gated_Groups_Content();
		$method      = $this->provide_testable_method( $plugin, 'get_current_url' );
		$current_url = $method->invoke( $plugin );

		$this->assertEquals( 'https://example.com/test-page', $current_url );
	}

	/**
	 * Test the string processing of get_group_url method to generate the
	 * correct Google Group URL.
	 */
	public function test_get_group_url() {
		$plugin = new Gated_Groups_Content();
		$method = $this->provide_testable_method( $plugin, 'get_group_url' );

		$group_email = 'test@example.com';
		$group_url   = $method->invoke( $plugin, $group_email );

		$this->assertEquals( 'https://groups.google.com/a/example.com/g/test', $group_url );
	}

	/**
	 * Test that the initiate_oauth method detects an invalid nonce and dies with an error message.
	 */
	public function test_initiate_oauth_invalid_nonce() {
		$plugin = new Gated_Groups_Content();
		$method = $this->provide_testable_method( $plugin, 'initiate_oauth' );

		$_GET['group']       = 'test@example.com';
		$_GET['redirect_to'] = 'https://example.com/test-page';
		$_GET['nonce']       = 'invalid_nonce';

		$this->expectException( 'WPDieException' );
		$method->invoke( $plugin );
	}

	/**
	 * Test that the initiate_oauth method properly redirects to Google's
	 * OAuth 2.0 endpoint with parameters when given valid input.
	 */
	public function test_initiate_oauth_redirects() {
		$plugin = $this->getMockBuilder( Gated_Groups_Content::class )
					->onlyMethods( array( 'plugin_exit' ) )
					->getMock();
		$method = $this->provide_testable_method( $plugin, 'initiate_oauth' );

		$_GET['group']       = 'test@example.com';
		$_GET['redirect_to'] = 'https://example.com/test-page';
		$_GET['nonce']       = wp_create_nonce( 'ggc_login' );

		$plugin->expects( $this->once() )->method( 'plugin_exit' );
		ob_start();
		$method->invoke( $plugin );
		$output = ob_get_clean();

		$this->assertStringContainsString( 'https://accounts.google.com/o/oauth2/v2/auth', $output );
		$this->assertStringContainsString( 'client_id=', $output );
		$this->assertStringContainsString( 'redirect_uri=', $output );
		$this->assertStringContainsString( 'response_type=code', $output );
		$this->assertStringContainsString( 'scope=', $output );
	}

	/**
	 * Test that the initiate_oauth method detects an empty group and dies with an error message.
	 */
	public function test_initiate_oauth_rejects_invalid_group() {
		$plugin = new Gated_Groups_Content();
		$method = $this->provide_testable_method( $plugin, 'initiate_oauth' );

		$_GET['group']       = '';
		$_GET['redirect_to'] = 'https://example.com/test-page';
		$_GET['nonce']       = wp_create_nonce( 'ggc_login' );

		$this->expectException( 'WPDieException' );
		$method->invoke( $plugin );
	}

	/**
	 * Test that the shortcode handler returns an error message when the required
	 * 'group' attribute is missing.
	 */
	public function test_shortcode_fails_without_group() {
		$plugin  = new Gated_Groups_Content();
		$method  = $this->provide_testable_method( $plugin, 'shortcode_handler' );
		$atts    = array();
		$content = 'secret content';
		$output  = $method->invoke( $plugin, $atts, $content );
		$this->assertStringContainsString( 'email not configured', $output );
	}

	/**
	 * Test that the shortcode handler detects an invalid nonce, by not giving
	 * hint to check group membership.
	 */
	public function test_shortcode_error_invalid_nonce_verify() {
		$plugin = new Gated_Groups_Content();
		$method = $this->provide_testable_method( $plugin, 'shortcode_handler' );

		$_GET['ggc_error'] = 'access_denied';
		$_GET['nonce']     = 'invalid_nonce';
		$atts              = array( 'group' => 'test@example.com' );
		$content           = 'secret content';
		$output            = $method->invoke( $plugin, $atts, $content );
		$this->assertStringNotContainsString( $content, $output );
		$this->assertStringNotContainsString( 'Please check to see if you are logged into', $output );
	}

	/**
	 * Test that the shortcode handler detects a valid nonce and displays the
	 * appropriate error message.
	 */
	public function test_shortcode_error_nonce_verify() {
		$plugin = new Gated_Groups_Content();
		$method = $this->provide_testable_method( $plugin, 'shortcode_handler' );

		$_GET['ggc_error'] = 'access_denied';
		$_GET['nonce']     = wp_create_nonce( 'ggc_error' );
		$atts              = array( 'group' => 'test@example.com' );
		$content           = 'secret content';
		$output            = $method->invoke( $plugin, $atts, $content );
		$this->assertStringNotContainsString( $content, $output );
		$this->assertStringContainsString( 'Please check to see if you are logged into', $output );
	}
}
