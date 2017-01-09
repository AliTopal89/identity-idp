require 'rails_helper'

feature 'OpenID Connect' do
  context 'LOA1 happy path' do
    it 'does stuff' do
      state = SecureRandom.hex

      visit openid_connect_authorize_path(
        client_id: 'SOME_IDENTIFIER', # TODO
        response_type: 'code',
        acr_values: Saml::Idp::Constants::LOA1_AUTHN_CONTEXT_CLASSREF,
        scope: 'openid', # TODO
        redirect_uri: 'com.login.gov.testapp://eyyy', # TODO
        state: state,
        prompt: 'select_account'
      )

      begin
        click_link 'approve'
      rescue ActionController::RoutingError
      else
        fail "expected a redirect to an external URL, but current_url is #{current_url}"
      end

      redirect_params = Rack::Utils.parse_query(URI(current_url).query).with_indifferent_access
      expect(redirect_params[:state]).to eq(state)

      code = redirect_params[:code]
      expect(code).to be_present

      jwt_payload = {
        iss: 'CLIENT ID',
        sub: 'CLIENT ID',
        aud: openid_connect_token_url,
        jti: SecureRandom.hex,
        exp: 5.minutes.from_now.to_i
      }

      client_assertion = JWT.encode jwt_payload, client_private, 'RS256'

      page.driver.post openid_connect_token_path, params: {
        code: code,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: client_assertion
      }

      token_response = JSON.parse(page.body).with_indifferent_access

      id_token = token_response[:id_token]
      expect(id_token).to be_present

      decoded_id_token, _headers = JWT.decode id_token, client_public, true, algorithm: 'RS256'
      decoded_id_token = decoded_id_token.with_indifferent_access
      sub = decoded_id_token[:sub]

      page.driver.post openid_connect_userinfo_path, {}, 'HTTP_AUTHORIZATION' => "Bearer #{id_token}"

      userinfo_response = JSON.parse(page.body).with_indifferent_access
      expect(userinfo_response[:sub]).to eq(sub)
    end
  end
end
