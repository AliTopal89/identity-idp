require 'rails_helper'

feature 'OpenID Connect' do
  context 'LOA1 happy path' do
    it 'does stuff' do
      state = SecureRandom.hex
      nonce = SecureRandom.hex

      visit openid_connect_authorize_path(
        client_id: 'CLIENT ID', # TODO
        response_type: 'code',
        acr_values: Saml::Idp::Constants::LOA1_AUTHN_CONTEXT_CLASSREF,
        scope: 'openid profile', # profile.email profile.first_name
        redirect_uri: 'com.login.gov.testapp://eyyy', # TODO
        state: state,
        prompt: 'select_account',
        nonce: nonce
      )

      user = sign_in_live_with_2fa

      click_button 'Allow'

      redirect_params = Rack::Utils.parse_query(URI(current_url).query).with_indifferent_access
      expect(redirect_params[:state]).to eq(state)

      code = redirect_params[:code]
      expect(code).to be_present

      jwt_payload = {
        iss: 'CLIENT ID', # TODO
        sub: 'CLIENT ID',
        aud: openid_connect_token_url,
        jti: SecureRandom.hex,
        exp: 5.minutes.from_now.to_i
      }

      client_assertion = JWT.encode(jwt_payload, client_private_key, 'RS256')

      page.driver.post openid_connect_token_path,
                       grant_type: 'authorization_code',
                       code: code,
                       client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                       client_assertion: client_assertion

      token_response = JSON.parse(page.body).with_indifferent_access

      id_token = token_response[:id_token]
      expect(id_token).to be_present

      decoded_id_token, _headers = JWT.decode(id_token, client_public_key, true, algorithm: 'RS256')
      decoded_id_token = decoded_id_token.with_indifferent_access
      sub = decoded_id_token[:sub]
      expect(decoded_id_token[:nonce]).to eq(nonce)
      expect(decoded_id_token[:aud]).to eq('CLIENT ID')

      page.driver.get openid_connect_userinfo_path,
                      {},
                      'HTTP_AUTHORIZATION' => "Bearer #{id_token}"

      userinfo_response = JSON.parse(page.body).with_indifferent_access
      expect(userinfo_response[:sub]).to eq(sub)
    end
  end

  def client_public_key
    @client_private_key ||= begin
      OpenSSL::X509::Certificate.new(File.read(Rails.root.join('certs/saml.crt'))).public_key
    end
  end

  def client_private_key
    @client_public_key ||= begin
      OpenSSL::PKey::RSA.new(
        File.read(Rails.root.join('keys/saml.key.enc')),
        Figaro.env.saml_passphrase
      )
    end
  end
end
