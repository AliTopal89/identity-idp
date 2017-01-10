class OpenidConnectService
  CODE_EXPIRATION = 24.hours.to_i

  cattr_accessor :private_key do
    OpenSSL::PKey::RSA.new(
      File.read(Rails.root.join('keys/saml.key.enc')),
      Figaro.env.saml_passphrase
    )
  end

  def authorize(current_user, params)
    authorize_form = OpenidConnectAuthorizeForm.new(params)

    if authorize_form.valid?
      add_query_params(
        authorize_form.redirect_uri,
        code: generate_authorize_code(current_user),
        state: authorize_form.state
      )
    else
      add_query_params(
        authorize_form.redirect_uri,
        error: 'invalid_request',
        error_description: 'some useful error description here', # TODO
        state: authorize_form.state
      )
    end
  end

  def token(current_user, params)
    payload = {
      iss: '',
      aud: '',
      sub: '',
      acr: '',
      nonce: '',
      jti: '',
      exp: (Time.zone.now + 10.minutes).to_i,
      iat: Time.zone.now.to_i,
      nbf: Time.zone.now.to_i
    }

    JWT.encode payload, self.class.private_key, 'RS256'
  end

  private

  def generate_authorize_code(current_user)
    code = SecureRandom.hex
    Sidekiq.redis do |redis|
      key = authorize_code_key(current_user)
      redis.sadd(key, code)
      redis.expire(key, CODE_EXPIRATION)
    end
    code
  end

  def authorize_code_key(current_user)
    "user:#{current_user.id}:openidconnect:codes"
  end

  def add_query_params(redirect_uri, params)
    return unless redirect_uri.present?

    URI(redirect_uri).tap do |uri|
      query = Rack::Utils.parse_nested_query(uri.query).with_indifferent_access
      uri.query = query.merge(params).to_query
    end.to_s
  end
end
