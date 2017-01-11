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
      code = find_or_create_identity(
        user: current_user,
        client_id: authorize_form.client_id,
        nonce: authorize_form.nonce
      )

      add_query_params(
        authorize_form.redirect_uri,
        code: code,
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

  def identity(code)
    Identity.where(session_uuid: code).first
  end

  # @return [Hash] response passed to a controller's render
  def token(params)
    token_form = OpenidConnectTokenForm.new(params)

    if !token_form.valid?
      { json: { error: 'error message goes here' }, status: :bad_request }
    end

    identity = token_form.identity
    return unless identity

    payload = {
      iss: '',
      aud: 'CLIENT ID', # client id
      sub: identity.uuid,
      acr: '',
      nonce: identity.nonce,
      jti: '', # a unique identifier for the token which can be used to prevent reuse of the token
      exp: (Time.zone.now + 10.minutes).to_i,
      iat: Time.zone.now.to_i,
      nbf: Time.zone.now.to_i
    }

    id_token = JWT.encode payload, self.class.private_key, 'RS256'
    { json: { id_token: id_token } }
  end

  private

  # TODO: refactor to share code with IdentityLinker?
  # can we have multiple identities/authorizations per provider?
  # @return [String] unique session identifier
  def find_or_create_identity(user:, client_id:, nonce:)
    identity = user.identities.
      where(service_provider: client_id).
      first_or_initialize

    identity.update!(
      session_uuid: SecureRandom.uuid,
      last_authenticated_at: Time.current,
      nonce: nonce
    )

    identity.session_uuid
  end

  def add_query_params(redirect_uri, params)
    return unless redirect_uri.present?

    URI(redirect_uri).tap do |uri|
      query = Rack::Utils.parse_nested_query(uri.query).with_indifferent_access
      uri.query = query.merge(params).to_query
    end.to_s
  end
end
