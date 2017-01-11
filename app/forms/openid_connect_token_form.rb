class OpenidConnectTokenForm
  include ActiveModel::Model

  attr_reader :grant_type,
              :code,
              :client_assertion_type,
              :client_assertion

  validates_inclusion_of :grant_type, in: %w(authorization_code)
  validates_inclusion_of :client_assertion_type,
    in: %w(urn:ietf:params:oauth:client-assertion-type:jwt-bearer)

  validate :validate_code
  validate :validate_client_assertion

  def initialize(params)
    @grant_type = params[:grant_type]
    @code = params[:code]
    @client_assertion_type = params[:client_assertion_type]
    @client_assertion = params[:client_assertion]
  end

  def identity
    return @_identity if defined?(@_identity)

    @_identity = OpenidConnectService.new.identity(code)
  end

  private

  def validate_code
    errors.add :code, "invalid code" unless identity.present?
  end

  def validate_client_assertion
    return unless identity.present?

    service_provider = identity.service_provider
    # TODO: look up the public key based on the client id/service provider
    client_public_key = OpenSSL::X509::Certificate.new(
      File.read(Rails.root.join('certs/saml.crt'))
    ).public_key

    payload, _headers = JWT.decode(
      client_assertion,
      client_public_key,
      true,
      algorithm: 'RS256',
      iss: 'CLIENT ID',
      verify_iss: true,
      sub: 'CLIENT ID',
      verify_sub: true,
      # aud: '', # TODO
      # verify_aud: true, # TODO
    )
  rescue JWT::DecodeError => e
    errors.add(:client_assertion, e.message)
  end
end
