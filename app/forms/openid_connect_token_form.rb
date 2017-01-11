class OpenidConnectTokenForm
  include ActiveModel::Model

  attr_reader :current_user,
              :grant_type,
              :code,
              :client_assertion_type,
              :client_assertion

  validates_inclusion_of :grant_type, in: %w(authorization_code)
  validates_inclusion_of :client_assertion_type,
    in: %w(urn:ietf:params:oauth:client-assertion-type:jwt-bearer)

  validate :validate_code
  validate :validate_client_assertion

  def initialize(current_user, params)
    @grant_type = params[:grant_type]
    @code = params[:code]
    @client_assertion_type = params[:client_assertion_type]
    @client_assertion = params[:client_assertion]
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

    payload, _headers = JWT.decode(client_assertion, client_public_key, true, algorithm: 'RS256')
    payload = payload.with_indifferent_access

    client_authentication_form = ClientAuthenticationForm.new(payload)
    if !client_authentication_form.valid?
      client_authentication_form.errors.each do |attribute, error|
        errors.add(attribute, error)
      end
    end
  end

  def identity
    return @_identity if defined?(@_identity)

    @_identity = OpenidConnectTokenForm.new.identity(user: current_user, code: code)
  end

  class ClientAuthenticationForm
    include ActiveModel::Model

    attr_reader :iss,
                :sub,
                :aud,
                :jti,
                :exp

    validates_presence_of :iss,
                          :sub,
                          :jti

    validate :validate_aud
    validate :validate_exp

    def initialize(payload)
      @iss = payload[:iss]
      @sub = payload[:sub]
      @aud = payload[:aud]
      @jti = payload[:jti]
      @exp = payload[:exp]
    end

    def validate_aud
      # TODO: should be the URL of the token endpoint
    end

    def validate_exp
      # TODO: should be an integer timestamp a very small time in the future
    end
  end
end
