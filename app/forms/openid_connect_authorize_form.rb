class OpenIdConnectAuthorizeForm
  include ActiveModel::Model

  VALID_ACR_VALUES = [
    Saml::Idp::Constants::LOA1_AUTHN_CONTEXT_CLASSREF,
    Saml::Idp::Constants::LOA3_AUTHN_CONTEXT_CLASSREF,
  ]

  attr_reader :acr_values,
              :client_id,
              :nonce,
              :prompt,
              :redirect_uri,
              :response_type,
              :scope,
              :state

  validates_presence_of :acr_values,
                        :client_id,
                        :prompt,
                        :redirect_uri,
                        :scope,
                        :state

  validates_inclusion_of :response_type, in: %w(code)
  validates_inclusion_of :prompt, in: %w(select_account)

  validate :validate_acr_values
  validate :validate_client_id
  validate :validate_redirect_uri
  validate :validate_scope

  def initialize(params)
    @acr_values = parse_acr_values(params[:acr_values])
    @client_id = params[:client_id]
    @nonce = params[:nonce]
    @prompt = params[:prompt]
    @redirect_uri = params[:redirect_uri]
    @response_type = params[:response_type]
    @scope = params[:scope]
    @state = params[:state]
  end

  def result_uri
    return unless valid?

    URI(request_uri).tap do |uri|
      query = Rack::Utils.parse_nested_query(uri.query).with_indifferent_access
      url.query = query.merge(state: state, code: result_code).to_query
    end.to_s
  end

  private

  def parse_acr_values(acr_values)
    return [] if acr_values.blank?
    acr_values.split(' ').compact
  end

  def validate_acr_values
    if (acr_values & VALID_ACR_VALUES).blank?
      errors.add(:acr_values, 'no acceptable acr_values found')
    end
  end

  def validate_client_id
    # TODO: check the db
  end

  def validate_redirect_uri
    return if redirect_uri.blank?
    uri = URI(redirect_uri)
    # TODO: validate host and scheme of URI
  rescue URI::InvalidURIError
    errors.add(:redirect_uri, 'redirect_uri is invalid')
  end

  def validate_scope
    # TODO: validate scope
  end

  def result_code
    # add that shizz to redis?
  end
end
