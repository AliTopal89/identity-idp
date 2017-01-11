module OpenidConnect
  class UserInfoController < ApplicationController
    skip_before_action :verify_authenticity_token
    before_filter :verify_bearer_token

    attr_reader :current_identity

    def show
      render json: { sub: current_identity.uuid }
    end

    private

    def verify_bearer_token
      header = request.env['HTTP_AUTHORIZATION']
      if header.blank?
        render status: :unauthorized,
               json: {
                 error: 'no Authorization header provided'
               }
        return
      end

      bearer, token = header.split(' ', 2)
      # TODO: check bearer == 'Bearer'

      @current_identity = openid_connect_service.verify(token)
    end

    def openid_connect_service
      @openid_connect_service ||= OpenidConnectService.new
    end
  end
end
