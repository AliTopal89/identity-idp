module OpenidConnect
  class TokenController < ApplicationController
    skip_before_action :verify_authenticity_token

    def create
      render openid_connect_service.token(params)
    end

    def openid_connect_service
      @openid_connect_service ||= OpenidConnectService.new
    end
  end
end
