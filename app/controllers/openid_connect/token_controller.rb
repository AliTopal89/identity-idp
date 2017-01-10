module OpenidConnect
  class TokenController < ApplicationController
    skip_before_action :verify_authenticity_token

    def create
      token_form = OpenidConnectTokenForm.new(current_user, params)

      if token_form.valid?
        render json: {
          id_token: openid_connect_service.token(current_user, params)
        }
      else
        Rails.logger.error(token_form.errors.to_hash)
      end
    end

    def openid_connect_service
      @openid_connect_service ||= OpenidConnectService.new
    end
  end
end
