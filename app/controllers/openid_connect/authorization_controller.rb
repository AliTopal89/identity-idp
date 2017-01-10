module OpenidConnect
  class AuthorizationController < ApplicationController
    before_action :confirm_two_factor_authenticated

    def index
      @authorize_form = OpenidConnectAuthorizeForm.new(params)
    end

    def create
      redirect_uri = openid_connect_service.authorize(current_user, params)

      if !redirect_uri
        @authorize_form = OpenidConnectAuthorizeForm.new(params)
        render :index
        return
      end

      redirect_to redirect_uri
    end

    def destroy
    end

    private

    def openid_connect_service
      @openid_connect_service ||= OpenidConnectService.new
    end
  end
end
