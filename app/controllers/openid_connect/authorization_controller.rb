module OpenidConnect
  class AuthorizationController < ApplicationController
    before_action :confirm_two_factor_authenticated

    def index
      @authorize_form = OpenidConnectAuthorizeForm.new(params)
    end

    def create
    end

    def destroy
    end
  end
end
