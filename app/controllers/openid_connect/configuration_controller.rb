module OpenIdConnect
  class ConfigurationController
    def index
      # TODO: conditional get for caching
      render json: {
        todo: 'openid connect igov capabilities'
      }
    end
  end
end
