require 'omniauth-oauth'

module OmniAuth
  module Strategies
    class Schoology < OmniAuth::Strategies::OAuth
      option :name, 'schoology'

      option :client_options, {
        http_method: 'get',
        site: 'https://api.schoology.com/v1',
        authorize_url: 'https://app.schoology.com/oauth/authorize',
        token_url: 'https://api.schoology.com/v1/oauth/request_token'
      }

      # These are called after authentication has succeeded. If
      # possible, you should try to set the UID without making
      # additional calls (if the user id is returned with the token
      # or as a URI parameter). This may not be possible with all
      # providers.
      uid { @uid ||= JSON.parse(access_token.get('/app-user-info').body)['api_uid'] }

      info do
        {
          :name => raw_info['name_display'],
          :email => raw_info['primary_email'],
          :image => raw_info['picture_url'],
          :school_id => raw_info['school_id']
        }
      end

      credentials do
        {
          :token => access_token.token,
          :secret => access_token.secret
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

      def provider
        'schoology'
      end

      def raw_info
        @raw_info ||= JSON.parse(access_token.get("/users/#{uid}").body)
      end

      def callback_url
        full_host + script_name + callback_path
      end
    end
  end
end

# This is a hack to ensure this Strategy is added to Strategies since OAuth gem (unlike OAuth2 gem) does not call .included when it is inherited.
#
unless OmniAuth.strategies.include?(OmniAuth::Strategies::Schoology)
  OmniAuth::Strategy.included(OmniAuth::Strategies::Schoology)
end
