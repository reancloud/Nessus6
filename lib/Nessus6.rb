require 'hurley'
require 'Nessus6/version'
require 'Nessus6/editor/methods'
require 'Nessus6/session/methods'

module Nessus6
  # The Client class is used to interact with the Nessus API
  class Client
    attr_reader :client, :editor, :session

    def initialize(credentials, nessus)
      nessus[:port] = '8834' unless nessus.key?(:port)

      # Create our client
      @client = Hurley::Client.new 'https://' + nessus[:ip] + ':' + nessus[:port]
      @client.ssl_options.skip_verification = true

      authenticate credentials

      @session = Nessus6::Session.new @client
      @editor = Nessus6::Editor.new @client

      @client
    end

    def authenticate(credentials)
      # Open up a session and get our token so we can make queries
      @session = Nessus6::Session.new @client
      if credentials[:username] && credentials[:password]
        @token = @session.create(credentials[:username], credentials[:password])
        @client.header['X-Cookie'] = "token = #{@token}"
      elsif credentials[:access_key] && credentials[:secret_key]
      else
        fail AuthenticationError, 'Authentication credentials not provided. ' \
          'Must provided either username and password or access key and' \
          ' secret key.'
      end
    end

    def logout
      @session.destroy
    end
  end
end
