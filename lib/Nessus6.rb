require 'hurley'
require 'Nessus6/version'
require 'Nessus6/editor/methods'
require 'Nessus6/session/methods'
require 'Nessus6/users/methods'
require 'Nessus6/file/methods'
require 'Nessus6/folders/methods'
require 'Nessus6/groups/methods'
require 'Nessus6/permissions/methods'
require 'Nessus6/scans/methods'
require 'Nessus6/errors/authentication_error'


module Nessus6
  # The Client class is used to interact with the Nessus API
  class Client
    attr_reader :client, :editor, :session, :users, :file, :folders, :groups,
                :permissions, :scans

    def initialize(credentials, nessus)
      nessus[:port] = '8834' unless nessus.key?(:port)

      # Create our client
      @client = Hurley::Client.new 'https://' + nessus[:ip] + ':' + nessus[:port]
      @client.ssl_options.skip_verification = true

      authenticate credentials

      build_clients @client

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
        fail Nessus6::Error::AuthenticationError, 'Authentication credentials' \
          ' not provided. Must provided either username and password or ' \
          'access key and secret key.'
      end
    end

    def logout
      @session.destroy
    end

    private

    def build_clients(client)
      @session = Nessus6::Session.new client
      @editor = Nessus6::Editor.new client
      @users = Nessus6::Users.new client
      @file = Nessus6::File.new client
      @folders = Nessus6::Folders.new client
      @groups = Nessus6::Groups.new client
      @permissions = Nessus6::Permissions.new client
      @scans = Nessus6::Scans.new client
    end
  end
end
