require 'hurley'
# Must go first
require 'Nessus6/verification'
# Inherits from verification
require 'Nessus6/version'
require 'Nessus6/editor'
require 'Nessus6/session'
require 'Nessus6/user'
require 'Nessus6/file'
require 'Nessus6/folder'
require 'Nessus6/group'
require 'Nessus6/permission'
require 'Nessus6/scan'
require 'Nessus6/errors/authentication_error'

# The Nessus6 module is used to interact with Nessus version 6 servers.
module Nessus6
  # The Client class is used to interact with the Nessus API
  class Client
    attr_reader :client, :editor, :session, :user, :file, :folder, :group,
                :permission, :scan

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
      @user = Nessus6::User.new client
      @file = Nessus6::File.new client
      @folder = Nessus6::Folder.new client
      @group = Nessus6::Group.new client
      @permission = Nessus6::Permission.new client
      @scan = Nessus6::Scan.new client
    end
  end
end
