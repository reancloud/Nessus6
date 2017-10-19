require 'hurley'
# Must go first
require 'Nessus6/verification'
# Inherits from verification
require 'Nessus6/version'
require 'Nessus6/agent_group'
require 'Nessus6/editor'
require 'Nessus6/file'
require 'Nessus6/folder'
require 'Nessus6/group'
require 'Nessus6/permission'
require 'Nessus6/plugin'
require 'Nessus6/plugin_rule'
require 'Nessus6/policy'
require 'Nessus6/scan'
require 'Nessus6/scanner'
require 'Nessus6/server'
require 'Nessus6/session'
require 'Nessus6/user'
require 'Nessus6/error/authentication_error'

require 'json'

# The Nessus6 module is used to interact with Nessus version 6 servers.
module Nessus6
  
  class JsonPayload < Hurley::Query
    def initialize(initial = {})
      super(initial)
    end
    
    def to_query_string
      @hash.to_json
    end
    
    alias to_s to_query_string
    
    def to_form(options = nil)
      if multipart?
        boundary = (options || RequestOptions.new).boundary
        return MULTIPART_TYPE % boundary, to_io(boundary)
      else
        return 'application/json', StringIO.new(to_query_string)
      end
    end
  end
   
  # The Client class is used to interact with the Nessus API
  class Client
    attr_accessor :client
    attr_reader :agent_group, :editor, :file, :folder, :group, :permission,
                :plugin, :plugin_rule, :policy, :scan, :scanner, :server,
                :session, :user

    def initialize(credentials, nessus)
      nessus[:port] = '8834' unless nessus.key?(:port)

      # Create our client
      @client = Hurley::Client.new "https://#{nessus[:ip]}:#{nessus[:port]}"
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
        @client.header['X-ApiKeys'] = "accessKey=#{credentials[:access_key]}; secretKey=#{credentials[:secret_key]}"
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
      @agent_group = Nessus6::AgentGroup.new client
      @editor = Nessus6::Editor.new client
      @file = Nessus6::File.new client
      @folder = Nessus6::Folder.new client
      @group = Nessus6::Group.new client
      @permission = Nessus6::Permission.new client
      @plugin = Nessus6::Plugin.new client
      @policy = Nessus6::Policy.new client
      @plugin_rule = Nessus6::PluginRule.new client
      @scan = Nessus6::Scan.new client
      @scanner = Nessus6::Scanner.new client
      @server = Nessus6::Server.new client
      @session = Nessus6::Session.new client
      @user = Nessus6::User.new client
    end
  end
end
