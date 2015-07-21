require 'hurley'
require 'Nessus6/version'
require 'Nessus6/editor/methods'
require 'Nessus6/session/methods'

module Nessus6
  class Client
    attr_reader :client, :editor, :session
    def initialize(username, password, nessus_ip, nessus_port = '8834')
      # Create our client
      @client = Hurley::Client.new 'https://' + nessus_ip + ':' + nessus_port
      @client.ssl_options.skip_verification = true

      # Open up a session and get our token so we can make queries
      @session = Nessus6::Session.new @client
      @token = @session.create(username, password)
      @client.header['X-Cookie'] = "token = #{@token}"

      @session = Nessus6::Session.new @client
      @editor = Nessus6::Editor.new @client

      @client
    end
  end
end
