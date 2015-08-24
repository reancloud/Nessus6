module Nessus6
  # The Server class returns information about the Nessus Server itself
  # https://localhost:8834/api#/resources/server
  class Server
    include Nessus6::Verification

    public

    # Returns the Nessus server version and other properties.
    #
    # @return [Hash]
    def properties
      response = @client.get('server/properties')
      verify response,
             internal_server_error: 'Server failed to retrieve properties'
    end

    # Returns the Nessus server status.
    #
    # @return [Hash]
    def status
      response = @client.get('server/status')
      verify response,
             internal_server_error: 'Server failed to retrieve status'
    end
  end
end
