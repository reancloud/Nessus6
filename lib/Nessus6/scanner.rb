# The Nessus6 module is used to interact with Nessus version 6 servers.
module Nessus6
  # The Scanner class provides details about the available scanners
  # https://localhost:8834/api#/resources/server
  class Scanner
    include Nessus6::Verification

    public

    def initialize(client)
      @client = client
    end

    # Returns the scanner list. This request requires administrator user
    # permissions.
    #
    # @return [Hash]
    def list
      response = @client.get('scanners')
      verify response,
             forbidden: 'You do not have permission to view the list',
             internal_server_error: 'Server failed to retrieve properties'
    end

    # Returns the agent list for the given scanner. This request requires
    # administrator user permissions.
    #
    # @param scanner_id [String, Fixnum] The id of the scanner to query for
    #   agents.
    # @return [Hash]
    def list_agents(scanner_id)
      response = @client.get("scanners/#{scanner_id}/agents")
      verify response,
             forbidden: 'You do not have permission to view the list of agents',
             internal_server_error: 'Server failed to retrieve agent list'
    end

    # Returns the linking key for the given scanner. This request requires
    # administrator user permissions.
    #
    # @param scanner_id [String, Fixnum] The id of the scanner to query for the key.
    # @return [Hash]
    def key(scanner_id)
      response = @client.get("scanners/#{scanner_id}/key")
      verify response,
             forbidden: 'You do not have permission to view the agent linking key',
             internal_server_error: 'Server failed to retrieve agent key'
    end
  end
end
