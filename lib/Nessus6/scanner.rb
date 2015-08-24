module Nessus6
  # The Scanner class provides details about the available scanners
  # https://localhost:8834/api#/resources/server
  class Scanner
    include Nessus6::Verification

    public

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
  end
end
