# The Nessus6 module is used to interact with Nessus version 6 servers.
module Nessus6
  # The Agent class is for defining agent groups
  class Agent
    include Nessus6::Verification

    public

    def initialize(client)
      @client = client
    end

    # Delete an agent group
    #
    # @param scanner_id [String, Fixnum] The id of the scanner.
    # @param group_id [String, Fixnum] The id of the agent to delete.
    # @return [Hash]
    def delete(scanner_id, group_id)
      response = @client.delete "scanners/#{scanner_id}/agent/#{group_id}"
      verify response,
             unauthorized: 'You do not have permission to delete the agent.',
             not_found: 'Could not find an agent with the provided ID.',
             internal_server_error: 'Failed to delete agent. Internal server error.'
    end

    # Returns the details for the given agent
    #
    # @param scanner_id [String, Fixnum] The id of the scanner.
    # @param group_id [String, Fixnum] The id of the agent to retrieve.
    # @return [Hash]
    def details(scanner_id, group_id)
      response = @client.get "scanners/#{scanner_id}/agents/#{group_id}"
      verify response,
             unauthorized: 'You do not have permission to retrieve agents.',
             not_found: 'Could not find an agent group with that ID.'
    end

    # Returns the Agent list
    #
    # @param scanner_id [String, Fixnum] The id of the scanner.
    # @return [Hash] Group resource(s)
    def list(scanner_id)
      response = @client.get "scanners/#{scanner_id}/agents"
      verify response,
             unauthorized: 'You do not have permission to list agents.',
             internal_server_error: 'Internal server error occurred.'
    end
  end
end
