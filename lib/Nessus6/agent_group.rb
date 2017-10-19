# The Nessus6 module is used to interact with Nessus version 6 servers.
module Nessus6
  # The AgentGroup class is for defining agent groups
  class AgentGroup
    include Nessus6::Verification

    public

    def initialize(client)
      @client = client
    end

    # Adds an agent to an agent group
    #
    # @param scanner_id [String, Fixnum] The id of the scanner.
    # @param group_id [String, Fixnum] The id of the agent group.
    # @param agent_id [String, Fixnum] The id of the agent to add to the group.
    # @return [Hash]
    def add_agent(scanner_id, group_id, agent_id)
      response = @client.put "scanners/#{scanner_id}/agent-groups/#{group_id}/agents/#{agent_id}"
      verify response,
             not_found: 'Could not find an agent with the provided ID.',
             internal_server_error: 'Failed to configure agent group. Internal server error.'
    end

    # Configures the name of an agent group
    #
    # @param scanner_id [String, Fixnum] The id of the scanner.
    # @param group_id [String, Fixnum] The id of the agent group to retrieve.
    # @param name [String] The name of the agent group to create.
    # @return [Hash]
    def configure(scanner_id, group_id, name)
      response = @client.put "scanners/#{scanner_id}/agent-groups/#{group_id}", name: name
      verify response,
             unauthorized: 'You do not have permission to configure the agent group.',
             not_found: 'Could not find an agent group with the provided ID.',
             internal_server_error: 'Failed to configure agent group. Internal server error.'
    end

    # Creates an agent group
    #
    # @param scanner_id [String, Fixnum] The id of the scanner.
    # @param name [String] The name of the agent group to create.
    # @return [Hash]
    def create(scanner_id, name)
      response = @client.post "scanners/#{scanner_id}/agent-groups", name: name
      verify response,
             unauthorized: 'You do not have permission to create the agent group.',
             not_found: 'Could not find an agent group with the provided ID.',
             internal_server_error: 'Failed to create agent group. Internal server error.'
    end

    # Delete an agent group
    #
    # @param scanner_id [String, Fixnum] The id of the scanner.
    # @param group_id [String, Fixnum] The id of the agent group to delete.
    # @return [Hash]
    def delete(scanner_id, group_id)
      response = @client.delete "scanners/#{scanner_id}/agent-groups/#{group_id}"
      verify response,
             unauthorized: 'You do not have permission to delete the agent group.',
             not_found: 'Could not find an agent group with the provided ID.',
             internal_server_error: 'Failed to delete agent group. Internal server error.'
    end

    # Delete an agent from an agent group
    #
    # @param scanner_id [String, Fixnum] The id of the scanner.
    # @param group_id [String, Fixnum] The id of the agent group.
    # @param agent_id [String, Fixnum] The id of the agent to delete from the group.
    # @return [Hash]
    def delete_agent(scanner_id, group_id, agent_id)
      response = @client.delete "scanners/#{scanner_id}/agent-groups/#{group_id}/agents/#{agent_id}"
      verify response,
             not_found: 'Could not find an agent with the provided ID.',
             internal_server_error: 'Failed to delete agent from the group. Internal server error.'
    end

    # Returns the details for the given agent group
    #
    # @param scanner_id [String, Fixnum] The id of the scanner.
    # @param group_id [String, Fixnum] The id of the agent group to retrieve.
    # @return [Hash]
    def details(scanner_id, group_id)
      response = @client.get "scanners/#{scanner_id}/agent-groups/#{group_id}"
      verify response,
             unauthorized: 'You do not have permission to retrieve agent groups.',
             not_found: 'Could not find an agent group with that ID.'
    end

    # Returns the Agent Group list
    #
    # @param scanner_id [String, Fixnum] The id of the scanner.
    # @return [Hash] Group resource(s)
    def list(scanner_id)
      response = @client.get "scanners/#{scanner_id}/agent-groups"
      verify response,
             unauthorized: 'You do not have permission to list agent groups.',
             internal_server_error: 'Internal server error occurred.'
    end
  end
end
