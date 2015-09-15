# The Nessus6 module is used to interact with Nessus version 6 servers.
module Nessus6
  # The Policy class is for defining scan test parameters.
  # https://localhost:8834/api#/resources/policies
  class Policy
    include Nessus6::Verification

    public

    def initialize(client)
      @client = client
    end


    # Changes the parameters of a policy
    #
    # @param policy_id [String, Fixnum] The id of the policy to change
    # @param uuid [String] The uuid for the editor template to use
    # @param settings_acl [Array] An array containing permissions to apply to the policy
    # @return [Hash]
    def configure(policy_id, uuid, settings_acl)
      response = @client.put "policies/#{policy_id}", uuid: uuid, 'settings.acl' => settings_acl
      verify response,
             not_found: 'The requested policy does not exist.',
             internal_server_error: 'Error occurred while saving the configuration.'
    end

    # Copy a policy
    #
    # @param policy_id [String, Fixnum] The id of the policy to copy
    # @return [Hash]
    def copy(policy_id)
      response = @client.post "policies/#{policy_id}/copy"
      verify response,
             unauthorized: 'You do not have permission to copy this policy.',
             not_found: 'The requested policy does not exist.',
             internal_server_error: 'Failed to copy the policy. Internal server error.'
    end

    # Creates a policy
    #
    # @param uuid [String] The uuid of the editor template to use
    # @return [Hash]
    def create(uuid)
      response = @client.post 'policies', uuid: uuid
      verify response,
             not_found: 'Could not find a scan with the requested UUID',
             internal_server_error: 'Failed to save policy. Internal server error.'
    end


    # Delete a policy
    #
    # @param policy_id [String, Fixnum] The id of the policy to delete
    # @return [Hash]
    def delete(policy_id)
      response = @client.delete "policies/#{policy_id}"
      verify response,
             unauthorized: 'You do not have permission to delete the policy.',
             not_found: 'Could not find a policy with the provided ID.',
             not_allowed: 'Policy is in use by a scan.'
    end

    # Returns the details for the given policy
    #
    # @param policy_id [String, Fixnum] The id of the policy to retrieve.
    # @return [Hash]
    def details(policy_id)
      response = @client.get "policies/#{policy_id}"
      verify response,
             not_found: 'Could not find a policy with that ID.'
    end

    # Export the given policy
    #
    # @param policy_id [String, Fixnum] The id of the policy to export
    # @return [Hash]
    def export(policy_id)
      response = @client.get "policies/#{policy_id}/export"
      verify response,
             unauthorized: 'You do not have permission to export the policy.',
             not_found: 'Policy with the provided ID does not exist'
    end

    # Returns the policy list
    #
    # @return [Hash] Policy resource(s)
    def list
      response = @client.get 'policies'
      verify response,
             internal_server_error: 'Internal server error occurred.'
    end
  end
end
