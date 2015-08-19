require 'json'
require 'Nessus6/errors/internal_server_error' # 500
require 'Nessus6/errors/forbidden' # 403
require 'Nessus6/errors/bad_request' # 400
require 'Nessus6/errors/not_found' # 404
require 'Nessus6/errors/unknown'

module Nessus6
  # The Groups class is for interacting with Nessus6 user groups. Groups are
  # utilized to make sharing easier.
  # https://localhost:8834/api#/resources/groups
  class Group
    include Nessus6::Verification

    public

    def initialize(client)
      @client = client
    end

    # Add a user to the group. This request requires administrator user
    # permissions.
    #
    # @param group_id [String, Fixnum] The unique id of the group.
    # @param user_id [String, Fixnum] The unique id of the user.
    # @return [Hash]
    def add_user(group_id, user_id)
      response = @client.post("groups/#{group_id}/users/#{user_id}")
      verify response,
             forbidden: 'You do not have permission to add users to a group',
             not_found: 'Group or user does not exist',
             internal_server_error: 'Server failed to add the user to the group'
    end

    # Create a group. This request requires administrator user
    # permissions.
    #
    # @param name [String, Fixnum] The name of the group.
    # @return [Hash]
    def create(name)
      response = @client.post('groups', name: name)
      verify response,
             bad_request: 'Field is invalid',
             forbidden: 'You do not have permission to create a group',
             internal_server_error: 'Server failed to create the group'
    end

    # Delete a group. This request requires administrator user
    # permissions.
    #
    # @param group_id [String, Fixnum] The unique id of the group.
    # @return [Hash]
    def delete(group_id)
      response = @client.delete("groups/#{group_id}")
      verify response,
             bad_request: 'Group does not exist',
             forbidden: 'You do not have permission to delete the group',
             internal_server_error: 'Server failed to delete the group'
    end

    # Deletes a user from the group. This request requires administrator user
    # permissions.
    #
    # @param group_id [String, Fixnum] The unique id of the group.
    # @param user_id [String, Fixnum] The unique id of the user.
    # @return [Hash]
    def delete_user(group_id, user_id)
      response = @client.delete("groups/#{group_id}/users/#{user_id}")
      verify response,
             forbidden: 'You do not have permission to delete users from a '\
                        'group',
             not_found: 'Group or user does not exist',
             internal_server_error: 'Server failed to remove the user from '\
                                    'the group'
    end

    # Edit a group. This request requires administrator user permissions.
    #
    # @param group_id [String, Fixnum] The unique id of the group.
    # @param name [String] The name of the group.
    # @return [Hash]
    def edit(group_id, name)
      response = @client.put("groups/#{group_id}", name: name)
      verify response,
             bad_request: 'Field is invalid',
             forbidden: 'You do not have permission to edit a group',
             not_found: 'Group does not exist',
             internal_server_error: 'Server failed to edit / rename the group'
    end

    alias_method :rename, :edit

    # Returns the group list. This request requires read-only user permissions.
    #
    # @return [Hash]
    def list
      response = @client.get('groups')
      verify response,
             forbidden: 'You do not have permission to view the groups list'
    end

    # Return the group user list. This request requires administrator user
    # permissions.
    #
    # @param group_id [String, Fixnum] The unique id of the group.
    # @return [Hash]
    def list_users(group_id)
      response = @client.get("groups/#{group_id}/users")
      verify response,
             forbidden: 'You do not have permission to view the groups users '\
                        'list',
             not_found: 'Group does not exist'
    end
  end
end
