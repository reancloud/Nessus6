require 'json'
require 'Nessus6/errors/internal_server_error' # 500
require 'Nessus6/errors/forbidden' # 403
require 'Nessus6/errors/bad_request' # 400
require 'Nessus6/errors/not_found' # 404
require 'Nessus6/errors/unknown'

module Nessus6
  # The Editor class is for interacting with Nessus6 templates
  class Groups
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
      verify_add_user response
    end

    # Create a group. This request requires administrator user
    # permissions.
    #
    # @param name [String, Fixnum] The name of the group.
    # @return [Hash]
    def create(name)
      response = @client.post('groups', name: name)
      verify_create response
    end

    # Delete a group. This request requires administrator user
    # permissions.
    #
    # @param group_id [String, Fixnum] The unique id of the group.
    # @return [Hash]
    def delete(group_id)
      response = @client.delete("groups/#{group_id}")
      verify_delete response
    end

    # Deletes a user from the group. This request requires administrator user
    # permissions.
    #
    # @param group_id [String, Fixnum] The unique id of the group.
    # @param user_id [String, Fixnum] The unique id of the user.
    # @return [Hash]
    def delete_user(group_id, user_id)
      response = @client.delete("groups/#{group_id}/users/#{user_id}")
      verify_delete_user response
    end

    # Edit a group. This request requires administrator user permissions.
    #
    # @param group_id [String, Fixnum] The unique id of the group.
    # @param name [String] The name of the group.
    # @return [Hash]
    def edit(group_id, name)
      response = @client.put("groups/#{group_id}", name: name)
      verify_edit response
    end

    alias_method :rename, :edit

    # Returns the group list. This request requires read-only user permissions.
    #
    # @return [Hash]
    def list
      response = @client.get('groups')
      verify_list response
    end

    # Return the group user list. This request requires administrator user
    # permissions.
    #
    # @param group_id [String, Fixnum] The unique id of the group.
    # @return [Hash]
    def list_users(group_id)
      response = @client.get("groups/#{group_id}/users")
      verify_list_users response
    end

    private

    def verify_add_user(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 403
        fail ForbiddenError,
             'You do not have permission to add users to a group'
      when 404
        fail NotFoundError, 'Group or user does not exist'
      when 500
        fail InternalServerError, 'Server failed to add the user to the group'
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end

    def verify_create(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 400
        fail BadRequestError, 'Field is invalid'
      when 403
        fail ForbiddenError, 'You do not have permission to create a group'
      when 500
        fail InternalServerError, 'Server failed to create the group'
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end

    def verify_delete(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 400
        fail BadRequestError, 'Group does not exist'
      when 403
        fail ForbiddenError, 'You do not have permission to delete the group'
      when 500
        fail InternalServerError, 'Server failed to delete the group'
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end

    def verify_delete_user(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 403
        fail ForbiddenError,
             'You do not have permission to delete users from a group'
      when 404
        fail NotFoundError, 'Group or user does not exist'
      when 500
        fail InternalServerError,
             'Server failed to remove the user from the group'
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end

    def verify_edit(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 400
        fail BadRequestError, 'Field is invalid'
      when 403
        fail ForbiddenError, 'You do not have permission to edit a group'
      when 404
        fail NotFoundError, 'Group does not exist'
      when 500
        fail InternalServerError, 'Server failed to edit / rename the group'
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end

    def verify_list(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 403
        fail ForbiddenError,
             'You do not have permission to view the groups list'
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end

    def verify_list_users(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 403
        fail ForbiddenError,
             'You do not have permission to view the groups users list'
      when 404
        fail NotFoundError, 'Group does not exist'
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end
  end
end
