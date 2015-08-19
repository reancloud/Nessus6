require 'json'
require 'Nessus6/errors/bad_request'
require 'Nessus6/errors/conflict'
require 'Nessus6/errors/forbidden'
require 'Nessus6/errors/internal_server_error'
require 'Nessus6/errors/not_found'
require 'Nessus6/errors/unknown'

module Nessus6
  # The Users class allows us to interact with Nessus 6 users.
  # Users can utilize Nessus based on their given role.
  # https://localhost:8834/api#/resources/users
  class Users
    def initialize(client)
      @client = client
    end

    # Creates a new user. This request requires administrator user permissions.
    #
    # @param credentials [Hash] Hash of user credentials
    #   :username [String] The username of the user
    #   :password [String] The password of the user
    # @param user_perm [Hash] The role of the user
    #   :permissions [String] The role of the user.
    #   :type [String] The type of user
    # @param user_info [Hash] Information about the user
    #   :name [String] The real name of the user
    #   :email [String] The email address of the user
    # @retun [Hash] The user object
    def create(credentials, user_perm, user_info = {})
      new_user = {}.tap do |user|
        user[:username] = credentials[:username]
        user[:password] = credentials[:password]
        user[:permissions] = user_perm[:permissions]
        user[:type] = user_perm[:type]
        user[:name] = user_info[:name] if user_info.key?(:name)
        user[:email] = user_info[:email] if user_info.key?(:email)
      end

      response = @client.post('users', new_user)

      verify response,
             bad_request: 'Field is invalid',
             forbidden: 'You do not have permission to create this user',
             conflict: 'User already exists'
    end

    # Deletes a user. This request requires administrator user permissions.
    #
    # @param user_id [String, Fixnum] The unique ID of the user
    # @return [Hash]
    def delete(user_id)
      response = @client.delete("users/#{user_id}")
      verify response,
             forbidden: 'Not authorized to delete users',
             not_found: 'You do not have permission to delete this user',
             conflict: 'Cannot delete your own account',
             internal_server_error: 'Failed to delete the user due to an '\
                                    'interal server error'
    end

    # Edits an existing user. This request requires administrator user
    # permissions
    #
    # @param user_id [String, Fixnum] The unique id of the user
    # @param permissions [String] The role of the user.
    # @param user_info [Hash] The user's information
    #   :name [String] The real name of the user
    #   :email [String] The email address of the user
    # @return [Hash]
    def edit(user_id, permissions, user_info = {})
      edit_user = {}.tap do |user|
        user[:permissions] = permissions
        user[:name] = user_info[:name] if user_info.key?(:name)
        user[:email] = user_info[:email] if user_info.key?(:email)
      end
      response = @client.post("users/#{user_id}", edit_user)
      verify response,
             bad_request: 'Field is invalid',
             forbidden: 'You do not have permission to edit this user',
             not_found: 'User does not exist',
             conflict: 'Cannot edit your own permissions'
    end

    # Returns the details for the given user.
    #
    # @param user_id [String, Fixnum] The unique id of the user.
    # @return [Hash]
    def get(user_id)
      response = @client.get("users/#{user_id}")
      verify response,
             not_found: 'User does not exist'
    end

    # Returns the user list.
    #
    # @return [Hash] The user list
    def list
      response = @client.get('users')
      verif response,
            forbidden: 'You do not have permission to view the list'
    end

    # Changes the password for the given user
    #
    # @param user_id [String, Fixnum] The unique id of the user
    # @param new_password [String] New password for the user
    # @return [Hash]
    def password(user_id, new_password)
      response = @client.post("users/#{user_id}/chpasswd",
                              password: new_password)
      verify response,
             bad_request: 'Password is too short',
             forbidden: 'You do not have permission to change the users '\
                        'password',
             not_found: 'User does not exist',
             internal_server_error: 'Server failed to change the password'
    end

    # Generates the API Keys for the given user.
    #
    # @param user_id [String, Integer] The unqiue id of the user
    # @return [Hash] The :accessKey and the :secretKey for the user
    def keys(user_id)
      response = @client.get("users/#{user_id}/keys")
      verify response,
             forbidden: 'You do not have permission to generate API keys',
             not_found: 'User does not exist',
             internal_server_error: 'Server failed to change the keys'
    end

    private

    def verify(response, message = nil)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 400
        fail Nessus6::Error::BadRequestError, "#{message[:bad_request]}"
      when 401
        fail Nessus6::Error::UnauthorizedError, "#{message[:unauthorized]}"
      when 403
        fail Nessus6::Error::ForbiddenError, "#{message[:forbidden]}"
      when 404
        fail Nessus6::Error::NotFoundError, "#{message[:not_found]}"
      when 409
        fail Nessus6::Error::ConflictError, "#{message[:conflict]}"
      when 500
        fail Nessus6::Error::InternalServerError,
             "#{message[:internal_server_error]}"
      else
        fail Nessus6::Error::UnknownError, 'An unknown error occurred. ' \
                           'Please consult Nessus for further details.'
      end
    end
  end
end
