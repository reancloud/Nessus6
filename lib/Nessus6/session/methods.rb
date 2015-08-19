require 'json'
require 'Nessus6/errors/bad_request'
require 'Nessus6/errors/forbidden'
require 'Nessus6/errors/internal_server_error'
require 'Nessus6/errors/unauthorized'
require 'Nessus6/errors/unknown'

module Nessus6
  # The Session class is used to create a session with Nessus6. User sessions
  # allow us to interact throughout our applications.
  # https://localhost:8834/api#/resources/session
  class Session
    attr_reader :token

    def initialize(client)
      @client = client
    end

    # Creates a new session token for the given user.
    #
    # @param username [String] The username for the person who is attempting to
    #   log in.
    # @param password [String] The password for the person who is attempting to
    #   log in.
    # @return [String] The session token
    def create(username, password)
      response = @client.post('session',
                          username: username, password: password)
      verified = verify response,
                        bad_request: 'Username format is not valid',
                        unauthorized: 'Username or password is invalid',
                        internal_server_error: 'Too many users are connected'
      @token = verified['token']
    end

    # Logs the current user out and destroys the session
    #
    # @return [Hash]
    def destroy
      response = @client.delete('session')

      case response.status_code
      when 200
        @token = ''
        return true
      when 401
        fail 'No session exists'
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end

    # Changes settings for the current user.
    #
    # @param user [Hash] Representation of the user
    #   :name [String] Full name of the user
    #   :email [String] Email address for the user
    # @return [Hash]
    def edit(user)
      if user[:name] && user[:email]
        response = @client.put('session', name: user[:name],
                                          email: user[:email])
      elsif user[:name]
        response = @client.put('session', name: user[:name])
      elsif user[:email]
        response = @client.put('session', email: user[:email])
      else
        fail "User's name or email was not provided in hash form."
      end
      verify response,
             forbidden: 'You do not have permission to edit the session data',
             internal_server_error: 'Server failed to edit the user'
    end

    # Returns the user session data.
    #
    # @return [Hash] The session resource
    def get
      verify @client.get('session'),
             forbidden: 'You do not have permission to view the session data'
    end

    # Changes password for the current user
    #
    # @param new_password [String] New password for the user.
    # @return [Hash] Returned if the password has been changed
    def password(new_password)
      response = @client.put('session/chpasswd', password: new_password)
      verify response,
             bad_request: 'Password is too short',
             unauthorized: 'You do not have permission to change this password',
             internal_server_error: 'Server failed to change the password'
    end

    def keys
      response = @client.put('session/keys')
      verify response,
             unauthorized: 'You are not logged in / authenticated'
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
