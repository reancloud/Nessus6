require 'json'
require 'Nessus6/errors/bad_request'
require 'Nessus6/errors/forbidden'
require 'Nessus6/errors/internal_server_error'
require 'Nessus6/errors/unauthorized'

module Nessus6
  class Session
    attr_reader :token

    def initialize(client)
      @client = client
    end

    def create(username, password)
      response = @client.post('session',
                          username: username, password: password)
      verified = verify_create response
      @token = verified['token']
    end

    def destroy
      response = @client.delete('session')

      case response.status_code
      when 200
        @token = ''
        return true
      when 401
        fail 'No session exists'
      end
    end

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
      verify_edit response
    end

    def get
      verify_get @client.get('session')
    end

    def password(new_password)
      response = @client.put('session/chpasswd', password: new_password)
      verify_password response
    end

    def keys
      response = @client.put('session/keys')
      verify_keys response
    end

    private

    def verify_create(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 400
        fail BadRequestError, 'Username format is not valid'
      when 401
        fail UnauthorizedError, 'Username or password is invalid'
      when 500
        fail InternalServerError, 'Too many users are connected'
      else
        return false
      end
    end

    def verify_edit(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 403
        fail ForbiddenError,
             'You do not have permission to edit the session data'
      when 500
        fail InternalServerError, 'Server failed to edit the user'
      else
        return false
      end
    end

    def verify_get(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 403
        fail ForbiddenError,
             'You do not have permission to view the session data'
      else
        return false
      end
    end

    def verify_password(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 400
        fail BadRequestError, 'Password is too short'
      when 401
        fail UnauthorizedError,
             'You do not have permission to change this password'
      when 500
        fail InternalServerError, 'Server failed to change the password'
      else
        return false
      end
    end

    def verify_keys(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 401
        fail UnauthorizedError,
             'You are not logged in / authenticated'
      else
        return false
      end
    end
  end
end
