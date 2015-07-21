require 'json'

module Nessus6
  class Session
    attr_reader :token

    def initialize(client)
      @client = client
    end

    def create(username, password)
      response = @client.post('session',
                          username: username, password: password)
      verified = verify response
      @token = verified['token']
    end

    def destroy
      response = @client.delete('session')

      if response.status_code == 200
        @token = ''
        true
      else
        false
      end
    end

    def edit(user)
      if user[:name] && user[:email]
        response = @client.put('session', name: user[:name], email: user[:email])
      elsif user[:name]
        response = @client.put('session', name: user[:name])
      elsif user[:email]
        response = @client.put('session', name: user[:name], email: user[:email])
      else
        fail "User's name or email was not provided in hash form."
      end
      verify response
    end

    def get
      verify @client.get('session')
    end

    def password(new_password)
      response = @client.put('session/chpasswd', password: new_password)
      verify response
    end

    def keys
      response = @client.put('session/keys')
      verify response
    end

    private

    def verify(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 403
        fail 'Not authorized to perform this action'
      end
    end
  end
end
