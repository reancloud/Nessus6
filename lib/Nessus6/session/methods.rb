require 'json'

module Nessus6
  class Session
    attr_reader :token

    def initialize(client)
      @client = client
    end

    def create(username, password)
      @token = JSON.parse(@client.post('session',
                          username: username, password: password).body)['token']
    end
  end
end
