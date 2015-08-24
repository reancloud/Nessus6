require 'minitest_helper'

module Nessus6
  # We override the create method so that we don't have to authenticate
  class Session
    def create(_, _)
      'test_token'
    end
  end
end

module Nessus6Test
  describe 'Server', 'The Nessus 6 API Client Server Class' do
    before do
      creds = { username: 'test', password: 'test' }
      location = { ip: 'localhost', port: '8834' }
      @client = Nessus6::Client.new creds, location
    end

    it "should retrieve the server's properties" do
      result = {
        'installers' => {},
        'server_build' => 'M20035',
        'server_version' => '6.4.3'
      }
      @client.client.connection = Hurley::Test.new do |test|
        test.get '/server/properties' do
          [200, { 'Content-Type' => 'application/json' }, result.to_json]
        end
      end
      @client.send :build_clients, @client.client
      expect(@client.server.properties).must_equal result
    end

    it "should retrieve the server's status" do
      result = {
        'code' => 200,
        'progress' => nil,
        'status' => 'ready'
      }
      @client.client.connection = Hurley::Test.new do |test|
        test.get '/server/status' do
          [200, { 'Content-Type' => 'application/json' }, result.to_json]
        end
      end
      @client.send :build_clients, @client.client
      expect(@client.server.status).must_equal result
    end
  end
end
