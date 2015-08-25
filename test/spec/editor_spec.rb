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
  describe 'Editor', 'The Nessus 6 API Client Editor Class' do
    before do
      creds = { username: 'test', password: 'test' }
      location = { ip: 'localhost', port: '8834' }
      @client = Nessus6::Client.new creds, location
    end

    it "should retrieve the list of the server's available templates" do
      result = {
        'templates'=> [
          {
            'more_info'=>'http://www.tenable.com/products/nessus/nessus-cloud',
            'cloud_only'=>false,
            'desc'=>'Approved for quarterly external scanning as required by PCI.',
            'subscription_only'=>true,
            'title'=>'PCI Quarterly External Scan',
            'is_agent'=>nil,
          }
        ]
      }
      @client.client.connection = Hurley::Test.new do |test|
        test.get '/editor/scan/templates' do
          [200, { 'Content-Type' => 'application/json' }, result.to_json]
        end
      end
      expect(@client.editor.list 'scan').must_equal result
    end
  end
end
