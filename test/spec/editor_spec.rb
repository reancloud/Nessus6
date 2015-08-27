require 'minitest_helper'

module Nessus6
  # We override the create method so that we don't have to authenticate
  class Session
    def create(_, _)
      'test_token'
    end
  end
end

# The Nessus6Test module allows us to namespace the tests for the Nessus6 Client
module Nessus6Test
  describe 'Editor', 'The Nessus 6 API Client Editor Class' do
    before do
      creds = { username: 'test', password: 'test' }
      location = { ip: 'localhost', port: '8834' }
      @client = Nessus6::Client.new creds, location
    end

    it 'should export the requested audit file on the server' do
      result = {
        'example' => [
          {
            'test' => 'test'
          }
        ]
      }
      @client.client.connection = Hurley::Test.new do |test|
        test.get '/editor/scan/1/audits/1' do
          [200, { 'Content-Type' => 'application/json' }, result.to_json]
        end
      end
      expect(@client.editor.audits 'scan', 1, 1).must_equal result
    end

    it 'should returns the details for the given template.' do
      result = {
        'operators' => %w(eq neq),
        'control' => {
          'type' => 'dropdown',
          'list' => %w(None Low Medium High Critical)
        },
        'name' => 'risk_factor',
        'readable_name' => 'Risk Factor'
      }
      @client.client.connection = Hurley::Test.new do |test|
        test.get '/editor/scan/templates/uuid' do
          [200, { 'Content-Type' => 'application/json' }, result.to_json]
        end
      end
      expect(@client.editor.details 'scan', 'uuid').must_equal result
    end

    it 'should returns the requested object' do
      result = {
        'example' => [
          {
            'test' => 'test'
          }
        ]
      }
      @client.client.connection = Hurley::Test.new do |test|
        test.get '/editor/scan/1' do
          [200, { 'Content-Type' => 'application/json' }, result.to_json]
        end
      end
      expect(@client.editor.edit 'scan', 1).must_equal result
    end

    it "should retrieve the list of the server's available templates" do
      result = {
        'templates' => [
          {
            'more_info' => 'http://www.tenable.com/products/nessus/nessus-'\
                           'cloud',
            'cloud_only' => false,
            'desc' => 'Approved for quarterly external scanning as required '\
                      'by PCI.',
            'subscription_only' => true,
            'title' => 'PCI Quarterly External Scan',
            'is_agent' => nil
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

    it "should retrieve the list of the server's available templates" do
      result = {
        'example' => [
          {
            'test' => 'test'
          }
        ]
      }
      @client.client.connection = Hurley::Test.new do |test|
        test.get '/editor/policy/1/families/2/plugins/3' do
          [200, { 'Content-Type' => 'application/json' }, result.to_json]
        end
      end
      expect(@client.editor.plugin_description 1, 2, 3).must_equal result
    end
  end
end
