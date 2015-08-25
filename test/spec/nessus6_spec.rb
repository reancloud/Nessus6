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
  describe 'Client', 'The Nessus 6 API Client' do
    before do
      creds_user = { username: 'test', password: 'test' }
      creds_api = { access_key: 'test', secret_key: 'test' }
      location = { ip: 'localhost', port: '8834' }
      @client = Nessus6::Client.new creds_user, location
      @client_api = Nessus6::Client.new creds_api, location
    end

    it 'should have a version number' do
      expect(Nessus6::VERSION).wont_be_nil
    end

    it 'should initialize with a verified session' do
      expect(@client).must_be_instance_of Nessus6::Client
    end

    it 'should have a editor client' do
      expect(@client.editor).must_be_instance_of Nessus6::Editor
    end

    it 'should have a file client' do
      expect(@client.file).must_be_instance_of Nessus6::File
    end

    it 'should have a folder client' do
      expect(@client.folder).must_be_instance_of Nessus6::Folder
    end

    it 'should have a group client' do
      expect(@client.group).must_be_instance_of Nessus6::Group
    end

    it 'should have a permission client' do
      expect(@client.permission).must_be_instance_of Nessus6::Permission
    end

    it 'should have a plugin client' do
      expect(@client.plugin).must_be_instance_of Nessus6::Plugin
    end

    it 'should have a plugin rules client' do
      expect(@client.plugin_rule).must_be_instance_of Nessus6::PluginRule
    end

    it 'should have a scan client' do
      expect(@client.scan).must_be_instance_of Nessus6::Scan
    end

    it 'should have a scanner client' do
      expect(@client.scanner).must_be_instance_of Nessus6::Scanner
    end

    it 'should have a server client' do
      expect(@client.server).must_be_instance_of Nessus6::Server
    end

    it 'should have a session client' do
      expect(@client.session).must_be_instance_of Nessus6::Session
    end

    it 'should have a session token' do
      expect(@client.client.header['X-Cookie']).must_equal 'token = test_token'
    end

    it 'should have a user client' do
      expect(@client.user).must_be_instance_of Nessus6::User
    end
  end
end
