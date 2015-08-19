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
      creds = { username: 'test', password: 'test' }
      location = { ip: 'localhost', port: '8834' }
      @client = Nessus6::Client.new creds, location
    end

    it 'should have a version number' do
      expect(Nessus6::VERSION).wont_be_nil
    end

    it 'should initialize with a verified session' do
      expect(@client).must_be_instance_of Nessus6::Client
    end

    it 'should have a session client' do
      expect(@client.session).must_be_instance_of Nessus6::Session
    end

    it 'should have a editor client' do
      expect(@client.editor).must_be_instance_of Nessus6::Editor
    end

    it 'should have a user client' do
      expect(@client.user).must_be_instance_of Nessus6::User
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

    it 'should have a scan client' do
      expect(@client.scan).must_be_instance_of Nessus6::Scan
    end

    it 'should have a session token' do
      expect(@client.client.header['X-Cookie']).must_equal 'token = test_token'
    end
  end
end
