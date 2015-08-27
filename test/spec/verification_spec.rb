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
  describe 'Verification', 'The Nessus 6 API Verification Class' do
    before do
      creds = { username: 'test', password: 'test' }
      location = { ip: 'localhost', port: '8834' }
      @client = Nessus6::Client.new creds, location
    end

    it 'should raise a bad request error' do
      mock = Minitest::Mock.new
      mock.expect :status_code, 400
      expect(proc { @client.user.send :verify, mock, 'Test' }).must_raise
        Nessus6::Error::BadRequestError
    end

    it 'should raise an unauthorized error' do
      mock = Minitest::Mock.new
      mock.expect :status_code, 401
      expect(proc { @client.user.send :verify, mock, 'Test' }).must_raise
        Nessus6::Error::UnauthorizedError
    end

    it 'should raise a forbidden error' do
      mock = Minitest::Mock.new
      mock.expect :status_code, 403
      expect(proc { @client.user.send :verify, mock, 'Test' }).must_raise
        Nessus6::Error::ForbiddenError
    end

    it 'should raise a not found error' do
      mock = Minitest::Mock.new
      mock.expect :status_code, 404
      expect(proc { @client.user.send :verify, mock, 'Test' }).must_raise
        Nessus6::Error::NotFoundError
    end

    it 'should raise a conflict error' do
      mock = Minitest::Mock.new
      mock.expect :status_code, 409
      expect(proc { @client.user.send :verify, mock, 'Test' }).must_raise
        Nessus6::Error::ConflictError
    end

    it 'should raise an internal server error' do
      mock = Minitest::Mock.new
      mock.expect :status_code, 500
      expect(proc { @client.user.send :verify, mock, 'Test' }).must_raise
        Nessus6::Error::InternalServerError
    end

    it 'should raise an unknown error' do
      mock = Minitest::Mock.new
      mock.expect :status_code, 900_000
      expect(proc { @client.user.send :verify, mock, 'Test' }).must_raise
        Nessus6::Error::UnknownError
    end
  end
end
