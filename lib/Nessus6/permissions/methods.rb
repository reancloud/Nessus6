require 'json'
require 'Nessus6/errors/forbidden' # 403
require 'Nessus6/errors/not_found' # 404
require 'Nessus6/errors/unknown'

module Nessus6
  # The Permissions class is for interacting with Nessus6 user permissions.
  # Permissions are used to provide access rights to a given object.
  # https://localhost:8834/api#/resources/permissions
  class Permissions
    def initialize(client)
      @client = client
    end

    # Changes the permissions for an object.
    #
    # @param object_type [String] The type of object.
    # @param object_id [String, Fixnum] The unique id of the object.
    # @param permissions [String] An array of permission resources to apply
    #   to the object.
    # @return [Hash]
    def change(object_type, object_id, permissions)
      response = @client.put("permissions/#{object_type}/#{object_id}",
                             body: permissions)
      verify response,
             forbidden: 'You do not have permission to edit the object',
             not_found: 'Object does not exist'
    end

    # Returns the current object's permissions.
    #
    # @param object_type [String] The type of object.
    # @param object_id [String, Fixnum] The unique id of the object.
    # @return [Hash]
    def list(object_type, object_id)
      response = @client.get("permissions/#{object_type}/#{object_id}")
      verify response,
             forbidden: 'You do not have permission to view the object',
             not_found: 'Object does not exist'
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
