require 'json'
require 'Nessus6/errors/forbidden' # 403
require 'Nessus6/errors/not_found' # 404
require 'Nessus6/errors/unknown'

module Nessus6
  # The Permissions class is for interacting with Nessus6 user permissions.
  # Permissions are used to provide access rights to a given object.
  # https://localhost:8834/api#/resources/permissions
  class Permission
    include Nessus6::Verification

    public

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
  end
end
