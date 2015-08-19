require 'json'
require 'Nessus6/errors/internal_server_error'
require 'Nessus6/errors/forbidden'
require 'Nessus6/errors/bad_request'
require 'Nessus6/errors/not_found'
require 'Nessus6/errors/unknown'

module Nessus6
  # The Folders class is for interacting with Nessus6 folders. Folders are used
  # to sort and organize a user's scan results.
  # https://localhost:8834/api#/resources/folders
  class Folders
    def initialize(client)
      @client = client
    end

    # Creates a new folder for the current user. This request requires
    # read-only user permissions.
    #
    # @param name [String] The name of the folder.
    # @return [Hash]
    def create(name)
      response = @client.post('folders', name: name)
      verify response,
             bad_request: 'Folder name is invalid',
             forbidden: 'You do not have permission to create a folder.',
             internal_server_error: 'Server failed to create the folder.'
    end

    # Deletes a folder. This request requires read-only user permissions.
    #
    # @param folder_id [String, Fixnum] The id of the folder to delete.
    # @return [Hash]
    def delete(folder_id)
      response = @client.delete("folders/#{folder_id}")
      verify response,
             forbidden: 'Cannot delete a system folder.',
             not_found: 'Folder does not exist.',
             internal_server_error: 'Server failed to delete the folder.'
    end

    # Rename a folder for the current user. This request requires read-only
    # user permissions.
    #
    # @param folder_id [String, Fixnum] The id of the folder to edit.
    # @param name [String] The name of the folder.
    # @return [Hash]
    def edit(folder_id, name)
      response = @client.put("folders/#{folder_id}", name: name)
      verify response,
             forbidden: 'Cannot rename a system folder.',
             not_found: 'Folder does not exist.',
             internal_server_error: 'Server failed to rename the folder.'
    end

    alias_method :rename, :edit

    # Returns the current user's scan folders.
    #
    # @return [Hash] { "folders": [folder Resource] }
    def list
      response = @client.get('folders')
      verify response,
             forbidden: 'You do not have permission to view the folder list.',
             internal_server_error: 'An internal server error occurred.'
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
