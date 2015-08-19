require 'json'
require 'Nessus6/errors/internal_server_error'
require 'Nessus6/errors/forbidden'
require 'Nessus6/errors/bad_request'
require 'Nessus6/errors/not_found'
require 'Nessus6/errors/unknown'

module Nessus6
  # The Editor class is for interacting with Nessus6 templates
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
      verify_create response
    end

    # Deletes a folder. This request requires read-only user permissions.
    #
    # @param folder_id [String, Fixnum] The id of the folder to delete.
    # @return [Hash]
    def delete(folder_id)
      response = @client.delete("folders/#{folder_id}")
      verify_delete response
    end

    # Rename a folder for the current user. This request requires read-only
    # user permissions.
    #
    # @param folder_id [String, Fixnum] The id of the folder to edit.
    # @param name [String] The name of the folder.
    # @return [Hash]
    def edit(folder_id, name)
      response = @client.put("folders/#{folder_id}", name: name)
      verify_edit response
    end

    alias_method :rename, :edit

    # Returns the current user's scan folders.
    #
    # @return [Hash] { "folders": [folder Resource] }
    def list
      response = @client.get('folders')
      verify_list response
    end

    private

    def verify_create(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 400
        fail BadRequestError, 'Folder name is invalid'
      when 403
        fail ForbiddenError, 'You do not have permission to create a folder'
      when 500
        fail InternalServerError, 'Server failed to create the folder'
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end

    def verify_delete(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 403
        fail ForbiddenError, 'Cannot delete a system folder'
      when 404
        fail NotFoundError, 'Folder does not exist'
      when 500
        fail InternalServerError, 'Server failed to delete the folder'
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end

    def verify_edit(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 403
        fail ForbiddenError, 'Cannot rename a system folder'
      when 404
        fail NotFoundError, 'Folder does not exist'
      when 500
        fail InternalServerError, 'Server failed to rename the folder'
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end

    def verify_list(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 403
        fail ForbiddenError,
             'You do not have permission to view the folder list'
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end
  end
end
