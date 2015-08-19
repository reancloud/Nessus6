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
    include Nessus6::Verification

    public

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
  end
end
