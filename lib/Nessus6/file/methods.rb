require 'json'
require 'hurley'
require 'Nessus6/errors/internal_server_error'
require 'Nessus6/errors/unknown'

module Nessus6
  # The File class is for uploading files to Nessus.
  # https://localhost:8834/api#/resources/file
  class File
    def initialize(client)
      @client = client
    end

    # Uploads a file. This request requires read only user permissions.
    #
    # @param file_path [String] Path to the file to upload
    # @param file_type [String] MIME type. E.g. 'text/plain'
    # @return [Hash] Returns a :fileuploaded string.
    def upload(file_path, file_type, encrypted = 0)
      response = @client.post('file/upload',
                              file: Hurley::UploadIO.new(file_path, file_type),
                              no_enc: encrypted)
      verify response,
             internal_server_error: 'File failed to upload'
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
