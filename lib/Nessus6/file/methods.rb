require 'json'
require 'hurley'
require 'Nessus6/errors/internal_server_error'
require 'Nessus6/errors/unknown'

module Nessus6
  # The Editor class is for interacting with Nessus6 templates
  class File
    def initialize(client)
      @client = client
    end

    def upload(file_path, file_type, encrypted = 0)
      response = @client.post('file/upload',
                              file: Hurley::UploadIO.new(file_path, file_type),
                              no_enc: encrypted)
      verify_upload response
    end

    private

    def verify_upload(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 500
        fail InternalServerError, 'File failed to upload'
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end
  end
end
