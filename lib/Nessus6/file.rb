module Nessus6
  # The File class is for uploading files to Nessus.
  # https://localhost:8834/api#/resources/file
  class File
    include Nessus6::Verification

    public

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
  end
end
