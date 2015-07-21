module Nessus6
  class Editor
    def initialize(client)
      @client = client
    end

    def audits(type, object_id, file_id)
      @client.get("editor/#{type}/#{object_id}/audits/#{file_id}")
    end
  end
end
