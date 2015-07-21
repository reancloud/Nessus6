require 'json'

module Nessus6
  # The Editor class is for interacting with Nessus6 templates
  class Editor
    def initialize(client)
      @client = client
    end

    def audits(type, object_id, file_id)
      response = @client.get("editor/#{type}/#{object_id}/audits/#{file_id}")
      verify response
    end

    def details(type, template_uuid)
      response = @client.get("editor/#{type}/templates/#{template_uuid}")
      verify response
    end

    def edit(type, id)
      response = @client.get("editor/#{type}/#{id}")
      verify response
    end

    def list(type)
      response = @client.get("editor/#{type}/templates")
      verify response
    end

    def plugin_description(policy_id, family_id, plugin_id)
      response = @client.get("editor/policy/#{policy_id}/families/#{family_id}/plugins/#{plugin_id}")
      verify response
    end

    private

    def verify(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 403
        fail 'Not authorized to perform this action'
      end
    end
  end
end
