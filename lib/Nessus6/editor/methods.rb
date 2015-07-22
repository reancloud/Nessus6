require 'json'
require 'Nessus6/errors/forbidden'
require 'Nessus6/errors/not_found'
require 'Nessus6/errors/unknown'

module Nessus6
  # The Editor class is for interacting with Nessus6 templates
  class Editor
    def initialize(client)
      @client = client
    end

    def audits(type, object_id, file_id)
      response = @client.get("editor/#{type}/#{object_id}/audits/#{file_id}")
      verify_audits response
    end

    def details(type, template_uuid)
      response = @client.get("editor/#{type}/templates/#{template_uuid}")
      verify_details response
    end

    def edit(type, id)
      response = @client.get("editor/#{type}/#{id}")
      verify_edit response
    end

    def list(type)
      response = @client.get("editor/#{type}/templates")
      verify response
    end

    def plugin_description(policy_id, family_id, plugin_id)
      response = @client.get("editor/policy/#{policy_id}/families/#{family_id}/plugins/#{plugin_id}")
      verify_plugin_description response
    end

    private

    def verify_audits(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 403
        fail ForbiddenError,
             'You do not have permission to export the audit file'
      when 404
        fail NotFoundError, 'Audit file does not exist'
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end

    def verify_details(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 403
        fail ForbiddenError,
             'You do not have permission to open the template'
      when 404
        fail NotFoundError, 'Template does not exist'
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
        fail ForbiddenError,
             'You do not have permission to open the object'
      when 404
        fail NotFoundError, 'Object does not exist'
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
             'You do not have permission to view the list'
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end

    def verify_plugin_description(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end
  end
end
