require 'json'
require 'Nessus6/errors/bad_request' # 400
require 'Nessus6/errors/forbidden' # 403
require 'Nessus6/errors/not_found' # 404
require 'Nessus6/errors/conflict' # 409
require 'Nessus6/errors/internal_server_error' # 500
require 'Nessus6/errors/unknown' # Unknown Error Code

module Nessus6
  # The Editor class is for interacting with Nessus6 templates. Templates are
  # used to create scans or policies with predefined parameters.
  # https://localhost:8834/api#/resources/editor
  class Editor
    include Nessus6::Verification

    public

    def initialize(client)
      @client = client
    end

    # Export the given audit file.
    #
    # @param type [String] The type of template to retrieve (scan or policy).
    # @param object_id [String, Fixnum] The unique id of the object.
    # @param file_id [String, Fixnum] The id of the file to export.
    # @return [Hash]
    def audits(type, object_id, file_id)
      response = @client.get("editor/#{type}/#{object_id}/audits/#{file_id}")
      verify response,
             forbidden: 'You do not have permission to export the audit file',
             not_found: 'Audit file does not exist',
             internal_server_error: 'Internal server error occurred.'
    end

    # Returns the details for the given template.
    #
    # @param type [String] The type of template to retrieve (scan or policy).
    # @param template_uuid [String] The uuid for the template.
    # @return [Hash] Details for the given template
    def details(type, template_uuid)
      response = @client.get("editor/#{type}/templates/#{template_uuid}")
      verify response,
             forbidden: 'You do not have permission to open the template',
             not_found: 'Template does not exist',
             internal_server_error: 'Internal server error occurred.'
    end

    # Returns the requested object.
    #
    # @param type [String] The type of template to retrieve (scan or policy).
    # @param id [String, Fixnum] The unique id of the object.
    # @return [Hash] The requested object
    def edit(type, id)
      response = @client.get("editor/#{type}/#{id}")
      verify response,
             forbidden: 'You do not have permission to open the object',
             not_found: 'Object does not exist',
             internal_server_error: 'Internal server error occurred.'
    end

    # Returns the template list.
    #
    # @param type [String] The type of template to retrieve (scan or policy).
    # @return [Hash] { "templates": [ template Resource ] }
    def list(type)
      response = @client.get("editor/#{type}/templates")
      verify response,
             forbidden: 'You do not have permission to view the list',
             internal_server_error: 'Internal server error occurred.'
    end

    # Returns the plugin description. This request requires standard user
    # permissions
    #
    # @param policy_id [String, Fixnum] The id of the policy to lookup.
    # @param family_id [String, Fixnum] The id of the family to lookup within
    #   the policy.
    # @param plugin_id [String, Fixnum] The id of the plugin to lookup within
    #   the family.
    # @return [Hash] The plugin output
    def plugin_description(policy_id, family_id, plugin_id)
      response = @client.get("editor/policy/#{policy_id}/families/#{family_id}/plugins/#{plugin_id}")
      verify response,
             internal_server_error: 'Internal server error occurred.'
    end
  end
end
