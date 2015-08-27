# The Nessus6 module is used to interact with Nessus version 6 servers.
module Nessus6
  # The Plugin class is for interacting with Nessus6 plugins.
  # https://localhost:8834/api#/resources/plugins
  class Plugin
    include Nessus6::Verification

    public

    def initialize(client)
      @client = client
    end

    # Returns the list of plugin families. This request requires standard user
    # permissions.
    #
    # @return [Hash]
    def families
      response = @client.get('plugins/families')
      verify response,
             forbidden: 'You do not have permission to view plugin families',
             internal_server_error: 'Server failed to retrieve the plugin '\
                                    'family list.'
    end

    # Returns the list of plugins in a family. This request requires standard
    # user permissions.
    #
    # @param plugin_family_id [String] The id of the family to lookup.
    # @return [Hash]
    def family_details(plugin_family_id)
      response = @client.get("plugins/families/#{plugin_family_id}")
      verify response,
             forbidden: 'You do not have permission to view the plugin family',
             not_found: 'Plugin family not found',
             internal_server_error: 'Server failed to retrieve the plugin '\
                                    'family details.'
    end

    # Returns the details for a given plugin. This request requires standard
    # user permissions.
    #
    # @param plugin_id [String] The id of the plugin.
    # @return [Hash]
    def plugin_details(plugin_id)
      response = @client.get("plugins/plugin/#{plugin_id}")
      verify response,
             forbidden: 'You do not have permission to view the plugin',
             not_found: 'Plugin not found',
             internal_server_error: 'Server failed to retrieve the plugin '\
                                    'details.'
    end
  end
end
