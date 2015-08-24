module Nessus6
  # The Plugin class is for interacting with Nessus6 plugins.
  # https://localhost:8834/api#/resources/plugins
  class PluginRule
    include Nessus6::Verification

    public

    def initialize(client)
      @client = client
    end

    # Returns the list of plugin families. This request requires standard user
    # permissions.
    #
    # @return [Hash]
    def list
      response = @client.get('plugins-rules')
      verify response,
             forbidden: 'You do not have permission to view plugin rules list',
             internal_server_error: 'Server failed to create the group'
    end

    # Returns the list of plugins in a family. This request requires standard
    # user permissions.
    #
    # @param plugin_id [String, Fixnum] The id of the plugin to apply the rule
    #   to.
    # @param type [String] The new severity to apply (recast_critical,
    #   recast_high, recast_medium, recast_low, recast_info, exclude).
    # @param host [String] The host to apply the rule to.
    # @param date [String] The expiration date of the plugin rule
    # @return [Hash]
    def create(plugin_id, type, host, date = nil)
      if date.nil?
        response = @client.post('plugin-rules', plugin_id: plugin_id,
                                                type: type,
                                                host: host)
      else
        response = @client.post('plugin-rules', plugin_id: plugin_id,
                                                type: type,
                                                host: host,
                                                date: date)
      end
      verify response,
             bad_request: 'An argument is missing or invalid',
             forbidden: 'You do not have permission to create this plugin rule',
             not_found: 'Plugin family not found',
             internal_server_error: 'Server failed to create the plugin rule'
    end

    # Deletes a plugin rule. This request requires read only user permissions.
    #
    # @param rule_id [String, Fixnum] The id of the rule to delete.
    # @return [Hash]
    def delete(rule_id)
      response = @client.delete("plugin-rules/#{rule_id}")
      verify response,
             forbidden: 'You do not have permission to delete the rule.',
             not_found: 'Rule with that ID could not be found',
             internal_server_error: 'Server failed to create the group'
    end

    # Modify a plugin rule for the current user. This request requires read only
    # user permissions.
    #
    # @param rule_id [String, Fixnum] The id of the rule to delete.
    # @param plugin_id [String, Fixnum] The id of the plugin to apply the rule
    #   to.
    # @param type [String] The new severity to apply (recast_critical,
    #   recast_high, recast_medium, recast_low, recast_info, exclude).
    # @param host [String] The host to apply the rule to.
    # @param date [String] The expiration date of the plugin rule
    # @return [Hash]
    def edit(rule_id, plugin_id, type, host, date = nil)
      if date.nil?
        response = @client.put("plugin-rules/#{rule_id}", plugin_id: plugin_id,
                                                          type: type,
                                                          host: host)
      else
        response = @client.put("plugin-rules/#{rule_id}", plugin_id: plugin_id,
                                                          type: type,
                                                          host: host,
                                                          date: date)
      end
      verify response,
             forbidden: 'You do not have permission to delete the rule.',
             not_found: 'Rule with that ID could not be found',
             internal_server_error: 'Server failed to create the group'
    end
  end
end
