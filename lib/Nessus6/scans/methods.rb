require 'json'
require 'Nessus6/errors/forbidden' # 403
require 'Nessus6/errors/not_found' # 404
require 'Nessus6/errors/conflict' # 409
require 'Nessus6/errors/internal_server_error' # 500
require 'Nessus6/errors/unknown'

module Nessus6
  # The Scans class is for interacting with Nessus6 scans.
  # https://localhost:8834/api#/resources/scans
  class Scans
    def initialize(client)
      @client = client
    end

    # Copies the given scan. Requires can configure scan permissions
    #
    # @param scan_id [String, Fixnum] The id of the scan to export.
    # @param query_params [Hash] Includes:
    #   :folder_id [String, Fixnum] - The id of the destination folder.
    #   :history [TrueClass, FalseClass, String] - If true, the history for
    #     the scan will be copied
    #   :name [String] - The name of the copied scan
    # @return [Hash]
    def copy(scan_id, query_params = nil)
      if query_params.is_a? Hash
        response = @client.post "scans/#{scan_id}/copy", query_params
      else
        response = @client.post "scans/#{scan_id}/copy"
      end

      verify response,
             not_found: 'Scan does not exist.',
             internal_server_error: 'An error occurred while copying.'
    end

    # Deletes a scan. NOTE: Scans in running, paused or stopping states can not
    # be deleted. This request requires can configure scan permissions
    #
    # @param scan_id [String, Fixnum] The id of the scan to delete.
    # @return [Hash] The scan UUID or throws an error
    def delete(scan_id)
      response = @client.delete "scans/#{scan_id}"
      verify response,
             internal_server_error: 'Failed to delete the scan. This may be ' \
                                    'because the scan is currently running'
    end

    # Deletes historical results from a scan. This request requires can
    # configure scan permissions.
    #
    # @param scan_id [String, Fixnum] The id of the scan.
    # @param query_params [Hash] Includes:
    #   :history_id [String, Fixnum] - The id of the results to delete.
    # @return [Hash] The scan UUID or throws an error
    def delete_history(scan_id, query_params = nil)
      response = @client.delete "scans/#{scan_id}"
      verify response,
             not_found: 'Results were not found.',
             internal_server_error: 'Failed to delete the results.'
    end

    # Launches a scan.
    #
    # @param scan_id [String, Fixnum] The id of the scan to launch.
    # @param alt_targets [Array] If specified, these targets will be scanned
    #   instead of the default. Value can be an array where each index is a
    #   target, or an array with a single index of comma separated targets.
    # @return [Hash] The scan UUID or throws an error
    def launch(scan_id, alt_targets = nil)
      if alt_targets.is_a? Array
        response = @client.post "scans/#{scan_id}/launch",
                                alt_targets: alt_targets
      else
        response = @client.post "scans/#{scan_id}/launch"
      end

      verify response,
             forbidden: 'This scan is disabled.',
             not_found: 'Scan does not exist.',
             internal_server_error: 'Failed to launch scan. This is usually '\
                                    'due to the scan already running.'
    end

    # Returns the scan list.
    #
    # @return [Hash] Returns the scan list.
    def list
      response = @client.get 'scans'
      JSON.parse response.body
    end

    # Pauses a scan.
    #
    # @param scan_id [String, Fixnum] The id of the scan to pause.
    # @return [Hash] The scan UUID or throws an error
    def pause(scan_id)
      response = @client.post "scans/#{scan_id}/pause"
      verify response,
             forbidden: 'This scan is disabled.',
             conflict: 'Scan is not active.'
    end

    # Stops a scan.
    #
    # @param scan_id [String, Fixnum] The id of the scan to stop.
    # @return [Hash] The scan UUID or throws an error
    def stop(scan_id)
      response = @client.post "scans/#{scan_id}/stop"
      verify response,
             not_found: 'Scan does not exist.',
             conflict: 'Scan is not active.'
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
