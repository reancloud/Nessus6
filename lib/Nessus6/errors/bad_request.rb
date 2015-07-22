# BadRequestError represents HTTP 400 Responses
# The server cannot or will not process the request
# due to something that is perceived to be a client
# error (e.g. malformed request syntax, invalid request
# message framing, or deceptive request routing)
class BadRequestError < StandardError
end
