# ConflictError represents HTTP 409 Responses
# Indicates that the request could not be processed
# because of a conflict in the request such as an
# edit conflict in the case of multiple updates.
class ConflictError < StandardError
end
