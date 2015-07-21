require 'json'

module Nessus6
  class Users
    def initialize(client)
      @client = client
    end

    def create(credentials, user_perm, user_info = {})
      new_user = {}.tap do |user|
        user[:username] = credentials[:username]
        user[:password] = credentials[:password]
        user[:permissions] = user_perm[:permissions]
        user[:type] = user_perm[:type]
        user[:name] = user_info[:name] if user_info.key?(:name)
        user[:email] = user_info[:email] if user_info.key?(:email)
      end

      response = @client.post('users', new_user)

      verify_create response
    end

    def delete(user_id)
      response = @client.delete("users/#{user_id}")
      verify_delete response
    end

    def edit(user_id, permissions, user_info = {})
      edit_user = {}.tap do |user|
        user[:permissions] = permissions
        user[:name] = user_info[:name] if user_info.key?(:name)
        user[:email] = user_info[:email] if user_info.key?(:email)
      end
      response = @client.post("users/#{user_id}", edit_user)
      verify_edit response
    end

    def get(user_id)
      response = @client.get("users/#{user_id}")
      verify_get response
    end

    def list
      response = @client.get('users')
      verify_list response
    end

    def password(user_id, new_password)
      response = @client.post("users/#{user_id}/chpasswd",
                              password: new_password)
      verify_password response
    end

    def keys(user_id)
      response = @client.get("users/#{user_id}/keys")
      verify_keys response
    end

    private

    def verify_create(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 400
        fail 'Field is invalid'
      when 403
        fail 'You do not have permission to create this user'
      when 409
        fail 'User already exists'
      else
        return false
      end
    end

    def verify_delete(response)
      case response.status_code
      when 200
        return true
      when 403
        fail 'Not authorized to delete users'
      when 404
        fail 'You do not have permission to delete this user'
      when 409
        fail 'Cannot delete your own account'
      when 500
        fail 'Failed to delete the user due to an interal server error'
      else
        return false
      end
    end

    def verify_edit(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 400
        fail 'Field is invalid'
      when 403
        fail 'You do not have permission to edit this user'
      when 404
        fail 'User does not exist'
      when 409
        fail 'Cannot edit your own permissions'
      else
        return false
      end
    end

    def verify_get(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 404
        fail 'User does not exist'
      else
        return false
      end
    end

    def verify_list(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 403
        fail 'You do not have permission to view the list'
      else
        return false
      end
    end

    def verify_password(response)
      case response.status_code
      when 200
        return true
      when 400
        fail 'Password is too short'
      when 403
        fail 'You do not have permission to change the users password'
      when 404
        fail 'User does not exist'
      when 500
        fail 'Server failed to change the password'
      else
        return false
      end
    end

    def verify_keys(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 403
        fail 'You do not have permission to generate API keys'
      when 404
        fail 'User does not exist'
      when 500
        fail 'Server failed to change the keys'
      else
        return false
      end
    end
  end
end
