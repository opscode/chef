#
# Author:: Sölvi Páll Ásgeirsson (<solvip@gmail.com>)
# Author:: Richard Lavey (richard.lavey@calastone.com)
# Author:: Tim Smith (tsmith@chef.io)
#
# Copyright:: 2014-2017, Sölvi Páll Ásgeirsson.
# Copyright:: Copyright (c) Chef Software Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require_relative "../resource"
require_relative "../util/path_helper"

class Chef
  class Resource
    class WindowsShare < Chef::Resource
      unified_mode true

      provides :windows_share

      description "Use the **windows_share** resource to create, modify and remove Windows shares."
      introduced "14.7"
      examples <<~DOC
      **Create a share**:

      ```ruby
      windows_share 'foo' do
        action :create
        path 'C:\\foo'
        full_users ['DOMAIN_A\\some_user', 'DOMAIN_B\\some_other_user']
        read_users ['DOMAIN_C\\Domain users']
      end
      ```

      **Delete a share**:

      ```ruby
      windows_share 'foo' do
        action :delete
      end
      ```
      DOC

      # Specifies a name for the SMB share. The name may be composed of any valid file name characters, but must be less than 80 characters long. The names pipe and mailslot are reserved for use by the computer.
      property :share_name, String,
        description: "An optional property to set the share name if it differs from the resource block's name.",
        name_property: true

      # Specifies the path of the location of the folder to share. The path must be fully qualified. Relative paths or paths that contain wildcard characters are not permitted.
      property :path, String,
        description: "The path of the folder to share. Required when creating. If the share already exists on a different path then it is deleted and re-created.",
        coerce: proc { |p| p.tr("/", "\\") || p }

      # Specifies an optional description of the SMB share. A description of the share is displayed by running the Get-SmbShare cmdlet. The description may not contain more than 256 characters.
      property :description, String,
        description: "The description to be applied to the share.",
        default: ""

      # Specifies which accounts are granted full permission to access the share. Use a comma-separated list to specify multiple accounts. An account may not be specified more than once in the FullAccess, ChangeAccess, or ReadAccess parameter lists, but may be specified once in the FullAccess, ChangeAccess, or ReadAccess parameter list and once in the NoAccess parameter list.
      property :full_users, Array,
        description: "The users that should have 'Full control' permissions on the share in domain\\username format.",
        default: [], coerce: proc { |u| add_hostname(u).sort }

      # Specifies which users are granted modify permission to access the share
      property :change_users, Array,
        description: "The users that should have 'modify' permission on the share in domain\\username format.",
        default: [], coerce: proc { |u| add_hostname(u).sort }

      # Specifies which users are granted read permission to access the share. Multiple users can be specified by supplying a comma-separated list.
      property :read_users, Array,
        description: "The users that should have 'read' permission on the share in domain\\username format.",
        default: [], coerce: proc { |u| add_hostname(u).sort }

      # Specifies the lifetime of the new SMB share. A temporary share does not persist beyond the next restart of the computer. By default, new SMB shares are persistent, and non-temporary.
      property :temporary, [TrueClass, FalseClass],
        description: "The lifetime of the new SMB share. A temporary share does not persist beyond the next restart of the computer.",
        default: false

      # Specifies the scope name of the share.
      property :scope_name, String,
        description: "The scope name of the share.",
        default: "*"

      # Specifies the continuous availability time-out for the share.
      property :ca_timeout, Integer,
        description: "The continuous availability time-out for the share.",
        default: 0

      # Indicates that the share is continuously available.
      property :continuously_available, [TrueClass, FalseClass],
        description: "Indicates that the share is continuously available.",
        default: false

      # Specifies the caching mode of the offline files for the SMB share.
      # property :caching_mode, String, equal_to: %w(None Manual Documents Programs BranchCache)

      # Specifies the maximum number of concurrently connected users that the new SMB share may accommodate. If this parameter is set to zero (0), then the number of users is unlimited.
      property :concurrent_user_limit, Integer,
        description: "The maximum number of concurrently connected users the share can accommodate.",
        default: 0

      # Indicates that the share is encrypted.
      property :encrypt_data, [TrueClass, FalseClass],
        description: "Indicates that the share is encrypted.",
        default: false

      # Specifies which files and folders in the SMB share are visible to users. AccessBased: SMB does not the display the files and folders for a share to a user unless that user has rights to access the files and folders. By default, access-based enumeration is disabled for new SMB shares. Unrestricted: SMB displays files and folders to a user even when the user does not have permission to access the items.
      # property :folder_enumeration_mode, String, equal_to: %(AccessBased Unrestricted)

      load_current_value do |new_resource|
        # this command selects individual objects because EncryptData & CachingMode have underlying
        # types that get converted to their Integer values by ConvertTo-Json & we need to make sure
        # those get written out as strings
        share_state_cmd = "Get-SmbShare -Name '#{new_resource.share_name}' | Select-Object Name,Path, Description, Temporary, CATimeout, ContinuouslyAvailable, ConcurrentUserLimit, EncryptData"

        Chef::Log.debug("Running '#{share_state_cmd}' to determine share state'")
        ps_results = powershell_exec(share_state_cmd)

        # detect a failure without raising and then set current_resource to nil
        if ps_results.error?
          Chef::Log.debug("Error fetching share state: #{ps_results.errors}")
          current_value_does_not_exist!
        end

        Chef::Log.debug("The Get-SmbShare results were #{ps_results.result}")
        results = ps_results.result

        path results["Path"]
        description results["Description"]
        temporary results["Temporary"]
        ca_timeout results["CATimeout"]
        continuously_available results["ContinuouslyAvailable"]
        # caching_mode results['CachingMode']
        concurrent_user_limit results["ConcurrentUserLimit"]
        encrypt_data results["EncryptData"]
        # folder_enumeration_mode results['FolderEnumerationMode']

        perm_state_cmd = %{Get-SmbShareAccess -Name "#{new_resource.share_name}" | Select-Object AccountName,AccessControlType,AccessRight}

        Chef::Log.debug("Running '#{perm_state_cmd}' to determine share permissions state'")
        ps_perm_results = powershell_exec(perm_state_cmd)

        # we raise here instead of warning like above because we'd only get here if the above Get-SmbShare
        # command was successful and that continuing would leave us with 1/2 known state
        raise "Could not determine #{new_resource.share_name} share permissions by running '#{perm_state_cmd}'" if ps_perm_results.error?

        Chef::Log.debug("The Get-SmbShareAccess results were #{ps_perm_results.result}")

        f_users, c_users, r_users = parse_permissions(ps_perm_results.result)

        full_users f_users
        change_users c_users
        read_users r_users
      end

      # given the string output of Get-SmbShareAccess parse out
      # arrays of full access users, change users, and read only users
      def parse_permissions(json_results)
        json_results = [json_results] unless json_results.is_a?(Array) # single result is not an array

        f_users = []
        c_users = []
        r_users = []

        json_results.each do |perm|
          next unless perm["AccessControlType"] == 0 # allow

          case perm["AccessRight"]
          when 0 then f_users << perm["AccountName"] # 0 full control
          when 1 then c_users << perm["AccountName"] # 1 == change
          when 2 then r_users << perm["AccountName"] # 2 == read
          end
        end
        [f_users, c_users, r_users]
      end

      action :create, description: "Create or modify a Windows share." do
        new_resource_users

        # we do this here instead of requiring the property because :delete doesn't need path set
        raise "No path property set" unless new_resource.path

        unless current_resource.nil? || users_changed? || different_path?
          logger.debug("Skipping update of #{new_resource}: has not changed any of the specified properties.")
        else
          converge_by("create #{new_resource}") do
            # you can't actually change the path so you have to delete the old share first
            if different_path?
              Chef::Log.debug("The path has changed so we will delete and recreate share")
              delete_share
              create_share
            elsif current_resource.nil?
              # powershell cmdlet for create is different than updates
              Chef::Log.debug("The current resource is nil so we will create a new share")
              create_share
            else
              Chef::Log.debug("The current resource was not nil so we will update an existing share")
              update_share
            end

            # creating the share does not set permissions so we need to update
            update_permissions
          end
        end
      end

      action :delete, description: "Delete an existing Windows share." do
        if current_resource.nil?
          Chef::Log.debug("#{new_resource.share_name} does not exist - nothing to do")
        else
          converge_by("delete #{new_resource.share_name}") do
            delete_share
          end
        end
      end

      action_class do
        private

        def different_path?
          return false if current_resource.nil? # going from nil to something isn't different for our concerns
          return false if current_resource.path == Chef::Util::PathHelper.cleanpath(new_resource.path)

          true
        end

        def delete_share
          delete_command = "Remove-SmbShare -Name '#{new_resource.share_name}' -Force"

          Chef::Log.debug("Running '#{delete_command}' to remove the share")
          powershell_exec!(delete_command)
        end

        def update_share
          update_command = "Set-SmbShare -Name '#{new_resource.share_name}' -Description '#{new_resource.description}'  -ConcurrentUserLimit #{new_resource.concurrent_user_limit} -CATimeout #{new_resource.ca_timeout} -EncryptData:#{bool_string(new_resource.encrypt_data)} -ContinuouslyAvailable:#{bool_string(new_resource.continuously_available)} -Force"
          update_command << " -ScopeName #{new_resource.scope_name}" unless new_resource.scope_name == "*" # passing * causes the command to fail
          update_command << " -Temporary:#{bool_string(new_resource.temporary)}" if new_resource.temporary # only set true

          Chef::Log.debug("Running '#{update_command}' to update the share")
          powershell_exec!(update_command)
        end

        def create_share
          raise "#{new_resource.path} is missing or not a directory. Shares cannot be created if the path doesn't first exist." unless ::File.directory? new_resource.path

          share_cmd = "New-SmbShare -Name '#{new_resource.share_name}' -Path '#{Chef::Util::PathHelper.cleanpath(new_resource.path)}' -Description '#{new_resource.description}' -ConcurrentUserLimit #{new_resource.concurrent_user_limit} -CATimeout #{new_resource.ca_timeout} -EncryptData:#{bool_string(new_resource.encrypt_data)} -ContinuouslyAvailable:#{bool_string(new_resource.continuously_available)}"
          share_cmd << " -ScopeName #{new_resource.scope_name}" unless new_resource.scope_name == "*" # passing * causes the command to fail
          share_cmd << " -Temporary:#{bool_string(new_resource.temporary)}" if new_resource.temporary # only set true

          Chef::Log.debug("Running '#{share_cmd}' to create the share")
          powershell_exec!(share_cmd)

          # New-SmbShare adds the "Everyone" user with read access no matter what so we need to remove it
          # before we add our permissions
          revoke_user_permissions(["Everyone"])
        end

        # determine what users in the current state don't exist in the desired state
        # users/groups will have their permissions updated with the same command that
        # sets it, but removes must be performed with Revoke-SmbShareAccess
        def users_to_revoke
          @users_to_revoke ||= if current_resource.nil?
                                 []
                               else # if it exists then calculate the current to new resource diffs
                                 (current_resource.full_users + current_resource.change_users + current_resource.read_users) - (new_resource.full_users + new_resource.change_users + new_resource.read_users)
                               end
        end

        # update existing permissions on a share
        def update_permissions
          # revoke any users that had something, but now has nothing
          revoke_user_permissions(users_to_revoke) unless users_to_revoke.empty?

          # set permissions for each of the permission types
          %w{read change full}.each do |perm_type|
            # set permissions for a brand new share OR
            # update permissions if the current state and desired state differ
            next unless permissions_need_update?(perm_type)

            grant_command = "Grant-SmbShareAccess -Name '#{new_resource.share_name}' -AccountName \"#{new_resource.send("#{perm_type}_users").join('","')}\" -Force -AccessRight #{perm_type}"

            Chef::Log.debug("Running '#{grant_command}' to update the share permissions")
            powershell_exec!(grant_command)
          end
        end

        # determine if permissions need to be updated.
        # Brand new share with no permissions defined: no
        # Brand new share with permissions defined: yes
        # Existing share with differing permissions: yes
        #
        # @param [String] type the permissions type (Full, Read, or Change)
        def permissions_need_update?(type)
          property_name = "#{type}_users"

          # brand new share, but nothing to set
          return false if current_resource.nil? && instance_variable_get("@#{property_name}").empty?

          # brand new share with new permissions to set
          return true if current_resource.nil? && !instance_variable_get("@#{property_name}").empty?

          # there's a difference between the current and desired state
          return true unless (instance_variable_get("@#{property_name}") - current_resource.send(property_name)).empty?

          # anything else
          false
        end

        # revoke user permissions from a share
        # @param [Array] users
        def revoke_user_permissions(users)
          revoke_command = "Revoke-SmbShareAccess -Name '#{new_resource.share_name}' -AccountName \"#{users.join('","')}\" -Force"
          Chef::Log.debug("Running '#{revoke_command}' to revoke share permissions")
          powershell_exec!(revoke_command)
        end

        # convert True/False into "$True" & "$False"
        def bool_string(bool)
          # bool ? 1 : 0
          bool ? "$true" : "$false"
        end

        # Grant-SmbShareAccess sets only one permission to one user so we need to remove from the lower permission access
        # For change_users remove common full_users from it
        # For read_users remove common full_users as well as change_users
        def new_resource_users
          @full_users = new_resource.full_users
          @change_users = new_resource.change_users - new_resource.full_users
          @read_users = new_resource.read_users - (new_resource.full_users + new_resource.change_users)
        end

        # Compare the full_users, change_users and read_users from current_resource and new_resource
        # @returns boolean True/False
        def users_changed?
          !(current_resource.full_users == @full_users && current_resource.change_users == @change_users && current_resource.read_users == @read_users)
        end
      end

      # local names are returned from Get-SmbShareAccess in the full format MACHINE\\NAME
      # but users of this resource would simply say NAME so we need to add hostname for comparison
      # If hostname is not present in front of user then add hostname from node

      # @input_params [Array]
      # @returns [Array]
      def add_hostname(users)
        users.map do |user|
          user = "#{node["hostname"]}\\" + user unless user.include?("\\")
          user.downcase
        end
      end
    end
  end
end
