#
# Author:: Adam Jacob (<adam@chef.io>)
# Copyright:: Copyright (c) Chef Software Inc.
# License:: Apache License, Version 2.0
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

class Chef
  class Resource
    class User < Chef::Resource
      unified_mode true

      description "Use the **user** resource to add users, update existing users, remove users, and to lock/unlock user passwords."

      default_action :create
      allowed_actions :create, :remove, :modify, :manage, :lock, :unlock

      property :username, String,
        description: "An optional property to set the username value if it differs from the resource block's name.",
        name_property: true

      property :comment, String,
        description: "The contents of the user comments field."

      property :home, String,
        description: "The location of the home directory."

      property :salt, String,
        description: "A SALTED-SHA512-PBKDF2 hash.",
        desired_state: false

      property :shell, String,
        description: "The login shell."

      property :password, String,
        description: "The password shadow hash",
        sensitive: true,
        desired_state: false

      property :expire_date, [ String, NilClass ],
        description: "(Linux) The date on which the user account will be disabled. The date is specified in the format YYYY-MM-DD.",
        desired_state: false

      property :inactive, [ Integer, NilClass ],
        description: "(Linux) The number of days after a password expires until the account is permanently disabled. A value of 0 disables the account as soon as the password has expired, and a value of -1 disables the feature.",
        desired_state: false

      property :non_unique, [ TrueClass, FalseClass ],
        description: "Create a duplicate (non-unique) user account.",
        default: false, desired_state: false

      property :manage_home, [ TrueClass, FalseClass ],
        description: "Manage a user's home directory.\nWhen used with the :create action, a user's home directory is created based on HOME_DIR. If the home directory is missing, it is created unless CREATE_HOME in /etc/login.defs is set to no. When created, a skeleton set of files and subdirectories are included within the home directory.\nWhen used with the :modify action, a user's home directory is moved to HOME_DIR. If the home directory is missing, it is created unless CREATE_HOME in /etc/login.defs is set to no. The contents of the user's home directory are moved to the new location.",
        default: false, desired_state: false

      property :force, [ TrueClass, FalseClass ],
        description: "Force the removal of a user. May be used only with the :remove action.",
        default: false, desired_state: false

      property :system, [ TrueClass, FalseClass ],
        description: "Create a system user. This property may be used with useradd as the provider to create a system user which passes the -r flag to useradd.",
        default: false

      property :uid, [ String, Integer, NilClass ], # nil for backwards compat
        description: "The numeric user identifier."

      property :gid, [ String, Integer, NilClass ], # nil for backwards compat
        description: "The numeric group identifier."

      alias_method :group, :gid
    end
  end
end
