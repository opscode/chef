#
# Copyright:: 2011-2018, Joshua Timberman
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
require "chef-utils/dist" unless defined?(ChefUtils::Dist)
require "corefoundation"
autoload :Plist, "plist"

class Chef
  class Resource
    class MacosUserDefaults < Chef::Resource
      unified_mode true

      # align with apple's marketing department
      provides(:macos_userdefaults) { true }
      provides(:mac_os_x_userdefaults) { true }

      description "Use the **macos_userdefaults** resource to manage the macOS user defaults system. The properties of this resource are passed to the defaults command, and the parameters follow the convention of that command. See the defaults(1) man page for details on how the tool works."
      introduced "14.0"
      examples <<~DOC
        **Specify a global domain value**

        ```ruby
        macos_userdefaults 'Full keyboard access to all controls' do
          key 'AppleKeyboardUIMode'
          value 2
        end
        ```

        **Setting a value on a specific domain**

        ```ruby
        macos_userdefaults 'Enable macOS firewall' do
          domain '/Library/Preferences/com.apple.alf'
          key 'globalstate'
          value 1
        end
        ```

        **Specifying the type of a key to skip automatic type detection**

        ```ruby
        macos_userdefaults 'Finder expanded save dialogs' do
          key 'NSNavPanelExpandedStateForSaveMode'
          value 'TRUE'
          type 'bool'
        end
        ```
      DOC

      property :domain, String,
        description: "The domain that the user defaults belong to.",
        default: "NSGlobalDomain",
        default_description: "NSGlobalDomain: the global domain.",
        desired_state: false

      property :global, [TrueClass, FalseClass],
        description: "Determines whether or not the domain is global.",
        deprecated: true,
        default: false,
        desired_state: false

      property :key, String,
        description: "The preference key.",
        required: true

      property :host, [String, Symbol],
        description: "Set either :current or a hostname to set the user default at the host level.",
        desired_state: false,
        introduced: "16.3"

      property :value, [Integer, Float, String, TrueClass, FalseClass, Hash, Array],
        description: "The value of the key. Note: With the `type` property set to `bool`, `String` forms of Boolean true/false values that Apple accepts in the defaults command will be coerced: 0/1, 'TRUE'/'FALSE,' 'true'/false', 'YES'/'NO', or 'yes'/'no'.",
        required: [:write],
        coerce: proc { |v| v.is_a?(Hash) ? v.transform_keys(&:to_s) : v } # make sure keys are all strings for comparison

      property :type, String,
        description: "The value type of the preference key.",
        deprecated: true,
        equal_to: %w{bool string int float array dict},
        desired_state: false

      property :user, [String, Symbol],
        description: "The system user that the default will be applied to.",
        desired_state: false

      property :sudo, [TrueClass, FalseClass],
        description: "Set to true if the setting you wish to modify requires privileged access. This requires passwordless sudo for the `/usr/bin/defaults` command to be setup for the user running #{ChefUtils::Dist::Infra::PRODUCT}.",
        default: false,
        desired_state: false

      load_current_value do |new_resource|
        state = read_preferences(new_resource)

        # TODO: error handling
        unless state
          Chef::Log.debug "#{new_resource.key} could not be found in the domain"
          current_value_does_not_exist!
        end

        value state
      end

      action :write, description: "Write the value to the specified domain/key." do
        converge_if_changed do
          write_preferences(new_resource)
        end
      end

      action :delete, description: "Delete a key from a domain." do
        # if it's not there there's nothing to remove
        return unless current_resource

        # TODO: implement in CF and use here
      end

      action_class do
        CF_MAPPING = {
          current_user: CF::Preferences::CURRENT_USER,
          all_users: CF::Preferences::ALL_USERS,
          current_host: CF::Preferences::CURRENT_HOST,
          all_hosts: CF::Preferences::ALL_HOSTS,
          current: CF::Preferences::CURRENT_HOST # TODO: deprecation warning for this option
        }

        def read_preferences(new_resource)
          CF::Preferences.get(new_resource.key, new_resource.domain, mapped_user, mapped_host)
        end

        def write_preferences(new_resource)
          CF::Preferences.set(new_resource.key, new_resource.value, new_resource.domain, mapped_user, mapped_host)
        end

        def mapped_user
          CF_MAPPING[valid_user.to_sym] || valid_user.to_s
        end

        def mapped_host
          CF_MAPPING[valid_host.to_sym] || valid_host.to_s
        end

        def valid_user
          # TODO: check backward compatibility and defaults util convention
          new_resource.user || :current_user
        end

        def valid_host
          # TODO: check backward compatibility and defaults util convention
          new_resource.host || :all_hosts
        end
      end
    end
  end
end
