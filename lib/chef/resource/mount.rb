#
# Author:: Joshua Timberman (<joshua@chef.io>)
# Author:: Tyler Cloke (<tyler@chef.io>)
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
    class Mount < Chef::Resource
      description "Use the **mount** resource to manage a mounted file system."
      unified_mode true

      provides :mount

      default_action :mount
      allowed_actions :mount, :umount, :unmount, :remount, :enable, :disable

      # this is a poor API please do not re-use this pattern
      property :supports, [Array, Hash],
        description: "Specify a Hash of supported mount features.",
        default: lazy { { remount: false } },
        default_description: "{ remount: false }",
        coerce: proc { |x| x.is_a?(Array) ? x.each_with_object({}) { |i, m| m[i] = true } : x }

      property :password, String,
        description: "Windows only:. Use to specify the password for username.",
        sensitive: true

      property :mount_point, String, name_property: true,
               coerce: proc { |arg| arg.chomp("/") }, # Removed "/" from the end of str, because it was causing idempotency issue.
               description: "The directory (or path) in which the device is to be mounted. Defaults to the name of the resource block if not provided."

      property :device, String, identity: true,
                description: "Required for `:umount` and `:remount` actions (for the purpose of checking the mount command output for presence). The special block device or remote node, a label, or a uuid to be mounted."

      property :device_type, [String, Symbol],
        description: "The type of device: :device, :label, or :uuid",
        coerce: proc { |arg| arg.is_a?(String) ? arg.to_sym : arg },
        default: :device,
        equal_to: RUBY_PLATFORM.match?(/solaris/i) ? %i{ device } : %i{ device label uuid }

      # @todo this should get refactored away: https://github.com/chef/chef/issues/7621
      property :mounted, [TrueClass, FalseClass], default: false, skip_docs: true

      property :fsck_device, String,
        description: "Solaris only: The fsck device.",
        default: "-"

      property :fstype, [String, nil],
        description: "The file system type (fstype) of the device.",
        default: "auto"

      property :options, [Array, String, nil],
        description: "An array or comma separated list of options for the mount.",
        coerce: proc { |arg| mount_options(arg) }, # Please see #mount_options method.
        default: %w{defaults}

      property :dump, [Integer, FalseClass],
        description: "The dump frequency (in days) used while creating a file systems table (fstab) entry.",
        default: 0

      property :pass, [Integer, FalseClass],
        description: "The pass number used by the file system check (fsck) command while creating a file systems table (fstab) entry.",
        default: 2

      property :enabled, [TrueClass, FalseClass],
        description: "Use to specify if a mounted file system is enabled.",
        default: false

      property :username, String,
        description: "Windows only: Use to specify the user name."

      property :domain, String,
        description: "Windows only: Use to specify the domain in which the `username` and `password` are located."

      private

      # Used by the AIX provider to set fstype to nil.
      # @todo use property to make nil a valid value for fstype
      def clear_fstype
        @fstype = nil
      end

      # Returns array of string without leading and trailing whitespace.
      def mount_options(options)
        (options.is_a?(String) ? options.split(",") : options).collect(&:strip)
      end

    end
  end
end
