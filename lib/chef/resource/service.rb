#
# Author:: AJ Christensen (<aj@hjksolutions.com>)
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

require "chef-utils/dsl/service" unless defined?(ChefUtils::DSL::Service)
require_relative "../resource"
require "shellwords" unless defined?(Shellwords)
require "chef-utils/dist" unless defined?(ChefUtils::Dist)

class Chef
  class Resource
    class Service < Chef::Resource
      include Chef::Platform::ServiceHelpers
      extend Chef::Platform::ServiceHelpers
      unified_mode true

      provides :service, target_mode: true

      description "Use the **service** resource to manage a service."

      default_action :nothing
      allowed_actions :enable, :disable, :start, :stop, :restart, :reload,
        :mask, :unmask

      # this is a poor API please do not re-use this pattern
      property :supports, Hash, default: { restart: nil, reload: nil, status: nil },
               description: "A list of properties that controls how #{ChefUtils::Dist::Infra::PRODUCT} is to attempt to manage a service: :restart, :reload, :status. For :restart, the init script or other service provider can use a restart command; if :restart is not specified, the #{ChefUtils::Dist::Infra::CLIENT} attempts to stop and then start a service. For :reload, the init script or other service provider can use a reload command. For :status, the init script or other service provider can use a status command to determine if the service is running; if :status is not specified, the #{ChefUtils::Dist::Infra::CLIENT} attempts to match the service_name against the process table as a regular expression, unless a pattern is specified as a parameter property. Default value: { restart: false, reload: false, status: false } for all platforms (except for the Red Hat platform family, which defaults to { restart: false, reload: false, status: true }.)",
               coerce: proc { |x| x.is_a?(Array) ? x.each_with_object({}) { |i, m| m[i] = true } : x }

      property :service_name, String,
        description: "An optional property to set the service name if it differs from the resource block's name.",
        name_property: true

      # regex for match against ps -ef when !supports[:has_status] && status == nil
      property :pattern, String,
        description: "The pattern to look for in the process table.",
        default_description: "The value provided to 'service_name' or the resource block's name",
        default: lazy { service_name }, desired_state: false

      # command to call to start service
      property :start_command, [ String, nil, FalseClass ],
        description: "The command used to start a service.",
        desired_state: false

      # command to call to stop service
      property :stop_command, [ String, nil, FalseClass ],
        description: "The command used to stop a service.",
        desired_state: false

      # command to call to get status of service
      property :status_command, [ String, nil, FalseClass ],
        description: "The command used to check the run status for a service.",
        desired_state: false

      # command to call to restart service
      property :restart_command, [ String, nil, FalseClass ],
        description: "The command used to restart a service.",
        desired_state: false

      property :reload_command, [ String, nil, FalseClass ],
        description: "The command used to tell a service to reload its configuration.",
        desired_state: false

      # The path to the init script associated with the service. On many
      # distributions this is '/etc/init.d/SERVICE_NAME' by default. In
      # non-standard configurations setting this value will save having to
      # specify overrides for the start_command, stop_command and
      # restart_command properties.
      property :init_command, String,
        description: "The path to the init script that is associated with the service. Use init_command to prevent the need to specify overrides for the start_command, stop_command, and restart_command properties. When this property is not specified, the #{ChefUtils::Dist::Infra::PRODUCT} will use the default init command for the service provider being used.",
        desired_state: false

      # if the service is enabled or not
      property :enabled, [ TrueClass, FalseClass ], skip_docs: true

      # if the service is running or not
      property :running, [ TrueClass, FalseClass ], skip_docs: true

      # if the service is masked or not
      property :masked, [ TrueClass, FalseClass ], skip_docs: true

      # if the service is static or not
      property :static, [ TrueClass, FalseClass ], skip_docs: true

      # if the service is indirect or not
      property :indirect, [ TrueClass, FalseClass ], skip_docs: true

      property :options, [ Array, String ],
        description: "Solaris platform only. Options to pass to the service command. See the svcadm manual for details of possible options.",
        coerce: proc { |x| x.respond_to?(:split) ? x.shellsplit : x }

      # Priority arguments can have two forms:
      #
      # - a simple number, in which the default start runlevels get
      #   that as the start value and stop runlevels get 100 - value.
      #
      # - a hash like { 2 => [:start, 20], 3 => [:stop, 55] }, where
      #   the service will be marked as started with priority 20 in
      #   runlevel 2, stopped in 3 with priority 55 and no symlinks or
      #   similar for other runlevels
      #
      property :priority, [ Integer, String, Hash ],
        description: "Debian platform only. The relative priority of the program for start and shutdown ordering. May be an integer or a Hash. An integer is used to define the start run levels; stop run levels are then 100-integer. A Hash is used to define values for specific run levels. For example, { 2 => [:start, 20], 3 => [:stop, 55] } will set a priority of twenty for run level two and a priority of fifty-five for run level three."

      property :timeout, Integer,
      description: "The amount of time (in seconds) to wait before timing out.",
      default: 900,
      desired_state: false

      property :parameters, Hash,
        description: "Upstart only: A hash of parameters to pass to the service command for use in the service definition."

      property :run_levels, Array,
        description: "RHEL platforms only: Specific run_levels the service will run under."

      property :user, String,
        description: "systemd only: A username to run the service under.",
        introduced: "12.21"
    end
  end
end
