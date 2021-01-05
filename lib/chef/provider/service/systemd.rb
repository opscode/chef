#
# Author:: Stephen Haynes (<sh@nomitor.com>)
# Author:: Davide Cavalca (<dcavalca@fb.com>)
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

require_relative "../../resource/service"
require_relative "simple"
require_relative "../../mixin/which"
require "shellwords" unless defined?(Shellwords)

class Chef::Provider::Service::Systemd < Chef::Provider::Service::Simple

  include Chef::Mixin::Which

  provides :service, os: "linux", target_mode: true do |node|
    systemd?
  end

  attr_accessor :status_check_success

  def self.supports?(resource, action)
    service_script_exist?(:systemd, resource.service_name)
  end

  def load_current_resource
    @current_resource = Chef::Resource::Service.new(new_resource.name)
    current_resource.service_name(new_resource.service_name)
    @status_check_success = true

    if new_resource.status_command
      logger.trace("#{new_resource} you have specified a status command, running..")

      unless shell_out(new_resource.status_command).error?
        current_resource.running(true)
      else
        @status_check_success = false
        current_resource.running(false)
        current_resource.enabled(false)
        current_resource.masked(false)
	current_resource.static(false)
        current_resource.indirect(false)
      end
    else
      current_resource.running(is_active?)
    end

    e, m, s, i = get_enabled_masked_static_indirect
    current_resource.enabled(e)
    current_resource.masked(m)
    current_resource.static(s)
    current_resource.indirect(i)
    current_resource
  end

  # systemd supports user services just fine
  def user_services_requirements; end

  def define_resource_requirements
    shared_resource_requirements
    requirements.assert(:all_actions) do |a|
      a.assertion { status_check_success }
      # We won't stop in any case, but in whyrun warn and tell what we're doing.
      a.whyrun ["Failed to determine status of #{new_resource}, using command #{new_resource.status_command}.",
        "Assuming service would have been installed and is disabled"]
    end
  end

  def get_systemctl_options_args
    if new_resource.user
      raise NotImplementedError, "#{new_resource} does not support the user property on a target_mode host (yet)" if Chef::Config.target_mode?

      uid = Etc.getpwnam(new_resource.user).uid
      options = {
        environment: {
          "DBUS_SESSION_BUS_ADDRESS" => "unix:path=/run/user/#{uid}/bus",
        },
        user: new_resource.user,
      }
      args = "--user"
    else
      options = {}
      args = "--system"
    end

    [options, args]
  end

  def start_service
    if current_resource.running
      logger.trace("#{new_resource} already running, not starting")
    else
      if new_resource.start_command
        super
      else
        options, args = get_systemctl_options_args
        shell_out!(systemctl_path, args, "start", new_resource.service_name, default_env: false, **options)
      end
    end
  end

  def stop_service
    unless current_resource.running
      logger.trace("#{new_resource} not running, not stopping")
    else
      if new_resource.stop_command
        super
      else
        options, args = get_systemctl_options_args
        shell_out!(systemctl_path, args, "stop", new_resource.service_name, default_env: false, **options)
      end
    end
  end

  def restart_service
    if new_resource.restart_command
      super
    else
      options, args = get_systemctl_options_args
      shell_out!(systemctl_path, args, "restart", new_resource.service_name, default_env: false, **options)
    end
  end

  def reload_service
    if new_resource.reload_command
      super
    else
      if current_resource.running
        options, args = get_systemctl_options_args
        shell_out!(systemctl_path, args, "reload", new_resource.service_name, default_env: false, **options)
      else
        start_service
      end
    end
  end

  def enable_service
    if current_resource.masked
      logger.trace("#{new_resource} cannot be enabled: it is masked")
      return
    end
    if current_resource.static
      logger.trace("#{new_resource} cannot be enabled: it is static")
      return
    end
    if current_resource.indirect
      logger.trace("#{new_resource} cannot be enabled: it is indirect")
      return
    end

    options, args = get_systemctl_options_args
    shell_out!(systemctl_path, args, "enable", new_resource.service_name, **options)
  end

  def disable_service
    if current_resource.masked
      logger.trace("#{new_resource} cannot be disabled: it is masked")
      return
    end
    if current_resource.static
      logger.trace("#{new_resource} cannot be disabled: it is static")
      return
    end
    if current_resource.indirect
      logger.trace("#{new_resource} cannot be disabled: it is indirect")
      return
    end

    options, args = get_systemctl_options_args
    shell_out!(systemctl_path, args, "disable", new_resource.service_name, **options)
  end

  def mask_service
    options, args = get_systemctl_options_args
    shell_out!(systemctl_path, args, "mask", new_resource.service_name, **options)
  end

  def unmask_service
    options, args = get_systemctl_options_args
    shell_out!(systemctl_path, args, "unmask", new_resource.service_name, **options)
  end

  def is_active?
    options, args = get_systemctl_options_args
    shell_out!(systemctl_path, args, "is-active", new_resource.service_name, "--quiet", **options)
  end

  def get_enabled_masked_static_indirect
    options, args = get_systemctl_options_args
    s = shell_out(systemctl_path, args, "is-enabled", new_resource.service_name, **options)
    output = s.stdout
    [s.exitstatus == 0, output.include?("masked"), output.include?("static"), output.include?("indirect")]
  end

  private

  def systemctl_path
    if @systemctl_path.nil?
      @systemctl_path = which("systemctl")
    end
    @systemctl_path
  end

end
