#
# Author:: Adam Jacob (<adam@opscode.com>)
# Copyright:: Copyright (c) 2008 Opscode, Inc.
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

require 'chef/provider/package'
require 'chef/mixin/command'
require 'chef/resource/package'
require 'chef/mixin/shell_out'


class Chef
  class Provider
    class Package
      class Apt < Chef::Provider::Package

        include Chef::Mixin::ShellOut
        attr_accessor :is_virtual_package

        def load_current_resource
          @current_resource = Chef::Resource::Package.new(@new_resource.name)
          @current_resource.package_name(@new_resource.package_name)
          check_package_state(@new_resource.package_name)
          @current_resource
        end

        def default_release_options
          # Use apt::Default-Release option only if provider was explicitly defined
          "-o APT::Default-Release=#{@new_resource.default_release}" if @new_resource.provider && @new_resource.default_release
        end

        def check_package_state(package)
          Chef::Log.debug("#{@new_resource} checking package status for #{package}")
          if package.is_a?(Array)
            final_installed_version = []
            final_candidate_version = []
            final_installed = []
            final_virtual = []
          end
          installed = virtual = false
          installed_version = candidate_version = nil

          [package].flatten.each do |pkg|
            installed = virtual = false
            installed_version = candidate_version = nil
            shell_out!("apt-cache#{expand_options(default_release_options)} policy #{pkg}").stdout.each_line do |line|
              case line
              when /^\s{2}Installed: (.+)$/
                installed_version = $1
                if installed_version == '(none)'
                  Chef::Log.debug("#{@new_resource} current version is nil")
                  installed_version = nil
                else
                  Chef::Log.debug("#{@new_resource} current version is #{installed_version}")
                  installed = true
                end
              when /^\s{2}Candidate: (.+)$/
                candidate_version = $1
                if candidate_version == '(none)'
                  # This may not be an appropriate assumption, but it shouldn't break anything that already worked -- btm
                  virtual = true
                  showpkg = shell_out!("apt-cache showpkg #{package}").stdout
                  providers = Hash.new
                  showpkg.rpartition(/Reverse Provides:? #{$/}/)[2].each_line do |line|
                    provider, version = line.split
                    providers[provider] = version
                  end
                  # Check if the package providing this virtual package is installed
                  num_providers = providers.length
                  raise Chef::Exceptions::Package, "#{@new_resource.package_name} has no candidate in the apt-cache" if num_providers == 0
                  # apt will only install a virtual package if there is a single providing package
                  raise Chef::Exceptions::Package, "#{@new_resource.package_name} is a virtual package provided by #{num_providers} packages, you must explicitly select one to install" if num_providers > 1
                  # Check if the package providing this virtual package is installed
                  Chef::Log.info("#{@new_resource} is a virtual package, actually acting on package[#{providers.keys.first}]")
                  installed = check_package_state(providers.keys.first)
                else
                  Chef::Log.debug("#{@new_resource} candidate version is #{$1}")
                end
              end
            end
            if package.is_a?(Array)
              final_installed_version << installed_version
              final_candidate_version << candidate_version
              final_installed << installed
              final_virtual << virtual
            else
              final_installed_version = installed_version
              final_candidate_version = candidate_version
              final_installed = installed
              final_virtual = virtual
            end
          end
          @candidate_version = final_candidate_version
          @current_resource.version(final_installed_version)
          @is_virtual_package = final_virtual

          return final_installed.is_a?(Array) ? final_installed.any? : final_installed
        end

        def install_package(name, version)
          if name.is_a?(Array)
            index = 0
            package_name = name.zip(version).map do |x, y|
              namestr = nil
              if @is_virtual_package[index]
                namestr = x
              else
                namestr = "#{x}=#{y}"
              end
              index += 1
              namestr
            end.join(' ')
          else
            package_name = "#{name}=#{version}"
            package_name = name if @is_virtual_package
          end
          run_command_with_systems_locale(
            :command => "apt-get -q -y#{expand_options(default_release_options)}#{expand_options(@new_resource.options)} install #{package_name}",
            :environment => {
              "DEBIAN_FRONTEND" => "noninteractive"
            }
          )
        end

        def upgrade_package(name, version)
          install_package(name, version)
        end

        def remove_package(name, version)
          if name.is_a?(Array)
            package_name = name.join(' ')
          else
            package_name = name
          end
          run_command_with_systems_locale(
            :command => "apt-get -q -y#{expand_options(@new_resource.options)} remove #{package_name}",
            :environment => {
              "DEBIAN_FRONTEND" => "noninteractive"
            }
          )
        end

        def purge_package(name, version)
          if name.is_a?(Array)
            package_name = name.join(' ')
          else
            package_name = "#{name}"
          end
          run_command_with_systems_locale(
            :command => "apt-get -q -y#{expand_options(@new_resource.options)} purge #{package_name}",
            :environment => {
              "DEBIAN_FRONTEND" => "noninteractive"
            }
          )
        end

        def preseed_package(preseed_file)
          Chef::Log.info("#{@new_resource} pre-seeding package installation instructions")
          run_command_with_systems_locale(
            :command => "debconf-set-selections #{preseed_file}",
            :environment => {
              "DEBIAN_FRONTEND" => "noninteractive"
            }
          )
        end

        def reconfig_package(name, version)
          if name.is_a?(Array)
            package_name = name.join(' ')
          else
            package_name = "#{name}"
          end
          Chef::Log.info("#{@new_resource} reconfiguring")
          run_command_with_systems_locale(
            :command => "dpkg-reconfigure #{package_name}",
            :environment => {
              "DEBIAN_FRONTEND" => "noninteractive"
            }
          )
        end

      end
    end
  end
end
