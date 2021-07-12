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

require_relative "../package"
require_relative "deb"
require_relative "../../resource/apt_package"

class Chef
  class Provider
    class Package
      class Apt < Chef::Provider::Package
        include Chef::Provider::Package::Deb
        use_multipackage_api

        provides :package, platform_family: "debian", target_mode: true
        provides :apt_package, target_mode: true

        def initialize(new_resource, run_context)
          super
        end

        def load_current_resource
          @current_resource = Chef::Resource::AptPackage.new(new_resource.name)
          current_resource.package_name(new_resource.package_name)
          current_resource.version(get_current_versions)
          current_resource
        end

        def define_resource_requirements
          super

          requirements.assert(:all_actions) do |a|
            a.assertion { !new_resource.source }
            a.failure_message(Chef::Exceptions::Package, "apt package provider cannot handle source property. Use dpkg provider instead")
          end
        end

        def package_data
          @package_data ||= Hash.new do |hash, key|
            hash[key] = package_data_for(key)
          end
        end

        def get_current_versions
          package_name_array.map do |package_name|
            package_data[package_name][:current_version]
          end
        end

        def get_candidate_versions
          package_name_array.map do |package_name|
            package_data[package_name][:candidate_version]
          end
        end

        def candidate_version
          @candidate_version ||= get_candidate_versions
        end

        def packages_all_locked?(names, versions)
          names.all? { |n| locked_packages.include? n }
        end

        def packages_all_unlocked?(names, versions)
          names.all? { |n| !locked_packages.include? n }
        end

        def locked_packages
          @locked_packages ||=
            begin
              locked = shell_out!("apt-mark", "showhold")
              locked.stdout.each_line.map(&:strip)
            end
        end

        def install_package(name, version)
          package_name = name.zip(version).map do |n, v|
            package_data[n][:virtual] ? n : "#{n}=#{v}"
          end
          dgrade = "--allow-downgrades" if supports_allow_downgrade? && allow_downgrade
          run_noninteractive("apt-get", "-q", "-y", dgrade, config_file_options, default_release_options, options, "install", package_name)
        end

        def upgrade_package(name, version)
          install_package(name, version)
        end

        def remove_package(name, version)
          package_name = name.map do |n|
            versions = resolve_package_versions(n)
            unless versions[0].nil?
              package_data[n][:virtual] ? resolve_virtual_package_name(n) : n
            end
          end
          run_noninteractive("apt-get", "-q", "-y", options, "remove", package_name)
        end

        def purge_package(name, version)
          package_name = name.map do |n|
            versions = resolve_package_versions(n)
            unless versions[0].nil?
              package_data[n][:virtual] ? resolve_virtual_package_name(n) : n
            end
          end
          run_noninteractive("apt-get", "-q", "-y", options, "purge", package_name)
        end

        def lock_package(name, version)
          run_noninteractive("apt-mark", options, "hold", name)
        end

        def unlock_package(name, version)
          run_noninteractive("apt-mark", options, "unhold", name)
        end

        private

        # @return [String] version of apt-get which is installed
        def apt_version
          @apt_version ||= shell_out("apt-get --version").stdout.match(/^apt (\S+)/)[1]
        end

        # @return [Boolean] if apt-get supports --allow-downgrades
        def supports_allow_downgrade?
          return @supports_allow_downgrade unless @supports_allow_downgrade.nil?

          @supports_allow_downgrade = ( version_compare(apt_version, "1.1.0") >= 0 )
        end

        # compare 2 versions to each other to see which is newer.
        # this differs from the standard package method because we
        # need to be able to parse debian version strings which contain
        # tildes which Gem cannot properly parse
        #
        # @return [Integer] 1 if v1 > v2. 0 if they're equal. -1 if v1 < v2
        def version_compare(v1, v2)
          if !shell_out("dpkg", "--compare-versions", v1.to_s, "gt", v2.to_s).error?
            1
          elsif !shell_out("dpkg", "--compare-versions", v1.to_s, "eq", v2.to_s).error?
            0
          else
            -1
          end
        end

        def default_release_options
          # Use apt::Default-Release option only if provider supports it
          if new_resource.respond_to?(:default_release) && new_resource.default_release
            [ "-o", "APT::Default-Release=#{new_resource.default_release}" ]
          end
        end

        def config_file_options
          # If the user has specified config file options previously, respect those.
          return if Array(options).any? { |opt| opt.include?("--force-conf") }

          # It doesn't make sense to install packages in a scenario that can
          # result in a prompt. Have users decide up-front whether they want to
          # forcibly overwrite the config file, otherwise preserve it.
          if new_resource.overwrite_config_files
            [ "-o", "Dpkg::Options::=--force-confnew" ]
          else
            [ "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold" ]
          end
        end

        def resolve_package_versions(pkg)
          current_version = nil
          candidate_version = nil
          all_versions = []
          run_noninteractive("apt-cache", default_release_options, "policy", pkg).stdout.each_line do |line|
            case line
            when /^\s{2}Installed: (.+)$/
              current_version = ( $1 != "(none)" ) ? $1 : nil
              logger.trace("#{new_resource} installed version for #{pkg} is #{$1}")
            when /^\s{2}Candidate: (.+)$/
              candidate_version = ( $1 != "(none)" ) ? $1 : nil
              logger.trace("#{new_resource} candidate version for #{pkg} is #{$1}")
            when /\s+(?:\*\*\* )?(\S+) \d+/
              all_versions << $1
            end
          end
          # This is a bit ugly... really this whole provider needs
          # to be rewritten to use target_version_array and friends, but
          # for now this gets us moving
          idx = package_name_array.index(pkg)
          chosen_version =
            if idx
              user_ver = new_version_array[idx]
              if user_ver
                if all_versions.include?(user_ver)
                  user_ver
                else
                  logger.debug("User specified a version that's not available")
                  nil
                end
              else
                # user didn't specify a version, use candidate
                candidate_version
              end
            else
              # this probably means we're redirected from a virtual
              # package, so... just go with candidate version
              candidate_version
            end
          [ current_version, chosen_version ]
        end

        def resolve_virtual_package_name(pkg)
          showpkg = run_noninteractive("apt-cache", "showpkg", pkg).stdout
          partitions = showpkg.rpartition(/Reverse Provides: ?#{$/}/)
          return nil if partitions[0] == "" && partitions[1] == "" # not found in output

          set = partitions[2].lines.each_with_object(Set.new) do |line, acc|
            # there may be multiple reverse provides for a single package
            acc.add(line.split[0])
          end
          if set.size > 1
            raise Chef::Exceptions::Package, "#{new_resource.package_name} is a virtual package provided by multiple packages, you must explicitly select one"
          end

          set.to_a.first
        end

        def package_data_for(pkg)
          virtual           = false
          current_version   = nil
          candidate_version = nil

          current_version, candidate_version = resolve_package_versions(pkg)

          if candidate_version.nil?
            newpkg = resolve_virtual_package_name(pkg)

            if newpkg
              virtual = true
              logger.info("#{new_resource} is a virtual package, actually acting on package[#{newpkg}]")
              current_version, candidate_version = resolve_package_versions(newpkg)
            end
          end

          {
            current_version: current_version,
            candidate_version: candidate_version,
            virtual: virtual,
          }
        end

      end
    end
  end
end
