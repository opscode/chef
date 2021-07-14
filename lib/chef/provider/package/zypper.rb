#
# Authors:: Adam Jacob (<adam@chef.io>)
#           Ionuț Arțăriși (<iartarisi@suse.cz>)
# Copyright:: Copyright (c) Chef Software Inc.
# Copyright:: 2013-2016, SUSE Linux GmbH
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
require_relative "../../resource/zypper_package"

class Chef
  class Provider
    class Package
      class Zypper < Chef::Provider::Package
        use_multipackage_api
        allow_nils

        provides :package, platform_family: "suse"
        provides :zypper_package

        def load_current_resource
          @current_resource = Chef::Resource::ZypperPackage.new(new_resource.name)
          current_resource.package_name(new_resource.package_name)
          current_resource.version(get_current_versions)
          current_resource
        end

        def install_package(name, version)
          zypper_package("install", global_options, *options, "--auto-agree-with-licenses", allow_downgrade, name, version)
        end

        def upgrade_package(name, version)
          # `zypper install` upgrades packages, we rely on the idempotency checks to get action :install behavior
          install_package(name, version)
        end

        def remove_package(name, version)
          zypper_package("remove", global_options, *options, name, version)
        end

        def purge_package(name, version)
          zypper_package("remove", global_options, *options, "--clean-deps", name, version)
        end

        def lock_package(name, version)
          zypper_package("addlock", global_options, *options, name, version)
        end

        def unlock_package(name, version)
          zypper_package("removelock", global_options, *options, name, version)
        end

        private

        def get_current_versions
          package_name_array.each_with_index.map { |pkg, i| installed_version(i) }
        end

        def candidate_version
          @candidate_version ||= package_name_array.each_with_index.map { |pkg, i| available_version(i) }
        end

        def resolve_current_version(package_name)
          latest_version = current_version = nil
          is_installed = false
          logger.trace("#{new_resource} checking zypper")
          status = shell_out!("zypper", "--non-interactive", "info", package_name)
          status.stdout.each_line do |line|
            case line
            when /^Version *: (.+) *$/
              latest_version = $1.strip
              logger.trace("#{new_resource} version #{latest_version}")
            when /^Installed *: Yes.*$/ # http://rubular.com/r/9StcAMjOn6
              is_installed = true
              logger.trace("#{new_resource} is installed")
            when /^Status *: out-of-date \(version (.+) installed\) *$/
              current_version = $1.strip
              logger.trace("#{new_resource} out of date version #{current_version}")
            end
          end
          current_version ||= latest_version if is_installed
          current_version
        end

        def resolve_available_version(package_name, new_version)
          search_string = new_version.nil? ? package_name : "#{package_name}=#{new_version}"
          so = shell_out("zypper", "--non-interactive", "search", "-s", "--provides", "--match-exact", "--type=package", search_string)
          so.stdout.each_line do |line|
            if md = line.match(/^(\S*)\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(.*)$/)
              (status, name, type, version, arch, repo) = [ md[1], md[2], md[3], md[4], md[5], md[6] ]
              next if version == "Version" # header

              # sometimes even though we request a specific version in the search string above and have match exact, we wind up
              # with other versions in the output, particularly getting the installed version when downgrading.
              if new_version
                next unless version == new_version || version.start_with?("#{new_version}-")
              end

              return version
            end
          end
          nil
        end

        def available_version(index)
          @available_version ||= []
          @available_version[index] ||= resolve_available_version(package_name_array[index], safe_version_array[index])
          @available_version[index]
        end

        def installed_version(index)
          @installed_version ||= []
          @installed_version[index] ||= resolve_current_version(package_name_array[index])
          @installed_version[index]
        end

        def zip(names, versions)
          names.zip(versions).map do |n, v|
            (v.nil? || v.empty?) ? n : "#{n}=#{v}"
          end.compact
        end

        def zypper_version
          @zypper_version ||=
            `zypper -V 2>&1`.scan(/\d+/).join(".").to_f
        end

        def zypper_package(command, global_options, *options, names, versions)
          zipped_names = zip(names, versions)
          if zypper_version < 1.0
            shell_out!("zypper", global_options, gpg_checks, command, *options, "-y", names)
          else
            shell_out!("zypper", global_options, "--non-interactive", gpg_checks, command, *options, zipped_names)
          end
        end

        def gpg_checks
          "--no-gpg-checks" unless new_resource.gpg_check
        end

        def allow_downgrade
          "--oldpackage" if new_resource.allow_downgrade
        end

        def global_options
          new_resource.global_options
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
              locked = shell_out!("zypper", "locks")
              locked.stdout.each_line.map do |line|
                line.split("|").shift(2).last.strip
              end
            end
        end

        def safe_version_array
          if new_resource.version.is_a?(Array)
            new_resource.version
          elsif new_resource.version.nil?
            package_name_array.map { nil }
          else
            [ new_resource.version ]
          end
        end

      end
    end
  end
end
