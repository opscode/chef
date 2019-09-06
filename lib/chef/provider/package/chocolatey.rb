#
# Copyright:: Copyright 2015-2016, Chef Software, Inc.
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
require_relative "../../resource/chocolatey_package"
require_relative "../../mixin/powershell_out"

class Chef
  class Provider
    class Package
      class Chocolatey < Chef::Provider::Package
        include Chef::Mixin::PowershellOut

        provides :chocolatey_package

        # Declare that our arguments should be arrays
        use_multipackage_api

        PATHFINDING_POWERSHELL_COMMAND = "[System.Environment]::GetEnvironmentVariable('ChocolateyInstall', 'MACHINE')".freeze
        CHOCO_MISSING_MSG = <<~EOS.freeze
          Could not locate your Chocolatey install. To install chocolatey, we recommend
          the 'chocolatey' cookbook (https://github.com/chocolatey/chocolatey-cookbook).
          If Chocolatey is installed, ensure that the 'ChocolateyInstall' environment
          variable is correctly set. You can verify this with the PowerShell command
          '#{PATHFINDING_POWERSHELL_COMMAND}'.
        EOS

        # Responsible for building the current_resource.
        #
        # @return [Chef::Resource::ChocolateyPackage] the current_resource
        def load_current_resource
          @current_resource = Chef::Resource::ChocolateyPackage.new(new_resource.name)
          current_resource.package_name(new_resource.package_name)
          current_resource.version(build_current_versions)
          current_resource
        end

        def define_resource_requirements
          super

          # The check that Chocolatey is installed is in #choco_exe.

          # Chocolatey source property points to an alternate feed
          # and not a package specific alternate source like other providers
          # so we want to assert candidates exist for the alternate source
          requirements.assert(:upgrade, :install) do |a|
            a.assertion { candidates_exist_for_all_uninstalled? }
            a.failure_message(Chef::Exceptions::Package, "No candidate version available for #{packages_missing_candidates.join(", ")}")
            a.whyrun("Assuming a repository that offers #{packages_missing_candidates.join(", ")} would have been configured")
          end
        end

        # Lazy initializer for candidate_version.  A nil value means that there is no candidate
        # version and the package is not installable (generally an error).
        #
        # @return [Array] list of candidate_versions indexed same as new_resource.package_name/version
        def candidate_version
          @candidate_version ||= build_candidate_versions
        end

        # Install multiple packages via choco.exe
        #
        # @param names [Array<String>] array of package names to install
        # @param versions [Array<String>] array of versions to install
        def install_package(names, versions)
          name_versions_to_install = desired_name_versions.select { |n, v| lowercase_names(names).include?(n) }

          name_nil_versions = name_versions_to_install.select { |n, v| v.nil? }
          name_has_versions = name_versions_to_install.reject { |n, v| v.nil? }

          # choco does not support installing multiple packages with version pins
          name_has_versions.each do |name, version|
            choco_command("install -y --version", version, cmd_args, name)
          end

          # but we can do all the ones without version pins at once
          unless name_nil_versions.empty?
            cmd_names = name_nil_versions.keys
            choco_command("install -y", cmd_args, *cmd_names)
          end
        end

        # Upgrade multiple packages via choco.exe
        #
        # @param names [Array<String>] array of package names to install
        # @param versions [Array<String>] array of versions to install
        def upgrade_package(names, versions)
          name_versions_to_install = desired_name_versions.select { |n, v| lowercase_names(names).include?(n) }

          name_nil_versions = name_versions_to_install.select { |n, v| v.nil? }
          name_has_versions = name_versions_to_install.reject { |n, v| v.nil? }

          # choco does not support installing multiple packages with version pins
          name_has_versions.each do |name, version|
            choco_command("upgrade -y --version", version, cmd_args, name)
          end

          # but we can do all the ones without version pins at once
          unless name_nil_versions.empty?
            cmd_names = name_nil_versions.keys
            choco_command("upgrade -y", cmd_args, *cmd_names)
          end
        end

        # Remove multiple packages via choco.exe
        #
        # @param names [Array<String>] array of package names to install
        # @param versions [Array<String>] array of versions to install
        def remove_package(names, versions)
          choco_command("uninstall -y", cmd_args(include_source: false), *names)
        end

        # Choco does not have dpkg's distinction between purge and remove
        alias purge_package remove_package

        # Override the superclass check.  The semantics for our new_resource.source is not files to
        # install from, but like the rubygem provider's sources which are more like repos.
        def check_resource_semantics!; end

        private

        def version_compare(v1, v2)
          if v1 == "latest" || v2 == "latest"
            return 0
          end

          gem_v1 = Gem::Version.new(v1)
          gem_v2 = Gem::Version.new(v2)

          gem_v1 <=> gem_v2
        end

        # Magic to find where chocolatey is installed in the system, and to
        # return the full path of choco.exe
        #
        # @return [String] full path of choco.exe
        def choco_exe
          @choco_exe ||= begin
              # if this check is in #define_resource_requirements, it won't get
              # run before choco.exe gets called from #load_current_resource.
              exe_path = ::File.join(choco_install_path.to_s, "bin", "choco.exe")
              raise Chef::Exceptions::MissingLibrary, CHOCO_MISSING_MSG unless ::File.exist?(exe_path)

              exe_path
            end
        end

        # lets us mock out an incorrect value for testing.
        def choco_install_path
          @choco_install_path ||= powershell_out!(
            PATHFINDING_POWERSHELL_COMMAND
          ).stdout.chomp
        end

        # Helper to dispatch a choco command through shell_out using the timeout
        # set on the new resource, with nice command formatting.
        #
        # @param args [String] variable number of string arguments
        # @return [Mixlib::ShellOut] object returned from shell_out!
        def choco_command(*args)
          shell_out!(args_to_string(choco_exe, *args), returns: new_resource.returns)
        end

        # Use the available_packages Hash helper to create an array suitable for
        # using in candidate_version
        #
        # @return [Array] list of candidate_version, same index as new_resource.package_name/version
        def build_candidate_versions
          new_resource.package_name.map do |package_name|
            available_packages[package_name.downcase]
          end
        end

        # Use the installed_packages Hash helper to create an array suitable for
        # using in current_resource.version
        #
        # @return [Array] list of candidate_version, same index as new_resource.package_name/version
        def build_current_versions
          new_resource.package_name.map do |package_name|
            installed_packages[package_name.downcase]
          end
        end

        # Helper to construct Hash of names-to-versions, requested on the new_resource.
        # If new_resource.version is nil, then all values will be nil.
        #
        # @return [Hash] Mapping of requested names to versions
        def desired_name_versions
          desired_versions = new_resource.version || new_resource.package_name.map { nil }
          Hash[*lowercase_names(new_resource.package_name).zip(desired_versions).flatten]
        end

        # Helper to construct optional args out of new_resource
        #
        # @param include_source [Boolean] should the source parameter be added
        # @return [String] options from new_resource or empty string
        def cmd_args(include_source: true)
          cmd_args = [ new_resource.options ]
          cmd_args.push( "-source #{new_resource.source}" ) if new_resource.source && include_source
          args_to_string(*cmd_args)
        end

        # Helper to nicely convert variable string args into a single command line.  It
        # will compact nulls or empty strings and join arguments with single spaces, without
        # introducing any double-spaces for missing args.
        #
        # @param args [String] variable number of string arguments
        # @return [String] nicely concatenated string or empty string
        def args_to_string(*args)
          args.reject { |i| i.nil? || i == "" }.join(" ")
        end

        # Available packages in chocolatey as a Hash of names mapped to versions
        # If pinning a package to a specific version, filter out all non matching versions
        # (names are downcased for case-insensitive matching)
        #
        # @return [Hash] name-to-version mapping of available packages
        def available_packages
          return @available_packages if @available_packages

          @available_packages = {}
          package_name_array.each do |pkg|
            available_versions =
              begin
                cmd = [ "list -r -a -e #{pkg}" ]
                cmd.push( "-source #{new_resource.source}" ) if new_resource.source
                cmd.push( new_resource.options ) if new_resource.options

                raw = parse_list_output(*cmd)
                raw.keys.each_with_object({}) do |name, available|
                  available[name] = desired_name_versions[name] || raw[name]
                end
              end
            @available_packages.merge! available_versions
          end
          @available_packages
        end

        # Installed packages in chocolatey as a Hash of names mapped to versions
        # (names are downcased for case-insensitive matching)
        #
        # @return [Hash] name-to-version mapping of installed packages
        def installed_packages
          @installed_packages ||= Hash[*parse_list_output("list -l -r").flatten]
          @installed_packages
        end

        # Helper to convert choco.exe list output to a Hash
        # (names are downcased for case-insenstive matching)
        #
        # @param cmd [String] command to run
        # @return [Hash] list output converted to ruby Hash
        def parse_list_output(*args)
          hash = {}
          choco_command(*args).stdout.each_line do |line|
            next if line.start_with?("Chocolatey v")

            name, version = line.split("|")
            hash[name.downcase] = version&.chomp
          end
          hash
        end

        # Helper to downcase all names in an array
        #
        # @param names [Array] original mixed case names
        # @return [Array] same names in lower case
        def lowercase_names(names)
          names.map(&:downcase)
        end
      end
    end
  end
end
