#
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
require_relative "../../resource/yum_package"
require_relative "../../mixin/which"
require_relative "../../mixin/shell_out"
require_relative "../../mixin/get_source_from_package"
require_relative "yum/python_helper"
require_relative "yum/version"
# the stubs in the YumCache class are still an external API
require_relative "yum/yum_cache"

class Chef
  class Provider
    class Package
      class Yum < Chef::Provider::Package
        extend Chef::Mixin::Which
        extend Chef::Mixin::ShellOut
        include Chef::Mixin::GetSourceFromPackage

        allow_nils
        use_multipackage_api
        use_package_name_for_source
        use_magic_version

        provides :package, platform_family: "fedora_derived"

        provides :yum_package

        #
        # Most of the magic in this class happens in the python helper script.  The ruby side of this
        # provider knows only enough to translate Chef-style new_resource name+package+version into
        # a request to the python side.  The python side is then responsible for knowing everything
        # about RPMs and what is installed and what is available.  The ruby side of this class should
        # remain a lightweight translation layer to translate Chef requests into RPC requests to
        # python.  This class knows nothing about how to compare RPM versions, and does not maintain
        # any cached state of installed/available versions and should be kept that way.
        #
        def python_helper
          @python_helper ||= PythonHelper.instance
        end

        def load_current_resource
          flushcache if new_resource.flush_cache[:before]

          @current_resource = Chef::Resource::YumPackage.new(new_resource.name)
          current_resource.package_name(new_resource.package_name)
          current_resource.version(get_current_versions)

          current_resource
        end

        def load_after_resource
          # force the installed version array to repopulate
          @current_version = []
          @after_resource = Chef::Resource::DnfPackage.new(new_resource.name)
          after_resource.package_name(new_resource.package_name)
          after_resource.version(get_current_versions)

          after_resource
        end

        def define_resource_requirements
          requirements.assert(:install, :upgrade, :remove, :purge) do |a|
            a.assertion { !new_resource.source || ::File.exist?(new_resource.source) }
            a.failure_message Chef::Exceptions::Package, "Package #{new_resource.package_name} not found: #{new_resource.source}"
            a.whyrun "assuming #{new_resource.source} would have previously been created"
          end

          super
        end

        def candidate_version
          package_name_array.each_with_index.map do |pkg, i|
            available_version(i).version_with_arch
          end
        end

        def magic_version
          package_name_array.each_with_index.map do |pkg, i|
            magical_version(i).version_with_arch
          end
        end

        def get_current_versions
          package_name_array.each_with_index.map do |pkg, i|
            current_version(i).version_with_arch
          end
        end

        def install_package(names, versions)
          method = nil
          methods = []
          names.each_with_index do |n, i|
            next if n.nil?

            av = available_version(i)
            name = av.name # resolve the name via the available/candidate version
            iv = python_helper.package_query(:whatinstalled, av.name_with_arch, options: options)

            method = "install"

            # If this is a package like the kernel that can be installed multiple times, we'll skip over this logic
            if new_resource.allow_downgrade && version_gt?(iv.version_with_arch, av.version_with_arch) && !python_helper.install_only_packages(name)
              # We allow downgrading only in the event of single-package
              # rules where the user explicitly allowed it
              method = "downgrade"
            end

            methods << method
          end

          # We could split this up into two commands if we wanted to, but
          # for now, just don't support this.
          if methods.uniq.length > 1
            raise Chef::Exceptions::Package, "Multipackage rule has a mix of upgrade and downgrade packages. Cannot proceed."
          end

          if new_resource.source
            yum(options, "-y", method, new_resource.source)
          else
            resolved_names = names.each_with_index.map { |name, i| available_version(i).to_s unless name.nil? }
            yum(options, "-y", method, resolved_names)
          end
          flushcache
        end

        # yum upgrade does not work on uninstalled packaged, while install will upgrade
        alias upgrade_package install_package

        def remove_package(names, versions)
          resolved_names = names.each_with_index.map { |name, i| magical_version(i).to_s unless name.nil? }
          yum(options, "-y", "remove", resolved_names)
          flushcache
        end

        alias purge_package remove_package

        action :flush_cache do
          flushcache
        end

        # NB: the yum_package provider manages individual single packages, please do not submit issues or PRs to try to add wildcard
        # support to lock / unlock.  The best solution is to write an execute resource which does a not_if `yum versionlock | grep '^pattern`` kind of approach
        def lock_package(names, versions)
          yum("-d0", "-e0", "-y", options, "versionlock", "add", resolved_package_lock_names(names))
        end

        # NB: the yum_package provider manages individual single packages, please do not submit issues or PRs to try to add wildcard
        # support to lock / unlock.  The best solution is to write an execute resource which does a only_if `yum versionlock | grep '^pattern`` kind of approach
        def unlock_package(names, versions)
          # yum versionlock delete on rhel6 needs the glob nonsense in the following command
          yum("-d0", "-e0", "-y", options, "versionlock", "delete", resolved_package_lock_names(names).map { |n| "*:#{n}-*" })
        end

        private

        # this will resolve things like `/usr/bin/perl` or virtual packages like `mysql` -- it will not work (well? at all?) with globs that match multiple packages
        def resolved_package_lock_names(names)
          names.each_with_index.map do |name, i|
            unless name.nil?
              if magical_version(i).version.nil?
                available_version(i).name
              else
                magical_version(i).name
              end
            end
          end
        end

        def locked_packages
          @locked_packages ||=
            begin
              locked = yum("versionlock", "list")
              locked.stdout.each_line.map do |line|
                line.sub(/-[^-]*-[^-]*$/, "").split(":").last.strip
              end
            end
        end

        def packages_all_locked?(names, versions)
          resolved_package_lock_names(names).all? { |n| locked_packages.include? n }
        end

        def packages_all_unlocked?(names, versions)
          !resolved_package_lock_names(names).any? { |n| locked_packages.include? n }
        end

        def version_gt?(v1, v2)
          return false if v1.nil? || v2.nil?

          python_helper.compare_versions(v1, v2) == 1
        end

        def version_equals?(v1, v2)
          return false if v1.nil? || v2.nil?

          python_helper.compare_versions(v1, v2) == 0
        end

        def version_compare(v1, v2)
          return false if v1.nil? || v2.nil?

          python_helper.compare_versions(v1, v2)
        end

        def resolve_source_to_version_obj
          shell_out!("rpm -qp --queryformat '%{NAME} %{EPOCH} %{VERSION} %{RELEASE} %{ARCH}\n' #{new_resource.source}").stdout.each_line do |line|
            # this is another case of committing the sin of doing some lightweight mangling of RPM versions in ruby -- but the output of the rpm command
            # does not match what the yum library accepts.
            case line
              when /^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)$/
                return Version.new($1, "#{$2 == "(none)" ? "0" : $2}:#{$3}-#{$4}", $5)
            end
          end
        end

        # @return Array<Version>
        def available_version(index)
          @available_version ||= []

          @available_version[index] ||= if new_resource.source
                                          resolve_source_to_version_obj
                                        else
                                          python_helper.package_query(:whatavailable, package_name_array[index], version: safe_version_array[index], arch: safe_arch_array[index], options: options)
                                        end

          @available_version[index]
        end

        def magical_version(index)
          @magical_version ||= []
          @magical_version[index] ||= if new_resource.source
                                        python_helper.package_query(:whatinstalled, available_version(index).name, version: safe_version_array[index], arch: safe_arch_array[index], options: options)
                                      else
                                        python_helper.package_query(:whatinstalled, package_name_array[index], version: safe_version_array[index], arch: safe_arch_array[index], options: options)
                                      end
          @magical_version[index]
        end

        # @return Array<Version>
        def current_version(index)
          @current_version ||= []
          @current_version[index] ||= if new_resource.source
                                        python_helper.package_query(:whatinstalled, available_version(index).name, arch: safe_arch_array[index], options: options)
                                      else
                                        python_helper.package_query(:whatinstalled, package_name_array[index], arch: safe_arch_array[index], options: options)
                                      end
          @current_version[index]
        end

        # cache flushing is accomplished by simply restarting the python helper.  this produces a roughly
        # 15% hit to the runtime of installing/removing/upgrading packages.  correctly using multipackage
        # array installs (and the multipackage cookbook) can produce 600% improvements in runtime.
        def flushcache
          python_helper.restart
        end

        def yum_binary
          @yum_binary ||=
            begin
              yum_binary = new_resource.yum_binary if new_resource.is_a?(Chef::Resource::YumPackage)
              yum_binary ||= ::File.exist?("/usr/bin/yum-deprecated") ? "yum-deprecated" : "yum"
            end
        end

        def yum(*args)
          shell_out!(yum_binary, *args)
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

        def safe_arch_array
          if new_resource.arch.is_a?(Array)
            new_resource.arch
          elsif new_resource.arch.nil?
            package_name_array.map { nil }
          else
            [ new_resource.arch ]
          end
        end

      end
    end
  end
end
