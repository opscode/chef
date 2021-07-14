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

require 'chef/mixin/get_source_from_package'
require 'chef/mixin/shell_out'
require 'chef/provider/package'
require_relative 'microdnf_helper'
require_relative 'microdnf_resource'

class Chef
  class Provider
    class Package
      class MicroDnf < Chef::Provider::Package
        extend Chef::Mixin::ShellOut
        include Chef::Mixin::GetSourceFromPackage

        allow_nils
        use_multipackage_api
        use_package_name_for_source

        provides :micro_dnf_package

        def microdnf_helper
          @microdnf_helper ||= MicroDnfHelper.instance
        end

        def load_current_resource
          @current_resource =
            Chef::Resource::MicroDnfPackage.new(new_resource.name)
          current_resource.package_name(new_resource.package_name)
          current_resource.version(get_current_versions)

          current_resource
        end

        def load_after_resource
          @current_version = []
          @after_resource =
            Chef::Resource::MicroDnfPackage.new(new_resource.name)
          after_resource.package_name(new_resource.package_name)
          after_resource.version(get_current_versions)

          after_resource
        end

        def define_resource_requirements
          requirements.assert(:install, :upgrade, :remove, :purge) do |a|
            a.assertion do
              !new_resource.source ||
                          ::File.exist?(new_resource.source)
            end
            a.failure_message Chef::Exceptions::Package, "Package #{new_resource.package_name} not found: #{new_resource.source}"
            a.whyrun "assuming #{new_resource.source} would have previously been created"
          end

          super
        end

        def candidate_version
          package_name_array.each_with_index.map do |_pkg, i|
            available_version(i).version_with_arch
          end
        end

        def magic_version
          package_name_array.each_with_index.map do |_pkg, i|
            magical_version(i).version_with_arch
          end
        end

        def get_current_versions
          package_name_array.each_with_index.map do |_pkg, i|
            current_version(i).version_with_arch
          end
        end

        def install_package(names, _versions)
          if new_resource.source
            microdnf_helper.microdnf(options, '-y', 'install', new_resource.source)
          else
            resolved_names = names.each_with_index.map do |name, i|
              available_version(i).to_s unless name.nil?
            end
            microdnf_helper.microdnf(options, '-y', 'install', resolved_names)
          end
        end

        # dnf upgrade does not work on uninstalled packaged,
        # while install will upgrade
        alias upgrade_package install_package

        def remove_package(names, _versions)
          # Currently microDNF only supports removing packages via name
          # and not nvra
          resolved_names = names.each_with_index.map do |name, i|
            magical_version(i).name.to_s unless name.nil?
          end
          microdnf_helper.microdnf(options, '-y', 'remove', resolved_names)
        end

        alias purge_package remove_package

        private

        def version_gt?(v1, v2)
          return false if v1.nil? || v2.nil?

          microdnf_helper.compare_versions(v1, v2) == 1
        end

        def version_equals?(v1, v2)
          return false if v1.nil? || v2.nil?

          microdnf_helper.compare_versions(v1, v2) == 0
        end

        def version_compare(v1, v2)
          microdnf_helper.compare_versions(v1, v2)
        end

        def resolve_source_to_version_obj
          shell_out!("rpm -qp --queryformat '%{NAME} %{EPOCH} %{VERSION} %{RELEASE} %{ARCH}\n' #{new_resource.source}").stdout.each_line do |line|
            # this is another case of committing the sin of doing some
            # lightweight mangling of RPM versions in ruby -- but the
            # output of the rpm command does not match what the yum
            # library accepts.
            case line
            when /^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)$/
              return Version.new($1, "#{$2 == '(none)' ? '0' : $2}:#{$3}-#{$4}", $5)
            end
          end
        end

        # @return Array<Version>
        def available_version(index)
          @available_version ||= []

          @available_version[index] ||=
            if new_resource.source
              resolve_source_to_version_obj
            else
              microdnf_helper.package_query(:whatavailable, package_name_array[index], :version => safe_version_array[index], :arch => safe_arch_array[index], :options => options)
            end

          @available_version[index]
        end

        # @return [Array<Version>]
        def magical_version(index)
          @magical_version ||= []
          @magical_version[index] ||=
            if new_resource.source
              microdnf_helper.package_query(:whatinstalled, available_version(index).name, :version => safe_version_array[index], :arch => safe_arch_array[index], :options => options)
            else
              microdnf_helper.package_query(:whatinstalled, package_name_array[index], :version => safe_version_array[index], :arch => safe_arch_array[index], :options => options)
            end
          @magical_version[index]
        end

        def current_version(index)
          @current_version ||= []
          @current_version[index] ||=
            if new_resource.source
              microdnf_helper.package_query(:whatinstalled, available_version(index).name, :arch => safe_arch_array[index], :options => options)
            else
              microdnf_helper.package_query(:whatinstalled, package_name_array[index], :arch =>  safe_arch_array[index], :options => options)
            end
          @current_version[index]
        end

        def safe_version_array
          if new_resource.version.is_a?(Array)
            new_resource.version
          elsif new_resource.version.nil?
            package_name_array.map { nil }
          else
            [new_resource.version]
          end
        end

        def safe_arch_array
          if new_resource.arch.is_a?(Array)
            new_resource.arch
          elsif new_resource.arch.nil?
            package_name_array.map { nil }
          else
            [new_resource.arch]
          end
        end
      end
    end
  end
end
