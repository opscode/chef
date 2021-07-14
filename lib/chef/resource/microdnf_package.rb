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

require 'chef/provider/package'
require 'chef/mixin/which'
require 'chef/mixin/shell_out'

class Chef
  class Resource
    class MicroDnfPackage < Chef::Resource::Package
      extend Chef::Mixin::Which
      extend Chef::Mixin::ShellOut

      unified_mode true
      provides :microdnf_package

      description 'Use the **microdnf_package** resource to install, upgrade, and remove packages with MicroDNF installed. The microdnf_package resource is able to resolve provides data for packages much like DNF can do when it is run from the command line. This allows a variety of options for installing packages, like minimum versions, virtual provides and library names.'
      introduced '14.15'

      allowed_actions :install, :upgrade, :remove, :purge

      # Install a specific arch
      property :arch, [String, Array],
               :description => 'The architecture of the package to be installed or upgraded. This value can also be passed as part of the package name.',
               :coerce => proc { |x| [x].flatten }

      def flush_cache(arg = nil)
        unless arg.nil?
          Chef::Log.warn('the flush_cache property on the microdnf_package provider is not used due to no local cache being implemented.')
        end
        true
      end

      def allow_downgrade(arg = nil)
        unless arg.nil?
          Chef::Log.warn('the allow_downgrade property on the microdnf_package provider is not used, microDNF supports downgrades by default.')
        end
        true
      end
    end
  end
end
