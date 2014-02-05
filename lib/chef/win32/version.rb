#
# Author:: Seth Chisamore (<schisamo@opscode.com>)
# Copyright:: Copyright 2011 Opscode, Inc.
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

require 'chef/win32/api'
require 'chef/win32/api/system'

class Chef
  module ReservedNames::Win32
    class Version
      include Chef::ReservedNames::Win32::API::Macros
      include Chef::ReservedNames::Win32::API::System

      # Ruby implementation of
      # http://msdn.microsoft.com/en-us/library/ms724833(v=vs.85).aspx
      # http://msdn.microsoft.com/en-us/library/ms724358(v=vs.85).aspx

      private

      def self.get_system_metrics(n_index)
        Win32API.new('user32', 'GetSystemMetrics', 'I', 'I').call(n_index)
      end

      public

      WIN_VERSIONS = {
        "Windows 8.1" => {:major => 6, :minor => 3, :callable => lambda{ @product_type == VER_NT_WORKSTATION }},
        "Windows Server 2012 R2" => {:major => 6, :minor => 3, :callable => lambda{ @product_type != VER_NT_WORKSTATION }},
        "Windows 8" => {:major => 6, :minor => 2, :callable => lambda{ @product_type == VER_NT_WORKSTATION }},
        "Windows Server 2012" => {:major => 6, :minor => 2, :callable => lambda{ @product_type != VER_NT_WORKSTATION }},
        "Windows 7" => {:major => 6, :minor => 1, :callable => lambda{ @product_type == VER_NT_WORKSTATION }},
        "Windows Server 2008 R2" => {:major => 6, :minor => 1, :callable => lambda{ @product_type != VER_NT_WORKSTATION }},
        "Windows Server 2008" => {:major => 6, :minor => 0, :callable => lambda{ @product_type != VER_NT_WORKSTATION }},
        "Windows Vista" => {:major => 6, :minor => 0, :callable => lambda{ @product_type == VER_NT_WORKSTATION }},
        "Windows Server 2003 R2" => {:major => 5, :minor => 2, :callable => lambda{ get_system_metrics(SM_SERVERR2) != 0 }},
        "Windows Home Server" => {:major => 5, :minor => 2, :callable => lambda{  (@suite_mask & VER_SUITE_WH_SERVER) == VER_SUITE_WH_SERVER }},
        "Windows Server 2003" => {:major => 5, :minor => 2, :callable => lambda{ get_system_metrics(SM_SERVERR2) == 0 }},
        "Windows XP" => {:major => 5, :minor => 1},
        "Windows 2000" => {:major => 5, :minor => 0}
      }

      # Publicly-readable attributes of the Windows version. See http://msdn.microsoft.com/en-us/library/windows/desktop/ms724833%28v=vs.85%29.aspx
      # for the complete explanation of these fields, but briefly:
      #
      # major version, e.g. "6" for the Windows Vista/2008+ family
      attr_reader :major_version
      # minor version, e.g. "2" for Windows 8
      attr_reader :minor_version
      # build number, e.g "2600"
      attr_reader :build_number
      # service pack major version, e.g. "3" for Service Pack 3
      attr_reader :sp_major_version
      # service pack minor version, e.g. "0"
      attr_reader :sp_minor_version

      def initialize
        @major_version, @minor_version, @build_number = get_version
        ver_info = get_version_ex
        @product_type = ver_info[:w_product_type]
        @suite_mask = ver_info[:w_suite_mask]
        @sp_major_version = ver_info[:w_service_pack_major]
        @sp_minor_version = ver_info[:w_service_pack_minor]

        # Obtain sku information for the purpose of identifying
        # datacenter, cluster, and core skus, the latter 2 only
        # exist in releases after Windows Server 2003
        if ! Chef::Platform::windows_server_2003?
          @sku = get_product_info(@major_version, @minor_version, @sp_major_version, @sp_minor_version)
        else
          # The get_product_info API is not supported on Win2k3,
          # use an alternative to identify datacenter skus
          @sku = get_datacenter_product_info_windows_server_2003(ver_info)
        end
      end

      marketing_names = Array.new

      # General Windows checks
      WIN_VERSIONS.each do |k,v|
        method_name = "#{k.gsub(/\s/, '_').downcase}?"
        define_method(method_name) do
          (@major_version == v[:major]) &&
          (@minor_version == v[:minor]) &&
          (v[:callable] ? v[:callable].call : true)
        end
        marketing_names << [k, method_name]
      end

      define_method(:marketing_name) do
        marketing_names.each do |mn|
          break mn[0] if self.send(mn[1])
        end
      end

      # Server Type checks
      %w{ cluster core datacenter }.each do |m|
        define_method("#{m}?") do
          self.class.constants.any? do |c|
            (self.class.const_get(c) == @sku) &&
              (c.to_s =~ /#{m}/i )
          end
        end
      end

      private

      def get_version
        version = GetVersion()
        major = LOBYTE(LOWORD(version))
        minor = HIBYTE(LOWORD(version))
        build = version < 0x80000000 ? HIWORD(version) : 0
        [major, minor, build]
      end

      def get_version_ex
        lp_version_info = OSVERSIONINFOEX.new
        lp_version_info[:dw_os_version_info_size] = OSVERSIONINFOEX.size
        unless GetVersionExW(lp_version_info)
          Chef::ReservedNames::Win32::Error.raise!
        end
        lp_version_info
      end

      def get_product_info(major, minor, sp_major, sp_minor)
        out = FFI::MemoryPointer.new(:uint32)
        GetProductInfo(major, minor, sp_major, sp_minor, out)
        out.get_uint(0)
      end

      def get_datacenter_product_info_windows_server_2003(ver_info)
        # The intent is not to get the actual sku, just identify
        # Windows Server 2003 datacenter
        sku = (ver_info[:w_suite_mask] & VER_SUITE_DATACENTER) ? PRODUCT_DATACENTER_SERVER : 0
      end

    end
  end
end
