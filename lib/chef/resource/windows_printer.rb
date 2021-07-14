#
# Author:: Doug Ireton (<doug@1strategy.com>)
# Author:: Tim Smith (<tsmith@chef.io>)
# Copyright:: 2012-2018, Nordstrom, Inc.
# Copyright:: Chef Software, Inc.
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
# See here for more info:
# http://msdn.microsoft.com/en-us/library/windows/desktop/aa394492(v=vs.85).aspx

require_relative "../resource"

class Chef
  class Resource
    # @todo
    # 2. Fail with a warning if the port can't be found and create_port is false
    # 3. Fail with helpful messaging if the printer driver can't be installed
    class WindowsPrinter < Chef::Resource
      unified_mode true

      autoload :Resolv, "resolv"

      provides(:windows_printer) { true }

      description "Use the **windows_printer** resource to setup Windows printers. This resource will automatically install the driver specified in the `driver_name` property and will automatically create a printer port using either the `ipv4_address` property or the `port_name` property."
      introduced "14.0"
      examples <<~DOC
      **Create a printer**:

      ```ruby
      windows_printer 'HP LaserJet 5th Floor' do
        driver_name 'HP LaserJet 4100 Series PCL6'
        ipv4_address '10.4.64.38'
      end
      ```

      **Delete a printer**:

      Note: this doesn't delete the associated printer port. See windows_printer_port above for how to delete the port.

      ```ruby
      windows_printer 'HP LaserJet 5th Floor' do
        action :delete
      end
      ```

      **Create a printer port and a printer that uses that port (new in 17.3)**

      ```ruby
      windows_printer_port '10.4.64.39' do
        port_name 'My awesome printer port'
        snmp_enabled true
        port_protocol 2
      end

      windows_printer 'HP LaserJet 5th Floor' do
        driver_name 'HP LaserJet 4100 Series PCL6'
        port_name 'My awesome printer port'
        ipv4_address '10.4.64.38'
        create_port false
      end
      ```
      DOC

      property :device_id, String,
        description: "An optional property to set the printer queue name if it differs from the resource block's name. Example: `HP LJ 5200 in fifth floor copy room`.",
        name_property: true

      property :comment, String,
        description: "Optional descriptor for the printer queue."

      property :default, [TrueClass, FalseClass],
        description: "Determines whether or not this should be the system's default printer.",
        default: false

      property :driver_name, String,
        description: "The exact name of printer driver installed on the system.",
        required: [:create]

      property :location, String,
        description: "Printer location, such as `Fifth floor copy room`."

      property :shared, [TrueClass, FalseClass],
        description: "Determines whether or not the printer is shared.",
        default: false

      property :share_name, String,
        description: "The name used to identify the shared printer."

      property :ipv4_address, String,
        description: "The IPv4 address of the printer, such as `10.4.64.23`",
        callbacks: {
          "The ipv4_address property must be in the IPv4 format of `WWW.XXX.YYY.ZZZ`" =>
            proc { |v| v.match(Resolv::IPv4::Regex) },
        }

      property :create_port, [TrueClass, FalseClass],
        description: "Create a printer port for the printer. Set this to false and specify the `port_name` property if using the `windows_printer_port` resource to create the port instead.",
        introduced: "17.3",
        default: true, desired_state: false

      property :port_name, String,
        description: "The port name.",
        default: lazy { |x| "IP_#{x.ipv4_address}" },
        introduced: "17.3",
        default_description: "The resource block name or the ipv4_address prepended with IP_."

      def ps_bool_to_ruby(bool)
        bool.to_s.downcase == "true"
      end

      load_current_value do |new_resource|
        # this is why so we can fetch the default printer on the system
        printer_data = powershell_exec(%Q{Get-WmiObject -Class Win32_Printer -Filter "DeviceID='#{new_resource.device_id}'"}).result

        if printer_data.empty?
          current_value_does_not_exist!
        else
          device_id new_resource.device_id
          comment printer_data["Comment"]
          default ps_bool_to_ruby(printer_data["Default"])
          location printer_data["Location"]
          shared ps_bool_to_ruby(printer_data["Shared"])
          share_name printer_data["ShareName"]
          port_name printer_data["PortName"]

          driver_data = powershell_exec(%Q{Get-PrinterDriver -Name="#{new_resource.driver_name}"}).result
          driver_name driver_data.empty? ? "unset" : new_resource.driver_name # we have to set this to a value or required validation fails
        end
      end

      action :create, description: "Create or update a printer." do
        # Create the printer port first unless the property is set to false
        if new_resource.create_port
          windows_printer_port new_resource.port_name do
            ipv4_address new_resource.ipv4_address
            port_name new_resource.port_name
          end
        end

        converge_if_changed(:driver_name) do
          powershell_exec!("Add-PrinterDriver -Name '#{new_resource.driver_name}'")
        end

        if current_resource
          converge_if_changed(:comment, :driver_name, :location, :port_name, :shared, :share_name) do
            # update the existing printer using PowerShell
            printer_shellout!("Set")
          end
        else
          converge_if_changed(:comment, :driver_name, :location, :port_name, :shared, :share_name) do
            # create a whole new printer using PowerShell
            printer_shellout!("Add")
          end
        end

        # Set-Printer does let you set the printer as the default
        converge_if_changed(:default) do
          powershell_exec!("(New-Object -ComObject WScript.Network).SetDefaultPrinter('#{new_resource.device_id}')")
        end
      end

      action :delete, description: "Delete an existing printer. Note that this resource does not delete the associated printer port or remove the driver." do
        if current_resource
          converge_by("Delete #{new_resource.device_id}") do
            powershell_exec!("Remove-Printer -Name '#{new_resource.device_id}'")
          end
        else
          Chef::Log.info "#{new_resource.device_id} doesn't exist - can't delete."
        end
      end

      action_class do
        def printer_shellout!(action)
          update_cmd = "#{action}-Printer -Name '#{new_resource.device_id}'"\
          " -DriverName '#{new_resource.driver_name}'"\
          " -PortName '#{new_resource.port_name}'"

          update_cmd << " -Shared" if new_resource.shared
          update_cmd << " -Comment '#{new_resource.comment}'" if new_resource.comment
          update_cmd << " -Location '#{new_resource.location}'" if new_resource.location
          update_cmd << " -ShareName '#{new_resource.share_name}" if new_resource.share_name

          powershell_exec!(update_cmd)
        end
      end
    end
  end
end
