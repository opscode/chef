#
# Author:: Richard Lavey (richard.lavey@calastone.com)
#
# Copyright:: 2015-2017, Calastone Ltd.
# Copyright:: Copyright (c) Chef Software Inc.
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

require_relative "../resource"
require_relative "../exceptions"
# require_relative "../win32/error" if RUBY_PLATFORM.match?(/mswin|mingw|windows/)
# require "chef-utils/dist" unless defined?(ChefUtils::Dist)

class Chef
  class Resource
    class WindowsPackageManager < Chef::Resource
      unified_mode true

      provides :windows_package_manager

      description "Use the **windows_package_manager** resource allows you to add/remove/update windows packages using WinGet."
      introduced "17.20"
      examples <<~DOC
      **Add a new package to a system**

      ```ruby
      windows_package_manager 'Install 7zip' do
        package_name  7zip
        action :install
      end
      ```

      **Add a package source to install from**

      ```ruby
      windows_package_manager "Add New Source" do
        source_name "my_package_source"
        url  https://foo/bar.com/packages
        action :register
      end
      ```

      **Remove a package source to install from**

      ```ruby
      windows_package_manager "Add New Source" do
        source_name "my_package_source"
        action :unregister
      end
      ```

      **Install a package from a custom source**

      ```ruby
      windows_package_manager "Install 7zip from new source" do
        package_name  7zip
        source_name "my_package_source"
        scope 'User'
        location "C:\\Foo\\7Zip"
        override "-o, -q, -h"
        force true
        action :install
      end
      ```

      DOC

      property :package_name, String,
        description: "The name of a single package to be installed."

      property :source_name, String,
        description: "The name of a custom installation source.",
        default: "winget"

      property :url, String,
        description: "The url to a package or source"

      property :scope, String,
        description: "Install the package for the current user or the whole machine.",
        default: "user", equal_to: [user, machine]

      property :location, String,
        description: "The location on the local system to install the package to. For example 'c:\foo\'."

      property :override, Array,
        description: "An array containing command line switches to pass to your package. In the form of '-o, -foo, -bar, -blat'."

      property :force, [TrueClass, FalseClass],
        description: "Tells WinGet to bypass hash-checking a package.",
        default: false

      action :install, description: "Installs an item on a Windows node." do
        local_arguments = build_argument_string
        converge_by("install package: #{new_resource.package_name}") do
          install_cmd = ps_execute_winget("install", package_name: new_resource.package_name, arguments: local_arguments)
          res = powershell_exec(install_cmd)
          raise "Failed to install #{new_resource.package_name}: #{res.errors}" if res.error?
        end
      end

      action :register, description: "Adds or updates a package source location to install a package from." do
        if package_source_exists?
          converge_if_changed :url do
            update_cmd = build_ps_package_source_command("update", new_resource.source_name, new_resource.url)
            res = powershell_exec(update_cmd)
            raise "Failed to update #{new_resource.source_name}: #{res.errors}" if res.error?
          end
        else
          converge_by("register source: #{new_resource.source_name}") do
            register_cmd = build_ps_package_source_command("add", new_resource.source_name, new_resource.url)
            res = powershell_exec!(register_cmd)
            puts "what does my result say? #{res.result}"
            raise "Failed to register #{new_resource.source_name}: #{res.errors}" if res.error?
          end
        end
      end

      action :unregister, description: "Removes a package source location." do
        if package_source_exists?
          powershell_exec!("winget source remove --name #{new_resource.source_name} ")
        end
      end

      action_class do
        def build_argument_string
          build_arguments = ""
          build_arguments << " --source #{new_resource.source_name}" if new_resource.source_name
          build_arguments << " --scope #{new_resource.scope}" if new_resource.scope
          build_arguments << " --override:#{new_resource.override}" if new_resource.override
          build_arguments << " --location #{new_resource.location}" if new_resource.location
          build_arguments << " --force" if new_resource.force
          build_arguments
        end

        def ps_execute_winget(cmd_type, package_name:, arguments:)
          <<-CMD
            winget #{cmd_type} --name #{package_name} #{arguments}
          CMD
        end

        def package_source_exists?
          powershell_exec!(ps_package_sources_cmd).result
        end

        def ps_package_sources_cmd
          <<-CMD
            $hash = new-object System.Collections.Hashtable
            [System.Collections.ArrayList]$sources = Invoke-Expression "winget source list"
            $sources += $sources.Remove("Name   Argument")
            $sources += $sources.Remove("-------------------------------------------------------")

            foreach($source in $sources){
              $break = $($source -replace '\s+', ' ').split()
              $key = $break[0]
              $value = $break[1]
              $hash.Add($key, $value)
            }

            foreach($key in $hash.Keys){
              if($key -contains "#{new_resource.source_name}"){
                return $true
              }
              else{
                return $false
              }
            }
          CMD
        end

        def build_ps_package_source_command(cmdlet_type, source, url)
          cmd = "winget source #{cmdlet_type} --Name #{source} #{url}"
          cmd
        end

      end

    end
  end
end
