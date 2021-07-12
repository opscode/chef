#
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

class Chef
  class Resource
    class HomebrewInstall < Chef::Resource
      unified_mode true

      provides :homebrew_install

      description "Use the **homebrew_install** resource to install the Homebrew package manager on macOS systems."
      introduced "16.11"
      examples <<~DOC
      **Install Homebrew using the Internet to download Command Line Tools for Xcode**:

      ```ruby
      homebrew_install 'Install Homebrew and xcode command line tools if necessary' do
        user 'someuser'
        action :install
      end
      ```

      **Install Homebrew using a customer-managed source to download Command Line Tools for Xcode from**:

      ```ruby
      homebrew_install 'Install Homebrew and xcode command line tools if necessary' do
        xcode_tools_url 'https://somewhere.something.com/downloads/command_line_tools.dmg'
        xcode_tools_pkg_name 'Command Line Tools.pkg'
        user 'someuser'
        action :install
      end
      ```
      DOC

      property :xcode_tools_url, String,
        description: "URL of the `Command Line Tools for Xcode` DMG file."

      property :xcode_tools_pkg_name, String,
        description: "The name of the pkg inside the DMG specified in the `xcode_tools_url` property."

      property :brew_source_url, String,
        description: "URL of the Homebrew install zipfile.",
        default: "https://codeload.github.com/Homebrew/brew/zip/master"

      property :user, String,
        description: "The user to install Homebrew as. Note: Homebrew cannot be installed as root.",
        required: true

      property :force, [TrueClass, FalseClass],
        description: "Force the installation of Homebrew even if the `/usr/local/bin/brew` command already exists on the system.",
        default: false

      action :install do
        # Avoid all the work in the below resources if homebrew is already installed
        return if !new_resource.force && ::File.exist?("/usr/local/bin/brew")

        # check if 'user' is root and raise an exception if so
        if Etc.getpwnam(new_resource.user).uid == 0
          msg = "You are attempting to install Homebrew as Root. This is not permitted by Homebrew. Please run this as a standard user with admin rights"
          raise Chef::Exceptions::InsufficientPermissions, msg
        end

        # Creating the basic directory structure needed for Homebrew
        ["bin", "etc", "include", "lib", "sbin", "share", "var", "opt", "share/zsh", "share/zsh/site-functions",
         "var/homebrew", "var/homebrew/linked", "Cellar", "Caskroom", "Homebrew", "Frameworks" ].each do |dir|
           directory "/usr/local/#{dir}" do
             mode "0775"
             owner new_resource.user
             group "admin"
             action :create
           end
         end

        directory ::File.join(Dir.home(new_resource.user), "/Library/Caches/Homebrew") do
          mode "0755"
          owner new_resource.user
          recursive true
          group "admin"
          action :create
        end

        script "Initialize the homebrew git source" do
          interpreter "bash"
          cwd "/usr/local/Homebrew"
          code <<-CODEBLOCK
            git init -q
            git config remote.origin.url https://github.com/Homebrew/homebrew-core
            git config remote.origin.fetch +refs/heads/*:refs/remotes/origin/*
            git config core.autocrlf false
            git fetch --force origin refs/heads/master:refs/remotes/origin/master
            git remote set-head origin --auto >/dev/null
            git reset --hard origin/master\
          CODEBLOCK
          user "root"
        end

        if new_resource.xcode_tools_url
          dmg_package new_resource.xcode_tools_pkg_name do
            source new_resource.xcode_tools_url
            type "pkg"
          end
        else
          build_essential "install Command Line Tools for Xcode" do
            action :install
          end
        end

        zip_file = Chef::Config[:file_cache_path] + "/brew_master.zip"
        remote_file zip_file do
          source new_resource.brew_source_url
          owner new_resource.user
          group "admin"
          mode "0755"
          action :create
        end


        archive_file "Unpack the existing Homebrew files" do
          path zip_file
          destination "/usr/local/Homebrew"
          action :extract
          overwrite true
        end

        script "move files to their correct locations" do
          interpreter "bash"
          cwd "/usr/local/Homebrew"
          code <<-CODEBLOCK
            mv /usr/local/Homebrew/brew-master/* /usr/local/Homebrew/
            mv /usr/local/Homebrew/brew-master/.* /usr/local/Homebrew/
            rmdir /usr/local/Homebrew/brew-master/
          CODEBLOCK
          user "root"
        end

        shell_out("rm", "#{zip_file}", user: "root", environment: nil, cwd: "/usr/local/Homebrew")
        shell_out("git", "config", "core.autocrlf", "false", user: new_resource.user, environment: nil, cwd: "/usr/local/Homebrew")
        shell_out("ln", "-sf", "/usr/local/Homebrew/bin/brew", "/usr/local/bin/brew", user: new_resource.user, environment: nil, cwd: "/usr/local/Homebrew")
        shell_out("/usr/local/bin/brew", "update", "--force", user: new_resource.user, environment: nil, cwd: "/usr/local/Homebrew")

        local_shell = shell_out("echo $SHELL")
        if local_shell.stdout.match(/zsh/)
          shell_out('export PATH="/usr/local/bin:$PATH" >> ~/.zshrc')
        else
          shell_out('export PATH="/usr/local/bin:$PATH" >> ~/.bash_profile')
        end
      end
    end
  end
end
