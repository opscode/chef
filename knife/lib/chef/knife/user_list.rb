#
# Author:: Steven Danna (<steve@chef.io>)
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

require_relative "../knife"

class Chef
  class Knife
    class UserList < Knife

      deps do
        # is not used there, only in knife.
        require "chef/user_v1" unless defined?(Chef::UserV1)
      end

      banner "knife user list (options)"

      option :with_uri,
        short: "-w",
        long: "--with-uri",
        description: "Show corresponding URIs."

      option :global,
        short: "-g",
        long: "--global",
        description: "List all global users."

      def run
        if config[:global]
          results = format_list_for_display(root_rest.get("users"))
        else
          user_arr = rest.get("users")
          results = user_arr.map { |user| user["user"]["username"] }
        end
        output(results)
      end

    end
  end
end
