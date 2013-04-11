#
# Author:: Steven Danna (<steve@opscode.com>)
# Copyright:: Copyright (c) 2009 Opscode, Inc.
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

require 'chef/knife'

class Chef
  class Knife
    class UserShow < Knife

      deps do
        require 'chef/user'
        require 'chef/json_compat'
      end

      banner "knife user show USER (options)"

      option :attribute,
        :short => "-a ATTR1,ATTR2",
        :long => "--attribute ATTR1,ATTR2",
        :description => "Show specific attribute(s)"

      def run
        @user_name = @name_args[0]

        if @user_name.nil?
          show_usage
          ui.fatal("You must specify a user name")
          exit 1
        end

        user = Chef::User.load(@user_name)
        output(format_for_display(user))
      end

    end
  end
end
