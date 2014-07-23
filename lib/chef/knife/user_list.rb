#
# Author:: Steven Danna (<steve@opscode.com>)
# Copyright:: Copyright (c) 2012 Opscode, Inc.
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
    class UserList < Knife
      deps do
        require 'chef/user'
        require 'chef/json_compat'
      end

      banner 'knife user list (options)'

      option :with_uri,
             short: '-w',
             long: '--with-uri',
             description: 'Show corresponding URIs'

      def run
        output(format_list_for_display(Chef::User.list))
      end
    end
  end
end
