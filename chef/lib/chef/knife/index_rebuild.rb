#
# Author:: Daniel DeLeo (<dan@kallistec.com>)
# Copyright:: Copyright (c) 2009 Daniel DeLeo
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
    class IndexRebuild < Knife

      banner "knife index rebuild (options)"
      option :yes,
        :short        => "-y",
        :long         => "--yes",
        :boolean      => true,
        :description  => "don't bother to ask if I'm sure"

      def run
        nag
        output rest.post_rest("/search/reindex", {})
      end

      def nag
        unless config[:yes]
          yea_or_nay = ask_question("This operation is destructive. Rebuilding the index may take some time. You sure? (yes/no): ")
          unless yea_or_nay =~ /^y/i
            puts "aborting"
            exit 7
          end
        end
      end


    end
  end
end
