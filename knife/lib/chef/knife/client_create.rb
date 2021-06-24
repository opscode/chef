#
# Author:: Adam Jacob (<adam@chef.io>)
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
require "chef-utils/dist" unless defined?(ChefUtils::Dist)
require "pry"

class Chef
  class Knife
    class ClientCreate < Knife

      deps do
        require "chef/api_client_v1" unless defined?(Chef::ApiClientV1)
      end

      option :file,
        short: "-f FILE",
        long: "--file FILE",
        description: "Write the private key to a file if the #{ChefUtils::Dist::Server::PRODUCT} generated one."

      option :validator,
        long: "--validator",
        description: "Create the client as a validator.",
        boolean: true

      option :public_key,
        short: "-p FILE",
        long: "--public-key",
        description: "Set the initial default key for the client from a file on disk (cannot pass with --prevent-keygen)."

      option :prevent_keygen,
        short: "-k",
        long: "--prevent-keygen",
        description: "Prevent #{ChefUtils::Dist::Server::PRODUCT} from generating a default key pair for you. Cannot be passed with --public-key.",
        boolean: true

      banner "knife client create CLIENTNAME (options)"

      def client
        @client_field ||= Chef::ApiClientV1.new
      end

      def create_client(client)
        # should not be using save :( bad behavior
        Chef::ApiClientV1.from_hash(client).save
      end

      def run
        test_mandatory_field(@name_args[0], "client name")
        client.name @name_args[0]

        if config[:public_key] && config[:prevent_keygen]
          show_usage
          ui.fatal("You cannot pass --public-key and --prevent-keygen")
          exit 1
        end

        if !config[:prevent_keygen] && !config[:public_key]
          client.create_key(true)
        end

        if config[:validator]
          client.validator(true)
        end

        if config[:public_key]
          client.public_key File.read(File.expand_path(config[:public_key]))
        end

        # Check the file before creating the client so the api is more transactional.
        if config[:file]
          file = config[:file]
          dir_name = File.dirname(file)
          chek_writable_or_exists(dir_name, "Directory")
          chek_writable_or_exists(file, "File")
        end

        output = edit_hash(client)
        final_client = create_client(output)
        ui.info("Created #{final_client}")

        # output private_key if one
        if final_client.private_key
          if config[:file]
            File.open(config[:file], "w") do |f|
              f.print(final_client.private_key)
            end
          else
            puts final_client.private_key
          end
        end
      end

      # To check if file or directory exists or writable and raise execption accordingly
      def chek_writable_or_exists(file, type)
        if File.exist?(file)
          unless File.writable?(file)
            ui.fatal "#{type} #{file} is not writable. Check permissions."
            exit 1
          end
        else
          ui.fatal "#{type} #{file} dose not exist."
          exit 1
        end
      end
    end
  end
end
