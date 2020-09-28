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

require_relative "../../version"
class Chef
  class Knife
    class SubcommandLoader
      #
      # Load a subcommand from a pre-computed path
      # for the given command.
      #
      class HashedCommandLoader < Chef::Knife::SubcommandLoader
        KEY = "_autogenerated_command_paths".freeze

        attr_accessor :manifest

        def initialize(chef_config_dir, plugin_manifest)
          super(chef_config_dir)
          @manifest = plugin_manifest
        end

        def guess_category(args)
          category_words = positional_arguments(args)
          category_words.map! { |w| w.split("-") }.flatten!
          find_longest_key(manifest[KEY]["plugins_by_category"], category_words, " ")
        end

        def list_commands(pref_category = nil)
          if pref_category || manifest[KEY]["plugins_by_category"].key?(pref_category)
            commands = { pref_category => manifest[KEY]["plugins_by_category"][pref_category] }
          else
            commands = manifest[KEY]["plugins_by_category"]
          end
          # If any of the specified plugins in the manifest don't have a valid path we will
          # eventually get an error and the user will need to rehash - instead, lets just
          # print out 1 error here telling them to rehash
          errors = {}
          commands.collect { |k, v| v }.flatten.each do |command|
            paths = manifest[KEY]["plugins_paths"][command]
            if paths && paths.is_a?(Array)
              # It is only an error if all the paths don't exist
              if paths.all? { |sc| !File.exist?(sc) }
                errors[command] = paths
              end
            end
          end
          if errors.empty?
            commands
          else
            Chef::Log.error "There are plugin files specified in the knife cache that cannot be found. Please run knife rehash to update the subcommands cache. If you see this error after rehashing delete the cache at #{Chef::Knife::SubcommandLoader.plugin_manifest_path}"
            Chef::Log.error "Missing files:\n\t#{errors.values.flatten.join("\n\t")}"
            {}
          end
        end

        def subcommand_files
          manifest[KEY]["plugins_paths"].values.flatten
        end

        def load_command(args)
          paths = manifest[KEY]["plugins_paths"][subcommand_for_args(args)]
          if paths.nil? || paths.empty? || (! paths.is_a? Array)
            false
          else
            paths.each do |sc|
              if File.exist?(sc)
                Kernel.load sc
              else
                return false
              end
            end
            true
          end
        end

        def subcommand_for_args(args)
          if manifest[KEY]["plugins_paths"].key?(args)
            args
          else
            find_longest_key(manifest[KEY]["plugins_paths"], args, "_")
          end
        end
      end
    end
  end
end
