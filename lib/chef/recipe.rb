#--
# Author:: Adam Jacob (<adam@chef.io>)
# Author:: Christopher Walters (<cw@chef.io>)
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

autoload :YAML, "yaml"
autoload :ERB, "erb"
require_relative "dsl/recipe"
require_relative "mixin/from_file"
require_relative "mixin/deprecation"

class Chef
  # == Chef::Recipe
  # A Recipe object is the context in which Chef recipes are evaluated.
  class Recipe
    attr_accessor :cookbook_name, :recipe_name, :recipe, :params, :run_context

    include Chef::DSL::Recipe

    include Chef::Mixin::FromFile
    include Chef::Mixin::Deprecation

    # Parses a potentially fully-qualified recipe name into its
    # cookbook name and recipe short name.
    #
    # For example:
    #   "aws::elastic_ip" returns [:aws, "elastic_ip"]
    #   "aws" returns [:aws, "default"]
    #   "::elastic_ip" returns [ current_cookbook, "elastic_ip" ]
    #--
    # TODO: Duplicates functionality of RunListItem
    def self.parse_recipe_name(recipe_name, current_cookbook: nil)
      case recipe_name
      when /(.+?)::(.+)/
        [ $1.to_sym, $2 ]
      when /^::(.+)/
        raise "current_cookbook is nil, cannot resolve #{recipe_name}" if current_cookbook.nil?

        [ current_cookbook.to_sym, $1 ]
      else
        [ recipe_name.to_sym, "default" ]
      end
    end

    def initialize(cookbook_name, recipe_name, run_context)
      @cookbook_name = cookbook_name
      @recipe_name = recipe_name
      @run_context = run_context
      # TODO: 5/19/2010 cw/tim: determine whether this can be removed
      @params = {}
    end

    # Used in DSL mixins
    def node
      run_context.node
    end

    # This was moved to Chef::Node#tag, redirecting here for compatibility
    def tag(*tags)
      run_context.node.tag(*tags)
    end

    # Removes the list of tags from the node.
    #
    # === Parameters
    # tags<Array>:: A list of tags
    #
    # === Returns
    # tags<Array>:: The current list of run_context.node.tags
    def untag(*tags)
      tags.each do |tag|
        run_context.node.tags.delete(tag)
      end
    end

    def from_yaml_file(filename)
      self.source_file = filename
      if File.file?(filename) && File.readable?(filename)
        yaml_contents = IO.read(filename)
        if ::YAML.load_stream(yaml_contents).length > 1
          raise ArgumentError, "YAML recipe '#{filename}' contains multiple documents, only one is supported"
        end

        from_yaml(yaml_contents)
      else
        raise IOError, "Cannot open or read file '#{filename}'!"
      end
    end

    def from_yaml(string)
      rcp = ::ERB.new(string).result(binding)
      res = ::YAML.safe_load(rcp)

      unless res.is_a?(Hash) && res.key?("resources")
        raise ArgumentError, "YAML recipe '#{source_file}' must contain a top-level 'resources' hash (YAML sequence), i.e. 'resources:'"
      end

      from_hash(res)
    end

    def from_hash(hash)
      # Define resource collection
      hash["resources"].each do |rhash|
        name = rhash.delete("name")
        if rhash.key? "type"
          type = rhash.delete("type").to_sym
        elsif name =~ /^(\w+?)\[(.+)\]$/
          type = $1
          name =$2
        else
          Chef::Application.fatal! "Resource type not defined"
        end

        res = declare_resource(type, name)
        rhash.each do |key, value|
          # FIXME?: we probably need a way to instance_exec a string that contains block code against the property?
          # If methods are +notifies+ or +subscribes+ pass as array of args, else as simple array
          if key == "notifies" || key == "subscribes"
            res.send(key, *value)
          else
            res.send(key, value)
          end
        end
      end
    end

    def to_s
      "cookbook: #{cookbook_name || "(none)"}, recipe: #{recipe_name || "(none)"} "
    end

    def inspect
      to_s
    end
  end
end
