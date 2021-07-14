#
# Author:: Adam Jacob (<adam@chef.io>)
# Author:: Nuo Yan (<nuo@chef.io>)
# Author:: Christopher Brown (<cb@chef.io>)
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

require_relative "config"
require_relative "mixin/params_validate"
require_relative "mixin/from_file"
require_relative "data_bag_item"
require_relative "mash"
require_relative "json_compat"
require_relative "server_api"

class Chef
  class DataBag

    include Chef::Mixin::FromFile
    include Chef::Mixin::ParamsValidate

    VALID_NAME = /^[\.\-[:alnum:]_]+$/.freeze
    RESERVED_NAMES = /^(node|role|environment|client)$/.freeze

    def self.validate_name!(name)
      unless VALID_NAME.match?(name)
        raise Exceptions::InvalidDataBagName, "DataBags must have a name matching #{VALID_NAME.inspect}, you gave #{name.inspect}"
      end
      if RESERVED_NAMES.match?(name)
        raise Exceptions::InvalidDataBagName, "DataBags may not have a name matching #{RESERVED_NAMES.inspect}, you gave #{name.inspect}"
      end

      if name.include? "."
        ChefConfig.logger.deprecation(" Databags name with period is now deprecated, consider using name without '.', you gave: #{name.inspect}")
      end
    end

    # Create a new Chef::DataBag
    def initialize(chef_server_rest: nil)
      @name = ""
      @chef_server_rest = chef_server_rest
    end

    def name(arg = nil)
      set_or_return(
        :name,
        arg,
        regex: VALID_NAME
      )
    end

    def to_h
      {
        "name" => @name,
        "json_class" => self.class.name,
        "chef_type" => "data_bag",
      }
    end

    alias_method :to_hash, :to_h

    # Serialize this object as a hash
    def to_json(*a)
      Chef::JSONCompat.to_json(to_h, *a)
    end

    def chef_server_rest
      @chef_server_rest ||= Chef::ServerAPI.new(Chef::Config[:chef_server_url])
    end

    def self.chef_server_rest
      Chef::ServerAPI.new(Chef::Config[:chef_server_url])
    end

    def self.from_hash(o)
      bag = new
      bag.name(o["name"])
      bag
    end

    def self.list(inflate = false)
      if Chef::Config[:solo_legacy_mode]
        paths = Array(Chef::Config[:data_bag_path])
        names = []
        paths.each do |path|
          unless File.directory?(path)
            raise Chef::Exceptions::InvalidDataBagPath, "Data bag path '#{path}' not found. Please create this directory."
          end

          names += Dir.glob(File.join(
            Chef::Util::PathHelper.escape_glob_dir(path), "*"
          )).map { |f| File.basename(f) }.sort
        end
        names.inject({}) { |h, n| h[n] = n; h }
      else
        if inflate
          # Can't search for all data bags like other objects, fall back to N+1 :(
          list(false).inject({}) do |response, bag_and_uri|
            response[bag_and_uri.first] = load(bag_and_uri.first)
            response
          end
        else
          Chef::ServerAPI.new(Chef::Config[:chef_server_url]).get("data")
        end
      end
    end

    # Load a Data Bag by name via either the RESTful API or local data_bag_path if run in solo mode
    def self.load(name)
      if Chef::Config[:solo_legacy_mode]
        paths = Array(Chef::Config[:data_bag_path])
        data_bag = {}
        paths.each do |path|
          unless File.directory?(path)
            raise Chef::Exceptions::InvalidDataBagPath, "Data bag path '#{path}' not found. Please create this directory."
          end

          Dir.glob(File.join(Chef::Util::PathHelper.escape_glob_dir(path, name.to_s), "*.json")).inject({}) do |bag, f|
            item = Chef::JSONCompat.parse(IO.read(f))

            # Check if we have multiple items with similar names (ids) and raise if their content differs
            if data_bag.key?(item["id"]) && data_bag[item["id"]] != item
              raise Chef::Exceptions::DuplicateDataBagItem, "Data bag '#{name}' has items with the same name '#{item["id"]}' but different content."
            else
              data_bag[item["id"]] = item
            end
          end
        end
        data_bag
      else
        Chef::ServerAPI.new(Chef::Config[:chef_server_url]).get("data/#{name}")
      end
    end

    def destroy
      chef_server_rest.delete("data/#{@name}")
    end

    # Save the Data Bag via RESTful API
    def save
      begin
        if Chef::Config[:why_run]
          Chef::Log.warn("In why-run mode, so NOT performing data bag save.")
        else
          create
        end
      rescue Net::HTTPClientException => e
        raise e unless e.response.code == "409"
      end
      self
    end

    # create a data bag via RESTful API
    def create
      chef_server_rest.post("data", self)
      self
    end

    # As a string
    def to_s
      "data_bag[#{@name}]"
    end

  end
end
