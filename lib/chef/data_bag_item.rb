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

require "forwardable" unless defined?(Forwardable)

require_relative "config"
require_relative "mixin/params_validate"
require_relative "mixin/from_file"
require_relative "data_bag"
require_relative "mash"
require_relative "server_api"
require_relative "json_compat"

class Chef
  class DataBagItem

    extend Forwardable

    include Chef::Mixin::FromFile
    include Chef::Mixin::ParamsValidate

    VALID_ID = /^[\.\-[:alnum:]_]+$/.freeze

    def self.validate_id!(id_str)
      if id_str.nil? || ( id_str !~ VALID_ID )
        raise Exceptions::InvalidDataBagItemID, "Data Bag items must have an id matching #{VALID_ID.inspect}, you gave: #{id_str.inspect}"
      end

      if id_str.include? "."
        ChefConfig.logger.deprecation(" Data bag item ID with period is now deprecated, consider using ID without '.', you gave: #{id_str.inspect}")
      end
    end

    # delegate missing methods to the @raw_data Hash
    def method_missing(method_name, *arguments, &block)
      @raw_data.send(method_name, *arguments, &block)
    rescue
      # throw more sensible errors back at the user
      super
    end

    def respond_to_missing?(method_name, include_private = false)
      @raw_data.respond_to?(method_name, include_private) || super
    end

    attr_reader :raw_data

    # Create a new Chef::DataBagItem
    def initialize(chef_server_rest: nil)
      @data_bag = nil
      @raw_data = Mash.new
      @chef_server_rest = chef_server_rest
    end

    def chef_server_rest
      @chef_server_rest ||= Chef::ServerAPI.new(Chef::Config[:chef_server_url])
    end

    def self.chef_server_rest
      Chef::ServerAPI.new(Chef::Config[:chef_server_url])
    end

    def validate_id!(id_str)
      self.class.validate_id!(id_str)
    end

    def raw_data=(new_data)
      new_data = Mash.new(new_data)
      unless new_data.respond_to?(:[]) && new_data.respond_to?(:keys)
        raise Exceptions::ValidationFailed, "Data Bag Items must contain a Hash or Mash!"
      end

      validate_id!(new_data["id"])
      @raw_data = new_data
    end

    def data_bag(arg = nil)
      set_or_return(
        :data_bag,
        arg,
        regex: /^[\-[:alnum:]_]+$/
      )
    end

    def name
      object_name
    end

    def object_name
      raise Exceptions::ValidationFailed, "You must have an 'id' or :id key in the raw data" unless raw_data.key?("id")
      raise Exceptions::ValidationFailed, "You must have declared what bag this item belongs to!" unless data_bag

      id = raw_data["id"]
      "data_bag_item_#{data_bag}_#{id}"
    end

    def self.object_name(data_bag_name, id)
      "data_bag_item_#{data_bag_name}_#{id}"
    end

    def to_h
      result = raw_data.dup
      result["chef_type"] = "data_bag_item"
      result["data_bag"] = data_bag.to_s
      result
    end

    alias_method :to_hash, :to_h

    # Serialize this object as a hash
    def to_json(*a)
      result = {
        "name" => object_name,
        "json_class" => self.class.name,
        "chef_type" => "data_bag_item",
        "data_bag" => data_bag,
        "raw_data" => raw_data,
      }
      Chef::JSONCompat.to_json(result, *a)
    end

    def self.from_hash(h)
      h.delete("chef_type")
      h.delete("json_class")

      item = new
      item.data_bag(h.delete("data_bag")) if h.key?("data_bag")
      if h.key?("raw_data")
        item.raw_data = h["raw_data"]
      else
        item.raw_data = h
      end
      item
    end

    # Load a Data Bag Item by name via either the RESTful API or local data_bag_path if run in solo mode
    def self.load(data_bag, name)
      if Chef::Config[:solo_legacy_mode]
        bag = Chef::DataBag.load(data_bag)
        raise Exceptions::InvalidDataBagItemID, "Item #{name} not found in data bag #{data_bag}. Other items found: #{bag.keys.join(", ")}" unless bag.include?(name)

        item = bag[name]
      else
        item = Chef::ServerAPI.new(Chef::Config[:chef_server_url]).get("data/#{data_bag}/#{name}")
      end

      if item.is_a?(DataBagItem)
        item
      else
        item = from_hash(item)
        item.data_bag(data_bag)
        item
      end
    end

    def destroy(data_bag = self.data_bag, databag_item = name)
      chef_server_rest.delete("data/#{data_bag}/#{databag_item}")
    end

    # Save this Data Bag Item via RESTful API
    def save(item_id = @raw_data["id"])
      r = chef_server_rest
      begin
        if Chef::Config[:why_run]
          Chef::Log.warn("In why-run mode, so NOT performing data bag item save.")
        else
          r.put("data/#{data_bag}/#{item_id}", self)
        end
      rescue Net::HTTPClientException => e
        raise e unless e.response.code == "404"

        r.post("data/#{data_bag}", self)
      end
      self
    end

    # Create this Data Bag Item via RESTful API
    def create
      chef_server_rest.post("data/#{data_bag}", self)
      self
    end

    def ==(other)
      other.respond_to?(:to_h) &&
        other.respond_to?(:data_bag) &&
        (other.to_h == to_h) &&
        (other.data_bag.to_s == data_bag.to_s)
    end

    # As a string
    def to_s
      "data_bag_item[#{id}]"
    end

    def inspect
      "data_bag_item[#{data_bag.inspect}, #{raw_data["id"].inspect}, #{raw_data.inspect}]"
    end

    def pretty_print(pretty_printer)
      pretty_printer.pp({ "data_bag_item('#{data_bag}', '#{id}')" => to_hash })
    end

    def id
      @raw_data["id"]
    end

  end
end
