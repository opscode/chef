#
# Author:: Tyler Ball (<tball@chef.io>)
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

require_relative "../resource"
require_relative "resource_collection_serialization"

class Chef
  class ResourceCollection
    class ResourceSet
      include ResourceCollection::ResourceCollectionSerialization

      # Matches a multiple resource lookup specification,
      # e.g., "service[nginx,unicorn]"
      MULTIPLE_RESOURCE_MATCH = /^(.+)\[(.+?),(.+)\]$/.freeze

      # Matches a single resource lookup specification,
      # e.g., "service[nginx]"
      SINGLE_RESOURCE_MATCH = /^(.+)\[(.*)\]$/.freeze

      # Matches e.g. "apt_update" with no name
      NAMELESS_RESOURCE_MATCH = /^([^\[\]\s]+)$/.freeze

      def initialize
        @resources_by_key = {}
      end

      def keys
        @resources_by_key.keys
      end

      def insert_as(resource, resource_type = nil, instance_name = nil)
        is_chef_resource!(resource)
        resource_type ||= resource.resource_name
        instance_name ||= resource.name
        key = create_key(resource_type, instance_name)
        @resources_by_key[key] = resource
      end

      def lookup(key)
        raise ArgumentError, "Must pass a Chef::Resource or String to lookup" unless key.is_a?(String) || key.is_a?(Chef::Resource)

        key = key.to_s
        res = @resources_by_key[key]
        unless res
          raise Chef::Exceptions::ResourceNotFound, "Cannot find a resource matching #{key} (did you define it first?)"
        end

        res
      end

      def delete(key)
        raise ArgumentError, "Must pass a Chef::Resource or String to delete" unless key.is_a?(String) || key.is_a?(Chef::Resource)

        key = key.to_s
        res = @resources_by_key.delete(key)

        if res == @resources_by_key.default
          raise Chef::Exceptions::ResourceNotFound, "Cannot find a resource matching #{key} (did you define it first?)"
        end

        res
      end

      # Find existing resources by searching the list of existing resources.  Possible
      # forms are:
      #
      # find(:file => "foobar")
      # find(:file => [ "foobar", "baz" ])
      # find("file[foobar]", "file[baz]")
      # find("file[foobar,baz]")
      #
      # Returns the matching resource, or an Array of matching resources.
      #
      # Raises an ArgumentError if you feed it bad lookup information
      # Raises a Runtime Error if it can't find the resources you are looking for.
      def find(*args)
        results = []
        args.each do |arg|
          case arg
            when Hash
              results << find_resource_by_hash(arg)
            when String
              results << find_resource_by_string(arg)
            else
              msg = "arguments to #{self.class.name}#find should be of the form :resource => 'name' or 'resource[name]'"
              raise Chef::Exceptions::InvalidResourceSpecification, msg
          end
        end
        flat_results = results.flatten
        flat_results.length == 1 ? flat_results[0] : flat_results
      end

      # @deprecated
      # resources is a poorly named, but we have to maintain it for back
      # compat.
      alias_method :resources, :find

      # Returns true if +query_object+ is a valid string for looking up a
      # resource, or raises InvalidResourceSpecification if not.
      # === Arguments
      # * query_object should be a string of the form
      # "resource_type[resource_name]", a single element Hash (e.g., :service =>
      # "apache2"), or a Chef::Resource (this is the happy path). Other arguments
      # will raise an exception.
      # === Returns
      # * true returns true for all valid input.
      # === Raises
      # * Chef::Exceptions::InvalidResourceSpecification for all invalid input.
      def validate_lookup_spec!(query_object)
        case query_object
          when Chef::Resource, SINGLE_RESOURCE_MATCH, MULTIPLE_RESOURCE_MATCH, NAMELESS_RESOURCE_MATCH, Hash
            true
          when String
            raise Chef::Exceptions::InvalidResourceSpecification,
              "The string `#{query_object}' is not valid for resource collection lookup. Correct syntax is `resource_type[resource_name]'"
          else
            raise Chef::Exceptions::InvalidResourceSpecification,
              "The object `#{query_object.inspect}' is not valid for resource collection lookup. " +
                "Use a String like `resource_type[resource_name]' or a Chef::Resource object"
        end
      end

      def self.from_hash(o)
        collection = new
        rl = o["instance_vars"]["@resources_by_key"]
        resources = rl.merge(rl) { |k, r| Chef::Resource.from_hash(r) }
        collection.instance_variable_set(:@resources_by_key, resources)
        collection
      end

      private

      def create_key(resource_type, instance_name)
        "#{resource_type}[#{instance_name}]"
      end

      def find_resource_by_hash(arg)
        results = []
        arg.each do |resource_type, name_list|
          instance_names = name_list.is_a?(Array) ? name_list : [ name_list ]
          instance_names.each do |instance_name|
            results << lookup(create_key(resource_type, instance_name))
          end
        end
        results
      end

      def find_resource_by_string(arg)
        begin
          if arg =~ SINGLE_RESOURCE_MATCH
            resource_type = $1
            name = $2
            return [ lookup(create_key(resource_type, name)) ]
          end
        rescue Chef::Exceptions::ResourceNotFound => e
          if arg =~ MULTIPLE_RESOURCE_MATCH
            begin
              results = []
              resource_type = $1
              arg =~ /^.+\[(.+)\]$/
              resource_list = $1
              resource_list.split(",").each do |instance_name|
                results << lookup(create_key(resource_type, instance_name))
              end
              Chef.deprecated(:multiresource_match, "The resource_collection multi-resource syntax is deprecated")
              return results
            rescue  Chef::Exceptions::ResourceNotFound
              raise e
            end
          else
            raise e
          end
        end

        if arg =~ NAMELESS_RESOURCE_MATCH
          resource_type = $1
          name = ""
          return [ lookup(create_key(resource_type, name)) ]
        end

        raise ArgumentError, "Bad string format #{arg}, you must have a string like resource_type[name]!"
      end
    end
  end
end
