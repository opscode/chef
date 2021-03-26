#
# Author:: Adam Jacob (<adam@chef.io>)
# Author:: Seth Chisamore (<schisamo@chef.io>)
# Author:: Tyler Cloke (<tyler@chef.io>)
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

require_relative "file"
require_relative "../mixin/securable"
require "chef-utils/dist" unless defined?(ChefUtils::Dist)

class Chef
  class Resource
    # A cookbook template is an Embedded Ruby (ERB) template that is used to dynamically generate static text files.
    # Templates may contain Ruby expressions and statements, and are a great way to manage configuration files. Use the
    # template resource to add cookbook templates to recipes; place the corresponding Embedded Ruby (ERB) template file
    # in a cookbook's /templates directory.
    #
    # Use the template resource to manage the contents of a file using an Embedded Ruby (ERB) template by transferring
    # files from a sub-directory of COOKBOOK_NAME/templates/ to a specified path located on a host that is running the
    # chef-client. This resource includes actions and properties from the file resource. Template files managed by the
    # template resource follow the same file specificity rules as the remote_file and file resources.
    class Template < Chef::Resource::File
      unified_mode true

      provides :template

      include Chef::Mixin::Securable

      attr_reader :inline_helper_blocks
      attr_reader :inline_helper_modules

      def initialize(name, run_context = nil)
        super
        @source = "#{::File.basename(name)}.erb"
        @inline_helper_blocks = {}
        @inline_helper_modules = []
        @helper_modules = []
      end

      def source(file = nil)
        set_or_return(
          :source,
          file,
          kind_of: [ String, Array ]
        )
      end

      property :variables, Hash,
        description: "The variables property of the template resource can be used to reference a partial template file by using a Hash.",
        default: {}

      property :cookbook, String,
        description: "The cookbook in which a file is located (if it is not located in the current cookbook). The default value is the current cookbook.",
        desired_state: false

      property :local, [ TrueClass, FalseClass ],
        default: false, desired_state: false,
        description: "Load a template from a local path. By default, the #{ChefUtils::Dist::Infra::CLIENT} loads templates from a cookbook's /templates directory. When this property is set to true, use the source property to specify the path to a template on the local node."

      # Declares a helper method to be defined in the template context when
      # rendering.
      #
      # === Example:
      #
      # ==== Basic usage:
      # Given the following helper:
      #   helper(:static_value) { "hello from helper" }
      # A template with the following code:
      #   <%= static_value %>
      # Will render as;
      #   hello from helper
      #
      # ==== Referencing Instance Variables:
      # Any instance variables available to the template can be referenced in
      # the method body. For example, you can simplify accessing app-specific
      # node attributes like this:
      #   helper(:app) { @node[:my_app_attributes] }
      # And use it in a template like this:
      #   <%= app[:listen_ports] %>
      # This is equivalent to the non-helper template code:
      #   <%= @node[:my_app_attributes][:listen_ports] %>
      #
      # ==== Method Arguments:
      # Helper methods can also take arguments. The syntax available for
      # argument specification supports full syntax available for method
      # definition.
      #
      # Continuing the above example of simplifying attribute access, we can
      # define a helper to look up app-specific attributes like this:
      #   helper(:app) { |setting| @node[:my_app_attributes][setting] }
      # The template can then look up attributes like this:
      #   <%= app(:listen_ports) %>
      def helper(method_name, &block)
        unless block_given?
          raise Exceptions::ValidationFailed,
            "`helper(:method)` requires a block argument (e.g., `helper(:method) { code }`)"
        end

        unless method_name.is_a?(Symbol)
          raise Exceptions::ValidationFailed,
            "method_name argument to `helper(method_name)` must be a symbol (e.g., `helper(:method) { code }`)"
        end

        @inline_helper_blocks[method_name] = block
      end

      # Declares a module to define helper methods in the template's context
      # when rendering. There are two primary forms.
      #
      # === Inline Module Definition
      # When a block is given, the block is used to define a module which is
      # then mixed in to the template context w/ `extend`.
      #
      # ==== Inline Module Example
      # Given the following code in the template resource:
      #   helpers do
      #     # Add "syntax sugar" for referencing app-specific attributes
      #     def app(attribute)
      #       @node[:my_app_attributes][attribute]
      #     end
      #   end
      # You can use it in the template like so:
      #   <%= app(:listen_ports) %>
      # Which is equivalent to:
      #   <%= @node[:my_app_attributes][:listen_ports] %>
      #
      # === External Module Form
      # When a module name is given, the template context will be extended with
      # that module. This is the recommended way to customize template contexts
      # when you need to define more than an handful of helper functions (but
      # also try to keep your template helpers from getting out of hand--if you
      # have very complex logic in your template helpers, you should further
      # extract your code into separate libraries).
      #
      # ==== External Module Example
      # To extract the above inline module code to a library, you'd create a
      # library file like this:
      #   module MyTemplateHelper
      #     # Add "syntax sugar" for referencing app-specific attributes
      #     def app(attribute)
      #       @node[:my_app_attributes][attribute]
      #     end
      #   end
      # And in the template resource:
      #   helpers(MyTemplateHelper)
      # The template code in the above example will work unmodified.
      def helpers(module_name = nil, &block)
        if block_given? && !module_name.nil?
          raise Exceptions::ValidationFailed,
            "Passing both a module and block to #helpers is not supported. Call #helpers multiple times instead"
        elsif block_given?
          @inline_helper_modules << block
        elsif module_name.is_a?(::Module)
          @helper_modules << module_name
        elsif module_name.nil?
          raise Exceptions::ValidationFailed,
            "#helpers requires either a module name or inline module code as a block.\n" +
            "e.g.: helpers do; helper_code; end;\n" +
            "OR: helpers(MyHelpersModule)"
        else
          raise Exceptions::ValidationFailed,
            "Argument to #helpers must be a module. You gave #{module_name.inspect} (#{module_name.class})"
        end
      end

      # Compiles all helpers from inline method definitions, inline module
      # definitions, and external modules into an Array of Modules. The context
      # object for the template is extended with these modules to provide
      # per-resource template logic.
      def helper_modules
        compiled_helper_methods + compiled_helper_modules + @helper_modules
      end

      private

      # compiles helper methods into a module that can be included in template context
      def compiled_helper_methods
        if inline_helper_blocks.empty?
          []
        else
          resource_helper_blocks = inline_helper_blocks
          helper_mod = Module.new do
            resource_helper_blocks.each do |method_name, method_body|
              define_method(method_name, &method_body)
            end
          end
          [ helper_mod ]
        end
      end

      def compiled_helper_modules
        @inline_helper_modules.map do |module_body|
          Module.new(&module_body)
        end
      end

    end
  end
end
