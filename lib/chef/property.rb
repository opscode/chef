#
# Author:: John Keiser <jkeiser@chef.io>
# Copyright:: Copyright 2015-2016, John Keiser
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

require_relative "exceptions"
require_relative "delayed_evaluator"
require_relative "chef_class"
require_relative "log"

class Chef
  #
  # Type and validation information for a property on a resource.
  #
  # A property named "x" manipulates the "@x" instance variable on a
  # resource.  The *presence* of the variable (`instance_variable_defined?(@x)`)
  # tells whether the variable is defined; it may have any actual value,
  # constrained only by validation.
  #
  # Properties may have validation, defaults, and coercion, and have full
  # support for lazy values.
  #
  # @see Chef::Resource.property
  # @see Chef::DelayedEvaluator
  #
  class Property
    #
    # Create a reusable property type that can be used in multiple properties
    # in different resources.
    #
    # @param options [Hash<Symbol,Object>] Validation options. See Chef::Resource.property for
    #   the list of options.
    #
    # @example
    #   Property.derive(default: 'hi')
    #
    def self.derive(**options)
      new(**options)
    end

    # This is to support #deprecated_property_alias, by emitting an alias and a
    # deprecation warning when called.
    #
    # @param from [String] Name of the deprecated property
    # @param to [String] Name of the correct property
    # @param message [String] Deprecation message to show to the cookbook author
    # @param declared_in [Class] Class this property comes from
    #
    def self.emit_deprecated_alias(from, to, message, declared_in)
      declared_in.class_eval <<-EOM, __FILE__, __LINE__ + 1
        def #{from}(value=NOT_PASSED)
          Chef.deprecated(:property, "#{message}")
          #{to}(value)
        end
        def #{from}=(value)
          Chef.deprecated(:property, "#{message}")
          #{to} = value
        end
      EOM
    end

    #
    # Create a new property.
    #
    # @param options [Hash<Symbol,Object>] Property options, including
    #   control options here, as well as validation options (see
    #   Chef::Mixin::ParamsValidate#validate for a description of validation
    #   options).
    #   @option options [Symbol] :name The name of this property.
    #   @option options [Class] :declared_in The class this property comes from.
    #   @option options [String] :description A description of the property.
    #   @option options [Symbol] :instance_variable_name The instance variable
    #     tied to this property. Must include a leading `@`. Defaults to `@<name>`.
    #     `nil` means the property is opaque and not tied to a specific instance
    #     variable.
    #   @option options [String] :introduced The release that introduced this property
    #   @option options [Boolean] :desired_state `true` if this property is part of desired
    #     state. Defaults to `true`.
    #   @option options [Boolean] :identity `true` if this property is part of object
    #     identity. Defaults to `false`.
    #   @option options [Boolean] :name_property `true` if this
    #     property defaults to the same value as `name`. Equivalent to
    #     `default: lazy { name }`, except that #property_is_set? will
    #     return `true` if the property is set *or* if `name` is set.
    #   @option options [Boolean] :nillable `true` opt-in to Chef-13 style behavior where
    #     attempting to set a nil value will really set a nil value instead of issuing
    #     a warning and operating like a getter [DEPRECATED]
    #   @option options [Object] :default The value this property
    #     will return if the user does not set one. If this is `lazy`, it will
    #     be run in the context of the instance (and able to access other
    #     properties) and cached. If not, the value will be frozen with Object#freeze
    #     to prevent users from modifying it in an instance.
    #   @option options [String] :default_description The description of the default value
    #     used in docs. Particularly useful when a default is computed or lazily eval'd.
    #   @option options [Boolean] :skip_docs This property should not be included in any
    #     documentation output
    #   @option options [Proc] :coerce A proc which will be called to
    #     transform the user input to canonical form. The value is passed in,
    #     and the transformed value returned as output. Lazy values will *not*
    #     be passed to this method until after they are evaluated. Called in the
    #     context of the resource (meaning you can access other properties).
    #   @option options [Boolean] :required `true` if this property
    #     must be present; `false` otherwise. This is checked after the resource
    #     is fully initialized.
    #   @option options [String] :deprecated If set, this property is deprecated and
    #     will create a deprecation warning.
    #
    def initialize(**options)
      options = options.inject({}) { |memo, (key, value)| memo[key.to_sym] = value; memo }
      @options = options
      options[:name] = options[:name].to_sym if options[:name]
      options[:instance_variable_name] = options[:instance_variable_name].to_sym if options[:instance_variable_name]

      # Replace name_attribute with name_property
      if options.key?(:name_attribute)
        # If we have both name_attribute and name_property and they differ, raise an error
        if options.key?(:name_property)
          raise ArgumentError, "name_attribute and name_property are functionally identical and both cannot be specified on a property at once. Use just one on property #{self}"
        end

        # replace name_property with name_attribute in place
        options = Hash[options.map { |k, v| k == :name_attribute ? [ :name_property, v ] : [ k, v ] }]
        @options = options
      end

      if options.key?(:default) && options.key?(:name_property)
        raise ArgumentError, "A property cannot be both a name_property/name_attribute and have a default value. Use one or the other on property #{self}"
      end

      if options[:name_property]
        options[:desired_state] = false unless options.key?(:desired_state)
      end

      # Recursively freeze the default if it isn't a lazy value.
      unless default.is_a?(DelayedEvaluator)
        visitor = lambda do |obj|
          case obj
          when Hash
            obj.each_value { |value| visitor.call(value) }
          when Array
            obj.each { |value| visitor.call(value) }
          end
          obj.freeze
        end
        visitor.call(default)
      end

      # Validate the default early, so the user gets a good error message, and
      # cache it so we don't do it again if so
      begin
        # If we can validate it all the way to output, do it.
        @stored_default = input_to_stored_value(nil, default, is_default: true)
      rescue Chef::Exceptions::CannotValidateStaticallyError
        # If the validation is not static (i.e. has procs), we will have to
        # coerce and validate the default each time we run
      end
    end

    def to_s
      "#{name || "<property type>"}#{declared_in ? " of resource #{declared_in.resource_name}" : ""}"
    end

    #
    # The name of this property.
    #
    # @return [String]
    #
    def name
      options[:name]
    end

    #
    # The class this property was defined in.
    #
    # @return [Class]
    #
    def declared_in
      options[:declared_in]
    end

    #
    # A description of this property.
    #
    # @return [String]
    #
    def description
      options[:description]
    end

    #
    # When this property was introduced
    #
    # @return [String]
    #
    def introduced
      options[:introduced]
    end

    #
    # The instance variable associated with this property.
    #
    # Defaults to `@<name>`
    #
    # @return [Symbol]
    #
    def instance_variable_name
      if options.key?(:instance_variable_name)
        options[:instance_variable_name]
      elsif name
        :"@#{name}"
      end
    end

    #
    # The raw default value for this resource.
    #
    # Does not coerce or validate the default. Does not evaluate lazy values.
    #
    # Defaults to `lazy { name }` if name_property is true; otherwise defaults to
    # `nil`
    #
    def default
      return options[:default] if options.key?(:default)
      return Chef::DelayedEvaluator.new { name } if name_property?

      nil
    end

    #
    # A description of the default value of this property.
    #
    # @return [String]
    #
    def default_description
      options[:default_description]
    end

    #
    # The equal_to field of this property.
    #
    # @return [Array, NilClass]
    #
    def equal_to
      options[:equal_to]
    end

    #
    # Whether this is part of the resource's natural identity or not.
    #
    # @return [Boolean]
    #
    def identity?
      options[:identity]
    end

    #
    # Whether this is part of desired state or not.
    #
    # Defaults to true.
    #
    # @return [Boolean]
    #
    def desired_state?
      return true unless options.key?(:desired_state)

      options[:desired_state]
    end

    #
    # Whether this is name_property or not.
    #
    # @return [Boolean]
    #
    def name_property?
      options[:name_property]
    end

    #
    # Whether this property has a default value.
    #
    # @return [Boolean]
    #
    def has_default?
      options.key?(:default) || name_property?
    end

    #
    # Whether this property is required or not.
    #
    # @return [Boolean]
    #
    def required?(action = nil)
      if !action.nil? && options[:required].is_a?(Array)
        (options[:required] & Array(action)).any?
      else
        !!options[:required]
      end
    end

    #
    # Whether this property should be skipped for documentation purposes.
    #
    # Defaults to false.
    #
    # @return [Boolean]
    #
    def skip_docs?
      options.fetch(:skip_docs, false)
    end

    #
    # Whether this property is sensitive or not.
    #
    # Defaults to false.
    #
    # @return [Boolean]
    #
    def sensitive?
      options.fetch(:sensitive, false)
    end

    #
    # Validation options.  (See Chef::Mixin::ParamsValidate#validate.)
    #
    # @return [Hash<Symbol,Object>]
    #
    def validation_options
      @validation_options ||= options.reject do |k, v|
        %i{declared_in name instance_variable_name desired_state identity default name_property coerce required nillable sensitive description introduced deprecated default_description skip_docs}.include?(k)
      end
    end

    #
    # Handle the property being called.
    #
    # The base implementation does the property get-or-set:
    #
    # ```ruby
    # resource.myprop # get
    # resource.myprop value # set
    # ```
    #
    # Subclasses may implement this with any arguments they want, as long as
    # the corresponding DSL calls it correctly.
    #
    # @param resource [Chef::Resource] The resource to get the property from.
    # @param value The value to set (or NOT_PASSED if it is a get).
    #
    # @return The current value of the property. If it is a `set`, lazy values
    #   will be returned without running, validating or coercing. If it is a
    #   `get`, the non-lazy, coerced, validated value will always be returned.
    #
    def call(resource, value = NOT_PASSED)
      if NOT_PASSED == value # see https://github.com/chef/chef/pull/8781 before changing this
        get(resource)
      else
        set(resource, value)
      end
    end

    #
    # Get the property value from the resource, handling lazy values,
    # defaults, and validation.
    #
    # - If the property's value is lazy, it is evaluated, coerced and validated.
    # - If the property has no value, and is required, raises ValidationFailed.
    # - If the property has no value, but has a lazy default, it is evaluated,
    #   coerced and validated. If the evaluated value is frozen, the resulting
    # - If the property has no value, but has a default, the default value
    #   will be returned and frozen. If the default value is lazy, it will be
    #   evaluated, coerced and validated, and the result stored in the property.
    # - If the property has no value, but is name_property, `resource.name`
    #   is retrieved, coerced, validated and stored in the property.
    # - Otherwise, `nil` is returned.
    #
    # @param resource [Chef::Resource] The resource to get the property from.
    #
    # @return The value of the property.
    #
    # @raise Chef::Exceptions::ValidationFailed If the value is invalid for
    #   this property, or if the value is required and not set.
    #
    def get(resource, nil_set: false)
      # If it's set, return it (and evaluate any lazy values)
      value = nil

      if is_set?(resource)
        value = get_value(resource)
        value = stored_value_to_output(resource, value)
      else
        # We are getting the default value.

        if has_default?
          # If we were able to cache the stored_default, grab it.
          if defined?(@stored_default)
            value = @stored_default
          else
            # Otherwise, we have to validate it now.
            value = input_to_stored_value(resource, default, is_default: true)
          end
          value = deep_dup(value)
          value = stored_value_to_output(resource, value)

          # If the value is mutable (non-frozen), we set it on the instance
          # so that people can mutate it.  (All constant default values are
          # frozen.)
          if !value.frozen? && !value.nil?
            set_value(resource, value)
          end
        end
      end

      action = resource.respond_to?(:action) ? resource.action : nil

      if value.nil? && required?(action)
        raise Chef::Exceptions::ValidationFailed, "#{name} is a required property"
      else
        value
      end
    end

    #
    # Set the value of this property in the given resource.
    #
    # Non-lazy values are coerced and validated before being set. Coercion
    # and validation of lazy values is delayed until they are first retrieved.
    #
    # @param resource [Chef::Resource] The resource to set this property in.
    # @param value The value to set.
    #
    # @return The value that was set, after coercion (if lazy, still returns
    #   the lazy value)
    #
    # @raise Chef::Exceptions::ValidationFailed If the value is invalid for
    #   this property.
    #
    def set(resource, value)
      value = set_value(resource, input_to_stored_value(resource, value))

      if options.key?(:deprecated)
        Chef.deprecated(:property, options[:deprecated])
      end

      action = resource.respond_to?(:action) ? resource.action : nil

      if value.nil? && required?(action)
        raise Chef::Exceptions::ValidationFailed, "#{name} is a required property"
      else
        value
      end
    end

    #
    # Find out whether this property has been set.
    #
    # This will be true if:
    # - The user explicitly set the value
    # - The property has a default, and the value was retrieved.
    #
    # From this point of view, it is worth looking at this as "what does the
    # user think this value should be." In order words, if the user grabbed
    # the value, even if it was a default, they probably based calculations on
    # it. If they based calculations on it and the value changes, the rest of
    # the world gets inconsistent.
    #
    # @param resource [Chef::Resource] The resource to get the property from.
    #
    # @return [Boolean]
    #
    def is_set?(resource)
      value_is_set?(resource)
    end

    #
    # Reset the value of this property so that is_set? will return false and the
    # default will be returned in the future.
    #
    # @param resource [Chef::Resource] The resource to get the property from.
    #
    def reset(resource)
      reset_value(resource)
    end

    #
    # Coerce an input value into canonical form for the property.
    #
    # After coercion, the value is suitable for storage in the resource.
    # You must validate values after coercion, however.
    #
    # Does no special handling for lazy values.
    #
    # @param resource [Chef::Resource] The resource we're coercing against
    #   (to provide context for the coerce).
    # @param value The value to coerce.
    #
    # @return The coerced value.
    #
    # @raise Chef::Exceptions::ValidationFailed If the value is invalid for
    #   this property.
    #
    def coerce(resource, value)
      if options.key?(:coerce)
        # nil is never coerced
        unless value.nil?
          value = exec_in_resource(resource, options[:coerce], value)
        end
      end
      value
    end

    #
    # Validate a value.
    #
    # Calls Chef::Mixin::ParamsValidate#validate with #validation_options as
    # options.
    #
    # @param resource [Chef::Resource] The resource we're validating against
    #   (to provide context for the validation).
    # @param value The value to validate.
    #
    # @raise Chef::Exceptions::ValidationFailed If the value is invalid for
    #   this property.
    #
    def validate(resource, value)
      # nils are not validated unless we have an explicit default value
      if !value.nil? || has_default?
        if resource
          resource.validate({ name => value }, { name => validation_options })
        else
          name = self.name || :property_type
          Chef::Mixin::ParamsValidate.validate({ name => value }, { name => validation_options })
        end
      end
    end

    #
    # Derive a new Property that is just like this one, except with some added or
    # changed options.
    #
    # @param options [Hash<Symbol,Object>] List of options that would be passed
    #   to #initialize.
    #
    # @return [Property] The new property type.
    #
    def derive(**modified_options)
      # Since name_property, name_attribute and default override each other,
      # if you specify one of them in modified_options it overrides anything in
      # the original options.
      options = self.options
      if modified_options.key?(:name_property) ||
          modified_options.key?(:name_attribute) ||
          modified_options.key?(:default)
        options = options.reject { |k, v| %i{name_attribute name_property default}.include?(k) }
      end
      self.class.new(**options.merge(modified_options))
    end

    #
    # Emit the DSL for this property into the resource class (`declared_in`).
    #
    # Creates a getter and setter for the property.
    #
    def emit_dsl
      # We don't create the getter/setter if it's a custom property; we will
      # be using the existing getter/setter to manipulate it instead.
      return unless instance_variable_name

      # Properties may override existing properties up the inheritance hierarchy, but
      # properties must not override inherited methods like Object#hash.  When the Resource is
      # placed into the resource collection the ruby Hash object will call the
      # Object#hash method on the resource, and overriding that with a property will cause
      # very confusing results.
      if property_redefines_method?
        resource_name = declared_in.respond_to?(:resource_name) ? declared_in.resource_name : declared_in
        raise ArgumentError, "Property `#{name}` of resource `#{resource_name}` overwrites an existing method. A different name should be used for this property."
      end

      # We prefer this form because the property name won't show up in the
      # stack trace if you use `define_method`.
      declared_in.class_eval <<-EOM, __FILE__, __LINE__ + 1
        def #{name}(value=NOT_PASSED)
          raise "Property `#{name}` of `\#{self}` was incorrectly passed a block. Possible property-resource collision. To call a resource named `#{name}` either rename the property or else use `declare_resource(:#{name}, ...)`" if block_given?
          self.class.properties[#{name.inspect}].call(self, value)
        end
        def #{name}=(value)
          raise "Property `#{name}` of `\#{self}` was incorrectly passed a block. Possible property-resource collision. To call a resource named `#{name}` either rename the property or else use `declare_resource(:#{name}, ...)`" if block_given?
          self.class.properties[#{name.inspect}].set(self, value)
        end
      EOM
    end

    #
    # The options this Property will use for get/set behavior and validation.
    #
    # @see #initialize for a list of valid options.
    #
    attr_reader :options

    #
    # Find out whether this type accepts nil explicitly.
    #
    # A type accepts nil explicitly if "is" allows nil, it validates as nil, *and* is not simply
    # an empty type.
    #
    # A type is presumed to accept nil if it does coercion (which must handle nil).
    #
    # These examples accept nil explicitly:
    # ```ruby
    # property :a, [ String, nil ]
    # property :a, [ String, NilClass ]
    # property :a, [ String, proc { |v| v.nil? } ]
    # ```
    #
    # This does not (because the "is" doesn't exist or doesn't have nil):
    #
    # ```ruby
    # property :x, String
    # ```
    #
    # These do not, even though nil would validate fine (because they do not
    # have "is"):
    #
    # ```ruby
    # property :a
    # property :a, equal_to: [ 1, 2, 3, nil ]
    # property :a, kind_of: [ String, NilClass ]
    # property :a, respond_to: [ ]
    # property :a, callbacks: { "a" => proc { |v| v.nil? } }
    # ```
    #
    # @param resource [Chef::Resource] The resource we're coercing against
    #   (to provide context for the coerce).
    #
    # @return [Boolean] Whether this value explicitly accepts nil.
    #
    # @api private
    def explicitly_accepts_nil?(resource)
      options.key?(:coerce) ||
        (options.key?(:is) && Chef::Mixin::ParamsValidate.send(:_pv_is, { name => nil }, name, options[:is]))
    rescue Chef::Exceptions::ValidationFailed, Chef::Exceptions::CannotValidateStaticallyError
      false
    end

    # @api private
    def get_value(resource)
      if instance_variable_name
        resource.instance_variable_get(instance_variable_name)
      else
        resource.send(name)
      end
    end

    # @api private
    def set_value(resource, value)
      if instance_variable_name
        resource.instance_variable_set(instance_variable_name, value)
      else
        resource.send(name, value)
      end
    end

    # @api private
    def value_is_set?(resource)
      if instance_variable_name
        resource.instance_variable_defined?(instance_variable_name)
      else
        true
      end
    end

    # @api private
    def reset_value(resource)
      if instance_variable_name
        if value_is_set?(resource)
          resource.remove_instance_variable(instance_variable_name)
        end
      else
        raise ArgumentError, "Property #{name} has no instance variable defined and cannot be reset"
      end
    end

    private

    def property_redefines_method?
      # We only emit deprecations if this property already exists as an instance method.
      # Weeding out class methods avoids unnecessary deprecations such Chef::Resource
      # defining a `name` property when there's an already-existing `name` method
      # for a Module.
      return false unless declared_in.instance_methods.include?(name)

      # Only emit deprecations for some well-known classes. This will still
      # allow more advanced users to subclass their own custom resources and
      # override their own properties.
      return false unless [ Object, BasicObject, Kernel, Chef::Resource ].include?(declared_in.instance_method(name).owner)

      # Allow top-level Chef::Resource properties, such as `name`, to be overridden.
      # As of this writing, `name` is the only Chef::Resource property created with the
      # `property` definition, but this will allow for future properties to be extended
      # as needed.
      !Chef::Resource.properties.key?(name)
    end

    def exec_in_resource(resource, proc, *args)
      if resource
        if proc.arity > args.size
          value = proc.call(resource, *args)
        else
          value = resource.instance_exec(*args, &proc)
        end
      else
        # If we don't have a resource yet, we can't exec in resource!
        raise Chef::Exceptions::CannotValidateStaticallyError, "Cannot validate or coerce without a resource"
      end
    end

    def input_to_stored_value(resource, value, is_default: false)
      if value.nil? && !is_default && !explicitly_accepts_nil?(resource)
        value = default
      end
      unless value.is_a?(DelayedEvaluator)
        value = coerce_and_validate(resource, value)
      end
      value
    end

    def stored_value_to_output(resource, value)
      # Crack open lazy values before giving the result to the user
      if value.is_a?(DelayedEvaluator)
        value = exec_in_resource(resource, value)
        value = coerce_and_validate(resource, value)
      end
      value
    end

    # Coerces and validates the value.
    def coerce_and_validate(resource, value)
      result = coerce(resource, value)
      validate(resource, result)

      result
    end

    # recursively dup the value
    def deep_dup(value)
      return value if value.is_a?(DelayedEvaluator)

      visitor = lambda do |obj|
        obj = obj.dup rescue obj
        case obj
        when Hash
          obj.each { |k, v| obj[k] = visitor.call(v) }
        when Array
          obj.each_with_index { |v, i| obj[i] = visitor.call(v) }
        end
        obj
      end
      visitor.call(value)
    end
  end
end
