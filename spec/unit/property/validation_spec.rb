require "support/shared/integration/integration_helper"

describe "Chef::Resource.property validation" do
  include IntegrationSupport

  module Namer
    @i = 0
    def self.next_resource_name
      "chef_resource_property_spec_#{@i += 1}"
    end

    def self.reset_index
      @current_index = 0
    end

    def self.current_index
      @current_index
    end

    def self.next_index
      @current_index += 1
    end
  end

  def lazy(&block)
    Chef::DelayedEvaluator.new(&block)
  end

  before do
    Namer.reset_index
  end

  def self.new_resource_name
    Namer.next_resource_name
  end

  let(:resource_class) do
    new_resource_name = self.class.new_resource_name
    Class.new(Chef::Resource) do
      resource_name new_resource_name
      def blah
        Namer.next_index
      end

      def self.blah
        "class#{Namer.next_index}"
      end

      action :doit do
        # this needs to not reference any properties
      end

      action :doit2 do
        # this needs to not reference any properties
      end
    end
  end

  let(:node) { Chef::Node.new }
  let(:events) { Chef::EventDispatch::Dispatcher.new }
  let(:run_context) { Chef::RunContext.new(node, {}, events) }
  let(:resource) do
    resource_class.new("blah", run_context)
  end

  def self.english_join(values)
    return "<nothing>" if values.size == 0
    return values[0].inspect if values.size == 1

    "#{values[0..-2].map(&:inspect).join(", ")} and #{values[-1].inspect}"
  end

  def self.with_property(*properties, &block)
    tags_index = properties.find_index { |p| !p.is_a?(String) }
    if tags_index
      properties, tags = properties[0..tags_index - 1], properties[tags_index..-1]
    else
      tags = []
    end
    properties = properties.map { |property| "property #{property}" }
    context "With properties #{english_join(properties)}", *tags do
      before do
        properties.each do |property_str|
          resource_class.class_eval(property_str, __FILE__, __LINE__)
        end
      end
      instance_eval(&block)
    end
  end

  def self.validation_test(validation, success_values, failure_values, *tags)
    with_property ":x, #{validation}", *tags do
      it "gets nil when retrieving the initial (non-set) value" do
        expect(resource.x).to be_nil
      end
      success_values.each do |v|
        it "value #{v.inspect} is valid" do
          resource.instance_eval { @x = "default" }
          expect(resource.x v).to eq v
          expect(resource.x).to eq v
        end
      end
      failure_values.each do |v|
        it "value #{v.inspect} is invalid" do
          expect { resource.x v }.to raise_error Chef::Exceptions::ValidationFailed
          resource.instance_eval { @x = "default" }
          expect { resource.x v }.to raise_error Chef::Exceptions::ValidationFailed
        end
      end
      it "setting x to nil when it is already nil does not emit a warning" do
        expect(resource.x nil).to be_nil
        expect(resource.x).to be_nil
      end
      unless tags.include?(:nillable)
        it "changing x to nil does a set" do
          resource.instance_eval { @x = "default" }
          expect(resource.x nil).to eq nil
          expect(resource.x).to eq nil
        end
      end
    end
    if tags.include?(:nil_is_valid)
      with_property ":x, #{validation}, default: nil" do
        it "setting x to nil when it is already nil does not emit a warning" do
          expect(resource.x nil).to be_nil
          expect(resource.x).to be_nil
        end
        it "changing x to nil does a set" do
          resource.instance_eval { @x = "default" }
          expect(resource.x nil).to eq nil
          expect(resource.x).to eq nil
        end
      end
    elsif tags.include?(:nillable)
      with_property ":x, #{validation}, nillable: true" do
        it "changing x to nil with nillable true overwrites defaults and just works" do
          resource.instance_eval { @x = "default" }
          expect { resource.x nil }.not_to raise_error
          expect(resource.x nil).to eq nil
          expect(resource.x).to eq nil
        end
      end
    elsif tags.include?(:delayed_nil_default_failure)
      it "property :x, #{validation}, default: nil warns that the default is invalid" do
        expect { resource_class.class_eval("property :x, #{validation}, default: nil", __FILE__, __LINE__) }.not_to raise_error
        expect { resource.x }.to raise_error Chef::Exceptions::ValidationFailed, /Property x must be one of: .*  You passed nil./
      end
    elsif tags.include?(:skip_nil_default)
      # intentionally left blank
    else
      it "property :x, #{validation}, default: nil warns that the default is invalid" do
        expect { resource_class.class_eval("property :x, #{validation}, default: nil", __FILE__, __LINE__) }.to raise_error Chef::Exceptions::ValidationFailed,
          /Property x must be one of: .*  You passed nil./
      end
    end
  end

  context "basic get, set, and nil set" do
    with_property ":x, kind_of: String" do
      context "when the variable already has a value" do
        before do
          resource.instance_eval { @x = "default" }
        end
        it "get succeeds" do
          expect(resource.x).to eq "default"
        end
        it "set to valid value succeeds" do
          expect(resource.x "str").to eq "str"
          expect(resource.x).to eq "str"
        end
        it "set to invalid value raises ValidationFailed" do
          expect { resource.x 10 }.to raise_error Chef::Exceptions::ValidationFailed
        end
        it "set to nil does a set" do
          resource.x "str"
          expect(resource.x nil).to eq nil
          expect(resource.x).to eq nil
        end
      end
      context "when the variable does not have an initial value" do
        it "get succeeds" do
          expect(resource.x).to be_nil
        end
        it "set to valid value succeeds" do
          expect(resource.x "str").to eq "str"
          expect(resource.x).to eq "str"
        end
        it "set to invalid value raises ValidationFailed" do
          expect { resource.x 10 }.to raise_error Chef::Exceptions::ValidationFailed
        end
        it "set to nil emits no warning because the value would not change" do
          expect(resource.x nil).to be_nil
        end
      end
    end
    with_property ":x, [ String, nil ]" do
      context "when the variable already has a value" do
        before do
          resource.instance_eval { @x = "default" }
        end
        it "get succeeds" do
          expect(resource.x).to eq "default"
        end
        it "set(nil) does a set" do
          expect(resource.x nil).to eq nil
          expect(resource.x).to eq nil
        end
        it "set to valid value succeeds" do
          expect(resource.x "str").to eq "str"
          expect(resource.x).to eq "str"
        end
        it "set to invalid value raises ValidationFailed" do
          expect { resource.x 10 }.to raise_error Chef::Exceptions::ValidationFailed
        end
      end
      context "when the variable does not have an initial value" do
        it "get succeeds" do
          expect(resource.x).to be_nil
        end
        it "set(nil) sets the value" do
          expect(resource.x nil).to be_nil
          expect(resource.x).to be_nil
        end
        it "set to valid value succeeds" do
          expect(resource.x "str").to eq "str"
          expect(resource.x).to eq "str"
        end
        it "set to invalid value raises ValidationFailed" do
          expect { resource.x 10 }.to raise_error Chef::Exceptions::ValidationFailed
        end
      end
    end
  end

  # Bare types
  context "bare types" do
    validation_test "String",
      [ "hi" ],
      [ 10 ]

    validation_test ":a",
      [ :a ],
      [ :b ]

    validation_test ":a, is: :b",
      %i{a b},
      [ :c ]

    validation_test ":a, is: [ :b, :c ]",
      %i{a b c},
      [ :d ]

    validation_test "[ :a, :b ], is: :c",
      %i{a b c},
      [ :d ]

    validation_test "[ :a, :b ], is: [ :c, :d ]",
      %i{a b c d},
      [ :e ]

    validation_test "nil",
      [ ],
      [ :a ],
      :nil_is_valid

    validation_test "[ nil ]",
      [ ],
      [ :a ],
      :nil_is_valid

    validation_test "[]",
      [],
      [ :a ]

    validation_test "[ String, nil ], nillable: true",
      [ nil, "thing" ],
      [ :nope, false ],
      :nillable
  end

  # is
  context "is" do
    # Class
    validation_test "is: String",
      [ "a", "" ],
      [ :a, 1 ]

    # Value
    validation_test "is: :a",
      [ :a ],
      [ :b ]

    validation_test "is: [ :a, :b ]",
      %i{a b},
      [ %i{a b} ]

    validation_test "is: [ [ :a, :b ] ]",
      [ %i{a b} ],
      %i{a b}

    # Regex
    validation_test "is: /abc/",
      %w{abc wowabcwow},
      [ "", "abac" ]

    # Property
    validation_test "is: Chef::Property.new(is: :a)",
      [ :a ],
      [ :b ]

    # RSpec Matcher
    class Globalses
      extend RSpec::Matchers
    end

    validation_test "is: Globalses.eq(10)",
      [ 10 ],
      [ 1 ]

    # Proc
    validation_test "is: proc { |x| x }",
      [ true, 1 ],
      [ false ],
      # this is somewhat complicated, we test adding `default: nil` and that the default fails, but with a proc the
      # validation is delayed until access, so we have to test after access not after declaring the default
      :delayed_nil_default_failure

    validation_test "is: proc { |x| x > blah }",
      [ 10 ],
      [ -1 ],
      # here the test of adding `default: nil` just causes the proc to explode because nil gets passed to the proc
      # which throws a NoMethodError on NilClass for the `>` method.
      :skip_nil_default

    validation_test "is: nil",
      [ ],
      [ "a" ],
      :nil_is_valid

    validation_test "is: [ String, nil ]",
      [ "a" ],
      [ :b ],
      :nil_is_valid

    validation_test "is: []",
      [],
      [ :a ]
  end

  # Combination
  context "combination" do
    validation_test 'kind_of: String, equal_to: "a"',
      [ "a" ],
      [ "b" ],
      :nil_is_valid
  end

  # equal_to
  context "equal_to" do
    # Value
    validation_test "equal_to: :a",
      [ :a ],
      [ :b ],
      :nil_is_valid

    validation_test "equal_to: [ :a, :b ]",
      %i{a b},
      [ %i{a b} ],
      :nil_is_valid

    validation_test "equal_to: [ [ :a, :b ] ]",
      [ %i{a b} ],
      %i{a b},
      :nil_is_valid

    validation_test "equal_to: nil",
      [ ],
      [ "a" ],
      :nil_is_valid

    validation_test 'equal_to: [ "a", nil ]',
      [ "a" ],
      [ "b" ],
      :nil_is_valid

    validation_test 'equal_to: [ nil, "a" ]',
      [ "a" ],
      [ "b" ],
      :nil_is_valid

    validation_test "equal_to: []",
      [],
      [ :a ],
      :nil_is_valid

  end

  # kind_of
  context "kind_of" do
    validation_test "kind_of: String",
      [ "a" ],
      [ :b ],
      :nil_is_valid

    validation_test "kind_of: [ String, Symbol ]",
      [ "a", :b ],
      [ 1 ],
      :nil_is_valid

    validation_test "kind_of: [ Symbol, String ]",
      [ "a", :b ],
      [ 1 ],
      :nil_is_valid

    validation_test "kind_of: NilClass",
      [ ],
      [ "a" ],
      :nil_is_valid

    validation_test "kind_of: [ NilClass, String ]",
      [ "a" ],
      [ :a ],
      :nil_is_valid

    validation_test "kind_of: []",
      [],
      [ :a ],
      :nil_is_valid

    validation_test "kind_of: nil",
      [],
      [ :a ],
      :nil_is_valid
  end

  # regex
  context "regex" do
    validation_test "regex: /abc/",
      [ "xabcy" ],
      [ "gbh", 123 ],
      :nil_is_valid

    validation_test "regex: [ /abc/, /z/ ]",
      %w{xabcy aza},
      [ "gbh", 123 ],
      :nil_is_valid

    validation_test "regex: [ /z/, /abc/ ]",
      %w{xabcy aza},
      [ "gbh", 123 ],
      :nil_is_valid

    validation_test "regex: [ [ /z/, /abc/ ], [ /n/ ] ]",
      %w{xabcy aza ana},
      [ "gbh", 123 ],
      :nil_is_valid

    validation_test "regex: []",
      [],
      [ :a ],
      :nil_is_valid

    validation_test "regex: nil",
      [],
      [ :a ],
      :nil_is_valid
  end

  # callbacks
  context "callbacks" do
    validation_test 'callbacks: { "a" => proc { |x| x > 10 }, "b" => proc { |x| x%2 == 0 } }',
      [ 12 ],
      [ 11, 4 ],
      :nil_is_valid

    validation_test 'callbacks: { "a" => proc { |x| x%2 == 0 }, "b" => proc { |x| x > 10 } }',
      [ 12 ],
      [ 11, 4 ],
      :nil_is_valid

    validation_test 'callbacks: { "a" => proc { |x| x.nil? } }',
      [ ],
      [ "a" ],
      :nil_is_valid

    validation_test "callbacks: {}",
      [ :a ],
      [],
      :nil_is_valid
  end

  # respond_to
  context "respond_to" do
    validation_test "respond_to: :split",
      [ "hi" ],
      [ 1 ],
      :nil_is_valid

    validation_test 'respond_to: "split"',
      [ "hi" ],
      [ 1 ],
      :nil_is_valid

    validation_test "respond_to: :to_s",
      [ :a ],
      [],
      :nil_is_valid

    validation_test "respond_to: [ :split, :to_s ]",
      [ "hi" ],
      [ 1 ],
      :nil_is_valid

    validation_test "respond_to: %w(split to_s)",
      [ "hi" ],
      [ 1 ],
      :nil_is_valid

    validation_test "respond_to: [ :to_s, :split ]",
      [ "hi" ],
      [ 1 ],
      :nil_is_valid

    validation_test "respond_to: []",
      [ :a ],
      [],
      :nil_is_valid

    validation_test "respond_to: nil",
      [ :a ],
      [],
      :nil_is_valid
  end

  context "cannot_be" do
    validation_test "cannot_be: :empty",
      [ 1, [1, 2], { a: 10 } ],
      [ [] ],
      :nil_is_valid

    validation_test 'cannot_be: "empty"',
      [ 1, [1, 2], { a: 10 } ],
      [ [] ],
      :nil_is_valid

    validation_test "cannot_be: [ :empty, :nil ]",
      [ 1, [1, 2], { a: 10 } ],
      [ [] ],
      :nil_is_valid

    validation_test 'cannot_be: [ "empty", "nil" ]',
      [ 1, [1, 2], { a: 10 } ],
      [ [] ],
      :nil_is_valid

    validation_test "cannot_be: [ :nil, :empty ]",
      [ 1, [1, 2], { a: 10 } ],
      [ [] ],
      :nil_is_valid

    validation_test "cannot_be: [ :empty, :nil, :blahblah ]",
      [ 1, [1, 2], { a: 10 } ],
      [ [] ],
      :nil_is_valid

    validation_test "cannot_be: []",
      [ :a ],
      [],
      :nil_is_valid

    validation_test "cannot_be: nil",
      [ :a ],
      [],
      :nil_is_valid

  end

  context "required" do
    with_property ":x, required: true" do
      it "if x is not specified, retrieval fails" do
        expect { resource.x }.to raise_error Chef::Exceptions::ValidationFailed
      end
      it "value 1 is valid" do
        expect(resource.x 1).to eq 1
        expect(resource.x).to eq 1
      end
      it "value nil emits a validation failed error because it must have a value" do
        expect { resource.x nil }.to raise_error Chef::Exceptions::ValidationFailed
      end
      it "fails if it is not specified, on running the action, even if it is not referenced" do
        expect { resource.run_action(:doit) }.to raise_error Chef::Exceptions::ValidationFailed
      end
    end

    with_property ":x, required: %i{doit}" do
      it "fails if it is not specified, on running the doit action, even if it is not referenced" do
        expect { resource.run_action(:doit) }.to raise_error Chef::Exceptions::ValidationFailed
      end

      it "does not fail if it is not specified, on running the doit2 action" do
        expect { resource.run_action(:doit2) }.not_to raise_error
      end

      context "when an action does not require it" do
        before do
          resource.action(:doit2)
        end

        it "retrieval succeeds if x is not set when resource uses the doit2 action" do
          expect { resource.x }.not_to raise_error
        end

        it "succeeds with set to nil when resource uses the doit2 action" do
          expect { resource.x nil }.not_to raise_error
        end
      end

      context "when an action requires it" do
        before do
          # NOTE: this is already the default action, but it doesn't
          # hurt to be clear about the situation.
          resource.action(:doit)
        end

        it "if x is not specified, retrieval fails for the doit action" do
          expect { resource.x }.to raise_error Chef::Exceptions::ValidationFailed
        end

        it "value nil is not valid for the doit action (required means 'not nil')" do
          expect { resource.x nil }.to raise_error Chef::Exceptions::ValidationFailed
        end
      end
    end

    with_property ":x, String, required: true" do
      it "if x is not specified, retrieval fails" do
        expect { resource.x }.to raise_error Chef::Exceptions::ValidationFailed
      end
      it "value nil is not valid (required means 'not nil')" do
        expect { resource.x nil }.to raise_error Chef::Exceptions::ValidationFailed
      end
      it "value '1' is valid" do
        expect(resource.x "1").to eq "1"
        expect(resource.x).to eq "1"
      end
      it "value 1 is invalid" do
        expect { resource.x 1 }.to raise_error Chef::Exceptions::ValidationFailed
      end
    end

    with_property ":x, [String, nil], required: true" do
      it "if x is not specified, retrieval fails" do
        expect { resource.x }.to raise_error Chef::Exceptions::ValidationFailed
      end
      it "value nil is not valid (required means 'not nil')" do
        expect { resource.x nil }.to raise_error Chef::Exceptions::ValidationFailed
      end
      it "value '1' is valid" do
        expect(resource.x "1").to eq "1"
        expect(resource.x).to eq "1"
      end
      it "value 1 is invalid" do
        expect { resource.x 1 }.to raise_error Chef::Exceptions::ValidationFailed
      end
    end

    with_property ":x, name_property: true, required: true" do
      it "if x is not specified, the name property is returned" do
        expect(resource.x).to eq "blah"
      end
      it "value 1 is valid" do
        expect(resource.x 1).to eq 1
        expect(resource.x).to eq 1
      end
      it "value nil sets to the default" do
        # this mildly complicated because the default of a name property is a lazy evaluator to the actual resource.name
        expect(resource.x nil).to be_a(Chef::DelayedEvaluator)
      end
    end

    with_property ":x, default: 10, required: true" do
      it "if x is not specified, the default is returned" do
        expect(resource.x).to eq 10
      end
      it "value 1 is valid" do
        expect(resource.x 1).to eq 1
        expect(resource.x).to eq 1
      end
      it "value nil sets the default" do
        expect(resource.x nil).to eq 10
        expect(resource.x).to eq 10
      end
    end
  end

  context "nil setting default" do
    with_property ":x, String" do
      it "if x is not specified, the default is returned" do
        expect(resource.x).to eq nil
      end
      it "value '2' is valid" do
        expect(resource.x "2").to eq "2"
        expect(resource.x).to eq "2"
      end
      it "value nil sets the default" do
        resource.x "2"
        expect(resource.x nil).to eq nil
        expect(resource.x).to eq nil
      end
    end
    with_property ":x, String, default: '1'" do
      it "if x is not specified, the default is returned" do
        expect(resource.x).to eq "1"
      end
      it "value '2' is valid" do
        expect(resource.x "2").to eq "2"
        expect(resource.x).to eq "2"
      end
      it "value nil sets the default" do
        resource.x "2"
        expect(resource.x nil).to eq "1"
        expect(resource.x).to eq "1"
      end
    end
    with_property ":x, [ String, nil ] , default: '1'" do
      it "if x is not specified, the default is returned" do
        expect(resource.x).to eq "1"
      end
      it "value '2' is valid" do
        expect(resource.x "2").to eq "2"
        expect(resource.x).to eq "2"
      end
      it "value nil sets to nil" do
        resource.x "2"
        expect(resource.x nil).to eq nil
        expect(resource.x).to eq nil
      end
    end
  end

  context "custom validators (def _pv_blarghle)" do
    before do
      Chef::Config[:treat_deprecation_warnings_as_errors] = false
    end

    with_property ":x, blarghle: 1" do
      context "and a class that implements _pv_blarghle" do
        before do
          resource_class.class_eval do
            def _pv_blarghle(opts, key, value)
              if _pv_opts_lookup(opts, key) != value
                raise Chef::Exceptions::ValidationFailed, "ouch"
              end
            end
          end
        end

        it "value 1 is valid" do
          expect(resource.x 1).to eq 1
          expect(resource.x).to eq 1
        end

        it "value '1' is invalid" do
          expect { resource.x "1" }.to raise_error Chef::Exceptions::ValidationFailed
        end

        it "value nil does a set" do
          resource.x 1
          resource.x nil
          expect(resource.x).to eq nil
        end
      end
    end

    with_property ":x, blarghle: 1" do
      context "and a class that implements _pv_blarghle" do
        before do
          resource_class.class_eval do
            def _pv_blarghle(opts, key, value)
              if _pv_opts_lookup(opts, key) != value
                raise Chef::Exceptions::ValidationFailed, "ouch"
              end
            end
          end
        end

        it "value 1 is valid" do
          expect(resource.x 1).to eq 1
          expect(resource.x).to eq 1
        end

        it "value '1' is invalid" do
          expect { resource.x "1" }.to raise_error Chef::Exceptions::ValidationFailed
        end

        it "value nil does a set" do
          resource.x 1
          resource.x nil
          expect(resource.x).to eq nil
        end
      end
    end
  end

  context "custom validation messages" do
    with_property ":x, String, validation_message: 'Must be a string, fool'" do
      it "raise with the correct error message" do
        expect { resource.x 1 }.to raise_error Chef::Exceptions::ValidationFailed,
          "Must be a string, fool"
      end
    end
  end
end
