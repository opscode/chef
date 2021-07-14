#
# Author:: Daniel DeLeo (<dan@chef.io>)
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

require "spec_helper"
require "chef/cookbook/syntax_check"

describe Chef::Cookbook::SyntaxCheck do
  before do
    allow(ChefUtils).to receive(:windows?) { false }
  end

  let(:cookbook_path) { File.join(CHEF_SPEC_DATA, "cookbooks", "openldap") }
  let(:unsafe_cookbook_path) { 'C:\AGENT-HOME\xml-data\build-dir\76808194-76906499\artifact\cookbooks/java' }
  let(:syntax_check) { Chef::Cookbook::SyntaxCheck.new(cookbook_path) }

  let(:open_ldap_cookbook_files) do
    %w{ attributes/default.rb
        attributes/smokey.rb
        definitions/client.rb
        definitions/server.rb
        libraries/openldap.rb
        libraries/openldap/version.rb
        metadata.rb
        recipes/default.rb
        recipes/gigantor.rb
        recipes/one.rb
        recipes/return.rb
        spec/spec_helper.rb }.map { |f| File.join(cookbook_path, f) }
  end

  before do
    Chef::Log.logger = Logger.new(StringIO.new)
    @original_log_level = Chef::Log.level
    Chef::Log.level = :warn # suppress "Syntax OK" messages

    @attr_files = %w{default.rb smokey.rb}.map { |f| File.join(cookbook_path, "attributes", f) }
    @libr_files = %w{openldap.rb openldap/version.rb}.map { |f| File.join(cookbook_path, "libraries", f) }
    @defn_files = %w{client.rb server.rb}.map { |f| File.join(cookbook_path, "definitions", f) }
    @recipes = %w{default.rb gigantor.rb one.rb return.rb}.map { |f| File.join(cookbook_path, "recipes", f) }
    @spec_files = [ File.join(cookbook_path, "spec", "spec_helper.rb") ]
    @ruby_files = @attr_files + @libr_files + @defn_files + @recipes + @spec_files + [File.join(cookbook_path, "metadata.rb")]
    @basenames = %w{ helpers_via_partial_test.erb
                    helper_test.erb
                    helpers.erb
                    openldap_stuff.conf.erb
                    nested_openldap_partials.erb
                    nested_partial.erb
                    openldap_nested_variable_stuff.erb
                    openldap_variable_stuff.conf.erb
                    test.erb
                    some_windows_line_endings.erb
                    all_windows_line_endings.erb
                    no_windows_line_endings.erb }
    @template_files = @basenames.map { |f| File.join(cookbook_path, "templates", "default", f) }
  end

  after do
    Chef::Log.level = @original_log_level
  end

  it "creates a syntax checker given the cookbook name when Chef::Config.cookbook_path is set" do
    Chef::Config[:cookbook_path] = File.dirname(cookbook_path)
    syntax_check = Chef::Cookbook::SyntaxCheck.for_cookbook(:openldap)
    expect(syntax_check.cookbook_path).to eq(cookbook_path)
    expect(syntax_check.ruby_files.sort).to eq(open_ldap_cookbook_files.sort)
  end

  it "creates a syntax checker given the cookbook name and cookbook_path" do
    syntax_check = Chef::Cookbook::SyntaxCheck.for_cookbook(:openldap, File.join(CHEF_SPEC_DATA, "cookbooks"))
    expect(syntax_check.cookbook_path).to eq(cookbook_path)
    expect(syntax_check.ruby_files.sort).to eq(open_ldap_cookbook_files.sort)
  end

  context "when using a standalone cookbook" do
    let(:cookbook_path) { File.join(CHEF_SPEC_DATA, "standalone_cookbook") }

    it "creates a syntax checker given the cookbook name and cookbook_path for a standalone cookbook" do
      syntax_check = Chef::Cookbook::SyntaxCheck.for_cookbook(:standalone_cookbook, CHEF_SPEC_DATA)
      expect(syntax_check.cookbook_path).to eq(cookbook_path)
      expect(syntax_check.ruby_files).to eq([File.join(cookbook_path, "recipes/default.rb")])
    end
  end

  it "safely handles a path containing control characters" do
    syntax_check = Chef::Cookbook::SyntaxCheck.new(unsafe_cookbook_path)
    expect { syntax_check.remove_uninteresting_ruby_files(@basenames) }.not_to raise_error
  end

  describe "when first created" do
    it "has the path to the cookbook to syntax check" do
      expect(syntax_check.cookbook_path).to eq(cookbook_path)
    end

    it "lists the ruby files in the cookbook" do
      expect(syntax_check.ruby_files.sort).to eq(@ruby_files.sort)
    end

    it "lists the erb templates in the cookbook" do
      expect(syntax_check.template_files.sort).to eq(@template_files.sort)
    end

  end

  describe "when validating cookbooks" do
    let(:cache_path) { Dir.mktmpdir }

    before do
      Chef::Config[:syntax_check_cache_path] = cache_path
    end

    after do
      FileUtils.rm_rf(cache_path) if File.exist?(cache_path)
    end

    describe "and the files have not been syntax checked previously" do
      it "shows that all ruby files require a syntax check" do
        expect(syntax_check.untested_ruby_files.sort).to eq(@ruby_files.sort)
      end

      it "shows that all template files require a syntax check" do
        expect(syntax_check.untested_template_files.sort).to eq(@template_files.sort)
      end

      it "removes a ruby file from the list of untested files after it is marked as validated" do
        recipe = File.join(cookbook_path, "recipes", "default.rb")
        syntax_check.validated(recipe)
        expect(syntax_check.untested_ruby_files).not_to include(recipe)
      end

      it "removes a template file from the list of untested files after it is marked as validated" do
        template = File.join(cookbook_path, "templates", "default", "test.erb")
        syntax_check.validated(template)
        expect(syntax_check.untested_template_files).not_to include(template)
      end

      it "validates all ruby files" do
        expect(syntax_check.validate_ruby_files).to be_truthy
        expect(syntax_check.untested_ruby_files).to be_empty
      end

      it "validates all templates" do
        expect(syntax_check.validate_templates).to be_truthy
        expect(syntax_check.untested_template_files).to be_empty
      end

      describe "and a file has a syntax error" do

        before do
          cookbook_path = File.join(CHEF_SPEC_DATA, "cookbooks", "borken")
          syntax_check.cookbook_path.replace(cookbook_path)
        end

        it "it indicates that a ruby file has a syntax error" do
          expect(Chef::Log).to receive(:fatal).with("Cookbook file borken/recipes/default.rb has a ruby syntax error.")
          allow(Chef::Log).to receive(:fatal)
          expect(syntax_check.validate_ruby_files).to be_falsey
        end

        it "does not remove the invalid file from the list of untested files" do
          expect(syntax_check.untested_ruby_files).to include(File.join(cookbook_path, "recipes", "default.rb"))
          syntax_check.validate_ruby_files
          expect(syntax_check.untested_ruby_files).to include(File.join(cookbook_path, "recipes", "default.rb"))
        end

        it "indicates that a template file has a syntax error" do
          expect(syntax_check.validate_templates).to be_falsey
        end

        it "does not remove the invalid template from the list of untested templates" do
          expect(syntax_check.untested_template_files).to include(File.join(cookbook_path, "templates", "default", "borken.erb"))
          expect { syntax_check.validate_templates }.not_to change(syntax_check, :untested_template_files)
        end

      end

      describe "and an ignored file has a syntax error" do
        before do
          cookbook_path = File.join(CHEF_SPEC_DATA, "cookbooks", "ignorken")
          Chef::Config[:cookbook_path] = File.dirname(cookbook_path)
          syntax_check.cookbook_path.replace(cookbook_path)
          @ruby_files = [File.join(cookbook_path, "metadata.rb"), File.join(cookbook_path, "recipes/default.rb")]
        end

        it "shows that ignored ruby files do not require a syntax check" do
          expect(syntax_check.untested_ruby_files.sort).to eq(@ruby_files.sort)
        end

        it "does not indicate that a ruby file has a syntax error" do
          expect(syntax_check.validate_ruby_files).to be_truthy
          expect(syntax_check.untested_ruby_files).to be_empty
        end

      end

    end

    describe "and the files have been syntax checked previously" do
      before do
        syntax_check.untested_ruby_files.each { |f| syntax_check.validated(f) }
        syntax_check.untested_template_files.each { |f| syntax_check.validated(f) }
      end

      it "does not syntax check ruby files" do
        expect(syntax_check).not_to receive(:shell_out)
        expect(syntax_check.validate_ruby_files).to be_truthy
      end

      it "does not syntax check templates" do
        expect(syntax_check).not_to receive(:shell_out)
        expect(syntax_check.validate_templates).to be_truthy
      end
    end
  end
end
