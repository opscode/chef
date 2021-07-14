#
# Author:: AJ Christensen (<aj@junglist.gen.nz>)
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

require "knife_spec_helper"
require "#{CHEF_SPEC_DATA}/knife_subcommand/test_yourself"

describe Chef::Application::Knife do
  include SpecHelpers::Knife

  before(:all) do
    class NoopKnifeCommand < Chef::Knife
      option :opt_with_default,
        short: "-D VALUE",
        long: "-optwithdefault VALUE",
        default: "default-value"

      def run; end
    end
  end

  after(:each) do
    # reset some really nasty global state
    NoopKnifeCommand.reset_config_loader!
  end

  before(:each) do
    # Prevent code from getting loaded on every test invocation.
    allow(Chef::Knife).to receive(:load_commands)

    @knife = Chef::Application::Knife.new
    allow(@knife).to receive(:puts)
    allow(@knife).to receive(:trap)
    allow(Chef::Knife).to receive(:list_commands)
  end

  it "should exit 1 and print the options if no arguments are given at all" do
    with_argv([]) do
      expect { @knife.run }.to raise_error(SystemExit) { |e| expect(e.status).to eq(1) }
    end
  end

  it "should exit 2 if run without a sub command" do
    with_argv("--user", "adam") do
      expect(Chef::Log).to receive(:error).with(/you need to pass a sub\-command/i)
      expect { @knife.run }.to raise_error(SystemExit) { |e| expect(e.status).to eq(2) }
    end
  end

  it "should run a sub command with the applications command line option prototype" do
    with_argv(*%w{noop knife command with some args}) do
      knife = double(Chef::Knife)
      expect(Chef::Knife).to receive(:run).with(ARGV, @knife.options).and_return(knife)
      expect(@knife).to receive(:exit).with(0)
      @knife.run
    end
  end

  it "should set the colored output to true by default on windows and true on all other platforms as well" do
    with_argv(*%w{noop knife command}) do
      expect(@knife).to receive(:exit).with(0)
      @knife.run
    end
    expect(Chef::Config[:color]).to be_truthy
  end

  context "validate --format option" do
    it "should set the default format summary" do
      with_argv(*%w{noop knife command}) do
        expect(@knife).to receive(:exit).with(0)
        @knife.run
        expect(@knife.default_config[:format]).to eq("summary")
      end
    end

    it "should raise the error for invalid value" do
      with_argv(*%w{noop knife command -F abc}) do
        expect(STDOUT).to receive(:puts).at_least(2).times
        expect { @knife.run }.to raise_error(SystemExit) { |e| expect(e.status).to eq(2) }
      end
    end
  end

  context "when given fips flags" do
    context "when Chef::Config[:fips]=false" do
      before do
        # This is required because the chef-fips pipeline does
        # has a default value of true for fips
        Chef::Config[:fips] = false
      end

      it "does not initialize fips mode when no flags are passed" do
        with_argv(*%w{noop knife command}) do
          expect(@knife).to receive(:exit).with(0)
          expect(Chef::Config).not_to receive(:enable_fips_mode)
          @knife.run
          expect(Chef::Config[:fips]).to eq(false)
        end
      end

      it "overwrites the Chef::Config value when passed --fips" do
        with_argv(*%w{noop knife command --fips}) do
          expect(@knife).to receive(:exit).with(0)
          @knife.run
          expect(Chef::Config[:fips]).to eq(true)
        end
      end
    end

    context "when Chef::Config[:fips]=true" do
      before do
        Chef::Config[:fips] = true
      end

      it "initializes fips mode when passed --fips" do
        with_argv(*%w{noop knife command --fips}) do
          expect(@knife).to receive(:exit).with(0)
          @knife.run
          expect(Chef::Config[:fips]).to eq(true)
        end
      end

      it "overwrites the Chef::Config value when passed --no-fips" do
        with_argv(*%w{noop knife command --no-fips}) do
          expect(@knife).to receive(:exit).with(0)
          expect(Chef::Config).not_to receive(:enable_fips_mode)
          @knife.run
          expect(Chef::Config[:fips]).to eq(false)
        end
      end
    end
  end

  describe "when given a path to the client key" do
    it "expands a relative path relative to the CWD" do
      relative_path = ".chef/client.pem"
      allow(Dir).to receive(:pwd).and_return(CHEF_SPEC_DATA)
      with_argv(*%W{noop knife command -k #{relative_path}}) do
        expect(@knife).to receive(:exit).with(0)
        @knife.run
      end
      expect(Chef::Config[:client_key]).to eq(File.join(CHEF_SPEC_DATA, relative_path))
    end

    it "expands a ~/home/path to the correct full path" do
      home_path = "~/.chef/client.pem"
      with_argv(*%W{noop knife command -k #{home_path}}) do
        expect(@knife).to receive(:exit).with(0)
        @knife.run
      end
      expect(Chef::Config[:client_key]).to eq(File.join(ENV["HOME"], ".chef/client.pem").gsub((File::ALT_SEPARATOR || "\\"), File::SEPARATOR))
    end

    it "does not expand a full path" do
      full_path = if windows?
                    "C:/chef/client.pem"
                  else
                    "/etc/chef/client.pem"
                  end
      with_argv(*%W{noop knife command -k #{full_path}}) do
        expect(@knife).to receive(:exit).with(0)
        @knife.run
      end
      expect(Chef::Config[:client_key]).to eq(full_path)
    end
  end

  describe "with environment configuration" do
    before do
      Chef::Config[:environment] = nil
    end

    it "should default to no environment" do
      with_argv(*%w{noop knife command}) do
        expect(@knife).to receive(:exit).with(0)
        @knife.run
      end
      expect(Chef::Config[:environment]).to eq(nil)
    end

    it "should load the environment from the config file" do
      config_file = File.join(CHEF_SPEC_DATA, "environment-config.rb")
      with_argv(*%W{noop knife command -c #{config_file}}) do
        expect(@knife).to receive(:exit).with(0)
        @knife.run
      end
      expect(Chef::Config[:environment]).to eq("production")
    end

    it "should load the environment from the CLI options" do
      with_argv(*%w{noop knife command -E development}) do
        expect(@knife).to receive(:exit).with(0)
        @knife.run
      end
      expect(Chef::Config[:environment]).to eq("development")
    end

    it "should override the config file environment with the CLI environment" do
      config_file = File.join(CHEF_SPEC_DATA, "environment-config.rb")
      with_argv(*%W{noop knife command -c #{config_file} -E override}) do
        expect(@knife).to receive(:exit).with(0)
        @knife.run
      end
      expect(Chef::Config[:environment]).to eq("override")
    end

    it "should override the config file environment with the CLI environment regardless of order" do
      config_file = File.join(CHEF_SPEC_DATA, "environment-config.rb")
      with_argv(*%W{noop knife command -E override -c #{config_file}}) do
        expect(@knife).to receive(:exit).with(0)
        @knife.run
      end
      expect(Chef::Config[:environment]).to eq("override")
    end

    it "should run a sub command with the applications command line option prototype" do
      with_argv(*%w{noop knife command with some args}) do
        knife = double(Chef::Knife)
        expect(Chef::Knife).to receive(:run).with(ARGV, @knife.options).and_return(knife)
        expect(@knife).to receive(:exit).with(0)
        @knife.run
      end
    end
  end

end
