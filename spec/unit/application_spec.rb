#
# Author:: AJ Christensen (<aj@junglist.gen.nz>)
# Author:: Mark Mzyk (mmzyk@opscode.com)
# Copyright:: Copyright (c) 2008 Opscode, Inc.
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

require 'spec_helper'

describe Chef::Application do
  before do
    @original_argv = ARGV.dup
    ARGV.clear
    Chef::Log.logger = Logger.new(StringIO.new)
    @app = Chef::Application.new
    Dir.stub(:chdir).and_return(0)
    @app.stub(:reconfigure)
    Chef::Log.init(STDERR)
  end

  after do
    ARGV.replace(@original_argv)
  end

  describe "reconfigure" do
    before do
      @app = Chef::Application.new
      @app.stub(:configure_chef).and_return(true)
      @app.stub(:configure_logging).and_return(true)
    end

    it "should configure chef" do
      @app.should_receive(:configure_chef).and_return(true)
      @app.reconfigure
    end

    it "should configure logging" do
      @app.should_receive(:configure_logging).and_return(true)
      @app.reconfigure
    end

  end

  describe Chef::Application do
    before do
      @app = Chef::Application.new
    end

    describe "run" do
      before do
        @app.stub(:setup_application).and_return(true)
        @app.stub(:run_application).and_return(true)
        @app.stub(:configure_chef).and_return(true)
        @app.stub(:configure_logging).and_return(true)
      end

      it "should reconfigure the application before running" do
        @app.should_receive(:reconfigure).and_return(true)
        @app.run
      end

      it "should setup the application before running it" do
        @app.should_receive(:setup_application).and_return(true)
        @app.run
      end

      it "should run the actual application" do
        @app.should_receive(:run_application).and_return(true)
        @app.run
      end
    end
  end

  describe "configure_chef" do
    before do
      @app = Chef::Application.new
      #Chef::Config.stub(:merge!).and_return(true)
      @app.stub(:parse_options).and_return(true)
    end

    it "should parse the commandline options" do
      @app.should_receive(:parse_options).and_return(true)
      @app.config[:config_file] = "/etc/chef/default.rb" #have a config file set, to prevent triggering error block
      @app.configure_chef
    end

    describe "when a config_file is present" do
      let(:config_content) { "rspec_ran('true')" }
      let(:config_location) { "/etc/chef/default.rb" }

      let(:config_location_pathname) do
        p = Pathname.new(config_location)
        p.stub(:realpath).and_return(config_location)
        p
      end

      before do
        @app.config[:config_file] = config_location
        Pathname.stub(:new).with(config_location).and_return(config_location_pathname)
        File.should_receive(:read).
          with(config_location).
          and_return(config_content)
      end

      it "should configure chef::config from a file" do
        Chef::Config.should_receive(:from_string).with(config_content, config_location)
        @app.configure_chef
      end

      it "should merge the local config hash into chef::config" do
        #File.should_receive(:open).with("/etc/chef/default.rb").and_yield(@config_file)
        @app.configure_chef
        Chef::Config.rspec_ran.should == "true"
      end

    end

    describe "when there is no config_file defined" do
      before do
        @app.config[:config_file] = nil
      end

      it "should emit a warning" do
        Chef::Config.should_not_receive(:from_file).with("/etc/chef/default.rb")
        Chef::Log.should_receive(:warn).with("No config file found or specified on command line, using command line options.")
        @app.configure_chef
      end
    end

    describe "when the config file is set and not found" do
      before do
        @app.config[:config_file] = "/etc/chef/notfound"
      end
      it "should use the passed in command line options and defaults" do
        Chef::Config.should_receive(:merge!)
        @app.configure_chef
      end
    end
  end

  describe "when configuring the logger" do
    before do
      @app = Chef::Application.new
      Chef::Log.stub(:init)
    end

    it "should initialise the chef logger" do
      Chef::Log.stub(:level=)
      @monologger = double("Monologger")
      MonoLogger.should_receive(:new).with(Chef::Config[:log_location]).and_return(@monologger)
      Chef::Log.should_receive(:init).with(@monologger)
      @app.configure_logging
    end

    it "should raise fatals if log location is invalid" do
      Chef::Config[:log_location] = "/tmp/non-existing-dir/logfile"
      Chef::Log.should_receive(:fatal).at_least(:once)
      Process.should_receive(:exit)
      @app.configure_logging
    end

    shared_examples_for "log_level_is_auto" do
      context "when STDOUT is to a tty" do
        before do
          STDOUT.stub(:tty?).and_return(true)
        end

        it "configures the log level to :warn" do
          @app.configure_logging
          Chef::Log.level.should == :warn
        end

        context "when force_logger is configured" do
          before do
            Chef::Config[:force_logger] = true
          end

          it "configures the log level to info" do
            @app.configure_logging
            Chef::Log.level.should == :info
          end
        end
      end

      context "when STDOUT is not to a tty" do
        before do
          STDOUT.stub(:tty?).and_return(false)
        end

        it "configures the log level to :info" do
          @app.configure_logging
          Chef::Log.level.should == :info
        end

        context "when force_formatter is configured" do
          before do
            Chef::Config[:force_formatter] = true
          end
          it "sets the log level to :warn" do
            @app.configure_logging
            Chef::Log.level.should == :warn
          end
        end
      end
    end

    context "when log_level is not set" do
      it_behaves_like "log_level_is_auto"
    end

    context "when log_level is :auto" do
      before do
        Chef::Config[:log_level] = :auto
      end

      it_behaves_like "log_level_is_auto"
    end
  end

  describe "class method: fatal!" do
    before do
      STDERR.stub(:puts).with("FATAL: blah").and_return(true)
      Chef::Log.stub(:fatal).and_return(true)
      Process.stub(:exit).and_return(true)
    end

    it "should log an error message to the logger" do
      Chef::Log.should_receive(:fatal).with("blah").and_return(true)
      Chef::Application.fatal! "blah"
    end

    describe "when an exit code is supplied" do
      it "should exit with the given exit code" do
        Process.should_receive(:exit).with(-100).and_return(true)
        Chef::Application.fatal! "blah", -100
      end
    end

    describe "when an exit code is not supplied" do
      it "should exit with the default exit code" do
        Process.should_receive(:exit).with(-1).and_return(true)
        Chef::Application.fatal! "blah"
      end
    end

  end

  describe "setup_application" do
    before do
      @app = Chef::Application.new
    end

    it "should raise an error" do
      lambda { @app.setup_application }.should raise_error(Chef::Exceptions::Application)
    end
  end

  describe "run_application" do
    before do
      @app = Chef::Application.new
    end

    it "should raise an error" do
      lambda { @app.run_application }.should raise_error(Chef::Exceptions::Application)
    end
  end

  context "when the config file is not available" do
    it "should warn for bad config file path" do
      @app.config[:config_file] = "/tmp/non-existing-dir/file"
      config_file_regexp = Regexp.new @app.config[:config_file]
      Chef::Log.should_receive(:warn).at_least(:once).with(config_file_regexp).and_return(true)
      Chef::Log.stub(:warn).and_return(true)
      @app.configure_chef
    end
  end

  describe "configuration errors" do
    before do
      Process.should_receive(:exit)
    end

    def raises_informative_fatals_on_configure_chef
      config_file_regexp = Regexp.new @app.config[:config_file]
      Chef::Log.should_receive(:fatal).
        with(/Configuration error/)
      Chef::Log.should_receive(:fatal).
        with(config_file_regexp).
        at_least(1).times
      @app.configure_chef
    end

    describe "when config file exists but contains errors" do
      def create_config_file(text)
        @config_file = Tempfile.new("rspec-chef-config")
        @config_file.write(text)
        @config_file.close
        @app.config[:config_file] = @config_file.path
      end

      after(:each) do
        @config_file.unlink
      end

      it "should raise informative fatals for badly written config" do
        create_config_file("text that should break the config parsing")
        raises_informative_fatals_on_configure_chef
      end
    end
  end
end
