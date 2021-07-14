#
# Author:: Bryan McLellan <btm@loftninjas.org>
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

require "knife_spec_helper"
require "chef/knife/core/windows_bootstrap_context"
describe Chef::Knife::Core::WindowsBootstrapContext do
  let(:config) { {} }
  let(:chef_config) { Chef::Config.save } # "dup" to a hash
  let(:bootstrap_context) { Chef::Knife::Core::WindowsBootstrapContext.new(config, nil, chef_config, nil) }

  describe "fips" do
    context "when fips is set" do
      before do
        chef_config[:fips] = true
      end

      it "sets fips mode in the client.rb" do
        expect(bootstrap_context.config_content).to match(/fips true/)
      end
    end

    context "when fips is not set" do
      before do
        chef_config[:fips] = false
      end

      it "sets fips mode in the client.rb" do
        expect(bootstrap_context.config_content).not_to match(/fips true/)
      end
    end
  end

  describe "trusted_certs_script" do
    let(:mock_cert_dir) { ::File.absolute_path(::File.join("spec", "assets", "fake_trusted_certs")) }
    let(:script_output) { bootstrap_context.trusted_certs_script }
    let(:crt_files) { ::Dir.glob(::File.join(mock_cert_dir, "*.crt")) }
    let(:pem_files) { ::Dir.glob(::File.join(mock_cert_dir, "*.pem")) }
    let(:other_files) { ::Dir.glob(::File.join(mock_cert_dir, "*")) - crt_files - pem_files }

    before do
      bootstrap_context.instance_variable_set(:@chef_config, Mash.new(trusted_certs_dir: mock_cert_dir))
    end

    it "should echo every .crt file in the trusted_certs directory" do
      crt_files.each do |f|
        echo_file = ::File.read(f).gsub(/^/, "echo.")
        expect(script_output).to include(::File.join("trusted_certs", ::File.basename(f)))
        expect(script_output).to include(echo_file)
      end
    end

    it "should echo every .pem file in the trusted_certs directory" do
      pem_files.each do |f|
        echo_file = ::File.read(f).gsub(/^/, "echo.")
        expect(script_output).to include(::File.join("trusted_certs", ::File.basename(f)))
        expect(script_output).to include(echo_file)
      end
    end

    it "should not echo files which aren't .crt or .pem files" do
      other_files.each do |f|
        echo_file = ::File.read(f).gsub(/^/, "echo.")
        expect(script_output).to_not include(::File.join("trusted_certs", ::File.basename(f)))
        expect(script_output).to_not include(echo_file)
      end
    end
  end

  describe "validation_key" do
    before do
      bootstrap_context.instance_variable_set(:@chef_config, Mash.new(validation_key: "C:\\chef\\key.pem"))
    end

    it "should return false if validation_key does not exist" do
      allow(::File).to receive(:expand_path).with("C:\\chef\\key.pem").and_call_original
      allow(::File).to receive(:exist?).and_return(false)
      expect(bootstrap_context.validation_key).to eq(false)
    end
  end

  describe "#get_log_location" do

    context "when config_log_location value is nil" do
      it "sets STDOUT in client.rb as default" do
        bootstrap_context.instance_variable_set(:@chef_config, Mash.new(config_log_location: nil))
        expect(bootstrap_context.get_log_location).to eq("STDOUT\n")
      end
    end

    context "when config_log_location value is empty" do
      it "sets STDOUT in client.rb as default" do
        bootstrap_context.instance_variable_set(:@chef_config, Mash.new(config_log_location: ""))
        expect(bootstrap_context.get_log_location).to eq("STDOUT\n")
      end
    end

    context "when config_log_location value is STDOUT" do
      it "sets STDOUT in client.rb" do
        bootstrap_context.instance_variable_set(:@chef_config, Mash.new(config_log_location: STDOUT))
        expect(bootstrap_context.get_log_location).to eq("STDOUT\n")
      end
    end

    context "when config_log_location value is STDERR" do
      it "sets STDERR in client.rb" do
        bootstrap_context.instance_variable_set(:@chef_config, Mash.new(config_log_location: STDERR))
        expect(bootstrap_context.get_log_location).to eq("STDERR\n")
      end
    end

    context "when config_log_location value is path to a file" do
      it "sets file path in client.rb" do
        bootstrap_context.instance_variable_set(:@chef_config, Mash.new(config_log_location: "C:\\chef\\chef.log"))
        expect(bootstrap_context.get_log_location).to eq("\"C:\\chef\\chef.log\"\n")
      end
    end

    context "when config_log_location value is :win_evt" do
      it "sets :win_evt in client.rb" do
        bootstrap_context.instance_variable_set(:@chef_config, Mash.new(config_log_location: :win_evt))
        expect(bootstrap_context.get_log_location).to eq(":win_evt\n")
      end
    end

    context "when config_log_location value is :syslog" do
      it "raise error with message and exit" do
        bootstrap_context.instance_variable_set(:@chef_config, Mash.new(config_log_location: :syslog))
        expect { bootstrap_context.get_log_location }.to raise_error("syslog is not supported for log_location on Windows OS\n")
      end
    end

  end

  describe "#config_content" do
    before do
      bootstrap_context.instance_variable_set(
        :@chef_config, Mash.new(
          config_log_level: :info,
          config_log_location: STDOUT,
          chef_server_url: "http://chef.example.com:4444",
          validation_client_name: "chef-validator-testing",
          windows_bootstrap_file_cache_path: "c:/chef/cache",
          windows_bootstrap_file_backup_path: "c:/chef/backup",
          cache_options: ({ path: "c:/chef/cache/checksums", skip_expires: true })
        )
      )
    end

    it "generates the config file data" do
      expected = <<~EXPECTED
        echo.chef_server_url  "http://chef.example.com:4444"
        echo.validation_client_name "chef-validator-testing"
        echo.file_cache_path   "c:/chef/cache"
        echo.file_backup_path  "c:/chef/backup"
        echo.cache_options     ^({:path =^> "C:\\\\chef\\\\cache\\\\checksums", :skip_expires =^> true}^)
        echo.# Using default node name ^(fqdn^)
        echo.log_level :info
        echo.log_location       STDOUT
      EXPECTED
      expect(bootstrap_context.config_content).to eq expected
    end

    describe "when chef_license is set" do
      before do
        bootstrap_context.instance_variable_set(:@chef_config, Mash.new(chef_license: "accept-no-persist"))
      end
      it "sets chef_license in the generated config file" do
        expect(bootstrap_context.config_content).to include("chef_license \"accept-no-persist\"")
      end
    end
  end

  describe "#start_chef" do
    it "returns the expected string" do
      expect(bootstrap_context.start_chef).to eq(
        <<~EOH
          SET "PATH=%SYSTEM32%;%SystemRoot%;%SYSTEM32%\\Wbem;%SYSTEM32%\\WindowsPowerShell\\v1.0\\;C:\\ruby\\bin;C:\\opscode\\chef\\bin;C:\\opscode\\chef\\embedded\\bin;%PATH%"
          chef-client -c C:\\chef\\client.rb -j C:\\chef\\first-boot.json
        EOH
      )
    end
  end

  describe "msi_url" do
    context "when msi_url config option is not set" do
      let(:config) { { channel: "stable" } }
      before do
        expect(bootstrap_context).to receive(:version_to_install).and_return("something")
      end

      it "returns a chef.io msi url with minimal url parameters" do
        reference_url = "https://omnitruck.chef.io/chef/download?p=windows&channel=stable&v=something"
        expect(bootstrap_context.msi_url).to eq(reference_url)
      end

      it "returns a chef.io msi url with provided url parameters substituted" do
        reference_url = "https://omnitruck.chef.io/chef/download?p=windows&pv=machine&m=arch&DownloadContext=ctx&channel=stable&v=something"
        expect(bootstrap_context.msi_url("machine", "arch", "ctx")).to eq(reference_url)
      end

      context "when a channel is provided in config" do
        let(:config) { { channel: "current" } }
        it "returns a chef.io msi url with the requested channel" do
          reference_url = "https://omnitruck.chef.io/chef/download?p=windows&channel=current&v=something"
          expect(bootstrap_context.msi_url).to eq(reference_url)
        end
      end
    end

    context "when msi_url config option is set" do
      let(:custom_url) { "file://something" }
      let(:config) { { msi_url: custom_url, install: true } }

      it "returns the overridden url" do
        expect(bootstrap_context.msi_url).to eq(custom_url)
      end

      it "doesn't introduce any unnecessary query parameters if provided by the template" do
        expect(bootstrap_context.msi_url("machine", "arch", "ctx")).to eq(custom_url)
      end
    end
  end
end
