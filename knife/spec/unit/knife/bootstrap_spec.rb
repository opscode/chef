#
# Author:: Ian Meyer (<ianmmeyer@gmail.com>)
# Copyright:: Copyright 2010-2016, Ian Meyer
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

Chef::Knife::Bootstrap.load_deps

describe Chef::Knife::Bootstrap do
  let(:bootstrap_template) { nil }
  let(:stderr) { StringIO.new }
  let(:bootstrap_cli_options) { [ ] }
  let(:linux_test) { true }
  let(:windows_test) { false }
  let(:linux_test) { false }
  let(:unix_test) { false }
  let(:ssh_test) { false }

  let(:connection) do
    double("TrainConnector",
      windows?: windows_test,
      linux?: linux_test,
      unix?: unix_test)
  end

  let(:knife) do
    Chef::Log.logger = Logger.new(StringIO.new)
    Chef::Config[:knife][:bootstrap_template] = bootstrap_template unless bootstrap_template.nil?

    k = Chef::Knife::Bootstrap.new(bootstrap_cli_options)
    allow(k.ui).to receive(:stderr).and_return(stderr)
    allow(k).to receive(:encryption_secret_provided_ignore_encrypt_flag?).and_return(false)
    allow(k).to receive(:connection).and_return connection
    k.merge_configs
    k
  end

  context "#check_license" do
    let(:acceptor) { instance_double(LicenseAcceptance::Acceptor) }

    before do
      expect(LicenseAcceptance::Acceptor).to receive(:new).and_return(acceptor)
    end

    describe "when a license is not required" do
      it "does not set the chef_license" do
        expect(acceptor).to receive(:license_required?).and_return(false)
        knife.check_license
        expect(Chef::Config[:chef_license]).to eq(nil)
      end
    end

    describe "when a license is required" do
      it "sets the chef_license" do
        expect(acceptor).to receive(:license_required?).and_return(true)
        expect(acceptor).to receive(:id_from_mixlib).and_return("id")
        expect(acceptor).to receive(:check_and_persist)
        expect(acceptor).to receive(:acceptance_value).and_return("accept-no-persist")
        knife.check_license
        expect(Chef::Config[:chef_license]).to eq("accept-no-persist")
      end
    end
  end

  context "#bootstrap_template" do
    it "should default to chef-full" do
      expect(knife.bootstrap_template).to be_a_kind_of(String)
      expect(File.basename(knife.bootstrap_template)).to eq("chef-full")
    end
  end

  context "#render_template - when using the chef-full default template" do
    let(:rendered_template) do
      knife.merge_configs
      knife.render_template
    end

    it "should render client.rb" do
      expect(rendered_template).to match("cat > /etc/chef/client.rb <<'EOP'")
      expect(rendered_template).to match("chef_server_url  \"https://localhost:443\"")
      expect(rendered_template).to match("validation_client_name \"chef-validator\"")
      expect(rendered_template).to match("log_location   STDOUT")
    end

    it "should render first-boot.json" do
      expect(rendered_template).to match("cat > /etc/chef/first-boot.json <<'EOP'")
      expect(rendered_template).to match('{"run_list":\[\]}')
    end

    context "and encrypted_data_bag_secret was provided" do
      it "should render encrypted_data_bag_secret file" do
        expect(knife).to receive(:encryption_secret_provided_ignore_encrypt_flag?).and_return(true)
        expect(knife).to receive(:read_secret).and_return("secrets")
        expect(rendered_template).to match("cat > /etc/chef/encrypted_data_bag_secret <<'EOP'")
        expect(rendered_template).to match('{"run_list":\[\]}')
        expect(rendered_template).to match(/secrets/)
      end
    end
  end

  context "with --bootstrap-vault-item" do
    let(:bootstrap_cli_options) { [ "--bootstrap-vault-item", "vault1:item1", "--bootstrap-vault-item", "vault1:item2", "--bootstrap-vault-item", "vault2:item1" ] }
    it "sets the knife config cli option correctly" do
      expect(knife.config[:bootstrap_vault_item]).to eq({ "vault1" => %w{item1 item2}, "vault2" => ["item1"] })
    end
  end

  context "with --bootstrap-preinstall-command" do
    command = "while sudo fuser /var/lib/dpkg/lock >/dev/null 2>&1; do\n   echo 'waiting for dpkg lock';\n   sleep 1;\n  done;"
    let(:bootstrap_cli_options) { [ "--bootstrap-preinstall-command", command ] }
    let(:rendered_template) do
      knife.merge_configs
      knife.render_template
    end
    it "configures the preinstall command in the bootstrap template correctly" do
      expect(rendered_template).to match(/command/)
    end
  end

  context "with --bootstrap-proxy" do
    let(:bootstrap_cli_options) { [ "--bootstrap-proxy", "1.1.1.1" ] }
    let(:rendered_template) do
      knife.merge_configs
      knife.render_template
    end
    it "configures the https_proxy environment variable in the bootstrap template correctly" do
      expect(rendered_template).to match(/https_proxy="1.1.1.1" export https_proxy/)
    end
  end

  context "with --bootstrap-no-proxy" do
    let(:bootstrap_cli_options) { [ "--bootstrap-no-proxy", "localserver" ] }
    let(:rendered_template) do
      knife.merge_configs
      knife.render_template
    end
    it "configures the https_proxy environment variable in the bootstrap template correctly" do
      expect(rendered_template).to match(/no_proxy="localserver" export no_proxy/)
    end
  end

  context "with :bootstrap_template and :template_file cli options" do
    let(:bootstrap_cli_options) { [ "--bootstrap-template", "my-template", "other-template" ] }

    it "should select bootstrap template" do
      expect(File.basename(knife.bootstrap_template)).to eq("my-template")
    end
  end

  context "when finding templates" do
    context "when :bootstrap_template config is set to a file" do
      context "that doesn't exist" do
        let(:bootstrap_template) { "/opt/blah/not/exists/template.erb" }

        it "raises an error" do
          expect { knife.find_template }.to raise_error(Errno::ENOENT)
        end
      end

      context "that exists" do
        let(:bootstrap_template) { File.expand_path(File.join(CHEF_SPEC_DATA, "bootstrap", "test.erb")) }

        it "loads the given file as the template" do
          expect(Chef::Log).to receive(:trace)
          expect(knife.find_template).to eq(File.expand_path(File.join(CHEF_SPEC_DATA, "bootstrap", "test.erb")))
        end
      end
    end

    context "when :bootstrap_template config is set to a template name" do
      let(:bootstrap_template) { "example" }

      let(:builtin_template_path) { File.expand_path(File.join(__dir__, "../../../lib/chef/knife/bootstrap/templates", "example.erb")) }

      let(:chef_config_dir_template_path) { "/knife/chef/config/bootstrap/example.erb" }

      let(:env_home_template_path) { "/env/home/.chef/bootstrap/example.erb" }

      let(:gem_files_template_path) { "/Users/schisamo/.rvm/gems/ruby-1.9.2-p180@chef-0.10/gems/knife-windows-0.5.4/lib/chef/knife/bootstrap/fake-bootstrap-template.erb" }

      def configure_chef_config_dir
        allow(Chef::Knife).to receive(:chef_config_dir).and_return("/knife/chef/config")
      end

      def configure_env_home
        allow(Chef::Util::PathHelper).to receive(:home).with(".chef", "bootstrap", "example.erb").and_yield(env_home_template_path)
      end

      def configure_gem_files
        allow(Gem).to receive(:find_files).and_return([ gem_files_template_path ])
      end

      before(:each) do
        expect(File).to receive(:exist?).with(bootstrap_template).and_return(false)
      end

      context "when file is available everywhere" do
        before do
          configure_chef_config_dir
          configure_env_home
          configure_gem_files

          expect(File).to receive(:exist?).with(builtin_template_path).and_return(true)
        end

        it "should load the template from built-in templates" do
          expect(knife.find_template).to eq(builtin_template_path)
        end
      end

      context "when file is available in chef_config_dir" do
        before do
          configure_chef_config_dir
          configure_env_home
          configure_gem_files

          expect(File).to receive(:exist?).with(builtin_template_path).and_return(false)
          expect(File).to receive(:exist?).with(chef_config_dir_template_path).and_return(true)

          it "should load the template from chef_config_dir" do
            knife.find_template.should eq(chef_config_dir_template_path)
          end
        end
      end

      context "when file is available in home directory" do
        before do
          configure_chef_config_dir
          configure_env_home
          configure_gem_files

          expect(File).to receive(:exist?).with(builtin_template_path).and_return(false)
          expect(File).to receive(:exist?).with(chef_config_dir_template_path).and_return(false)
          expect(File).to receive(:exist?).with(env_home_template_path).and_return(true)
        end

        it "should load the template from chef_config_dir" do
          expect(knife.find_template).to eq(env_home_template_path)
        end
      end

      context "when file is available in Gem files" do
        before do
          configure_chef_config_dir
          configure_env_home
          configure_gem_files

          expect(File).to receive(:exist?).with(builtin_template_path).and_return(false)
          expect(File).to receive(:exist?).with(chef_config_dir_template_path).and_return(false)
          expect(File).to receive(:exist?).with(env_home_template_path).and_return(false)
          expect(File).to receive(:exist?).with(gem_files_template_path).and_return(true)
        end

        it "should load the template from Gem files" do
          expect(knife.find_template).to eq(gem_files_template_path)
        end
      end

      context "when file is available in Gem files and home dir doesn't exist" do
        before do
          configure_chef_config_dir
          configure_gem_files
          allow(Chef::Util::PathHelper).to receive(:home).with(".chef", "bootstrap", "example.erb").and_return(nil)

          expect(File).to receive(:exist?).with(builtin_template_path).and_return(false)
          expect(File).to receive(:exist?).with(chef_config_dir_template_path).and_return(false)
          expect(File).to receive(:exist?).with(gem_files_template_path).and_return(true)
        end

        it "should load the template from Gem files" do
          expect(knife.find_template).to eq(gem_files_template_path)
        end
      end
    end
  end

  ["-t", "--bootstrap-template"].each do |t|
    context "when #{t} option is given in the command line" do
      it "sets the knife :bootstrap_template config" do
        knife.parse_options([t, "blahblah"])
        knife.merge_configs
        expect(knife.bootstrap_template).to eq("blahblah")
      end
    end
  end

  context "with run_list template" do
    let(:bootstrap_template) { File.expand_path(File.join(CHEF_SPEC_DATA, "bootstrap", "test.erb")) }

    it "should return an empty run_list" do
      expect(knife.render_template).to eq('{"run_list":[]}')
    end

    it "should have role[base] in the run_list" do
      knife.parse_options(["-r", "role[base]"])
      knife.merge_configs
      expect(knife.render_template).to eq('{"run_list":["role[base]"]}')
    end

    it "should have role[base] and recipe[cupcakes] in the run_list" do
      knife.parse_options(["-r", "role[base],recipe[cupcakes]"])
      knife.merge_configs
      expect(knife.render_template).to eq('{"run_list":["role[base]","recipe[cupcakes]"]}')
    end

    context "with bootstrap_attribute options" do
      let(:jsonfile) do
        file = Tempfile.new(["node", ".json"])
        File.open(file.path, "w") { |f| f.puts '{"foo":{"bar":"baz"}}' }
        file
      end

      it "should have foo => {bar => baz} in the first_boot from cli" do
        knife.parse_options(["-j", '{"foo":{"bar":"baz"}}'])
        knife.merge_configs
        expected_hash = FFI_Yajl::Parser.new.parse('{"foo":{"bar":"baz"},"run_list":[]}')
        actual_hash = FFI_Yajl::Parser.new.parse(knife.render_template)
        expect(actual_hash).to eq(expected_hash)
      end

      it "should have foo => {bar => baz} in the first_boot from file" do
        knife.parse_options(["--json-attribute-file", jsonfile.path])
        knife.merge_configs
        expected_hash = FFI_Yajl::Parser.new.parse('{"foo":{"bar":"baz"},"run_list":[]}')
        actual_hash = FFI_Yajl::Parser.new.parse(knife.render_template)
        expect(actual_hash).to eq(expected_hash)
        jsonfile.close
      end

      it "raises a Chef::Exceptions::BootstrapCommandInputError with the proper error message" do
        knife.parse_options(["-j", '{"foo":{"bar":"baz"}}'])
        knife.parse_options(["--json-attribute-file", jsonfile.path])
        knife.merge_configs
        allow(knife).to receive(:validate_name_args!)
        expect(knife).to receive(:check_license)

        expect { knife.run }.to raise_error(Chef::Exceptions::BootstrapCommandInputError)
        jsonfile.close
      end
    end
  end

  context "with hints template" do
    let(:bootstrap_template) { File.expand_path(File.join(CHEF_SPEC_DATA, "bootstrap", "test-hints.erb")) }

    it "should create a hint file when told to" do
      knife.parse_options(["--hint", "openstack"])
      knife.merge_configs
      expect(knife.render_template).to match(%r{/etc/chef/ohai/hints/openstack.json})
    end

    it "should populate a hint file with JSON when given a file to read" do
      allow(::File).to receive(:read).and_return('{ "foo" : "bar" }')
      knife.parse_options(["--hint", "openstack=hints/openstack.json"])
      knife.merge_configs
      expect(knife.render_template).to match(/\{\"foo\":\"bar\"\}/)
    end
  end

  describe "specifying no_proxy with various entries" do
    subject(:knife) do
      k = described_class.new
      Chef::Config[:knife][:bootstrap_template] = template_file
      allow(k).to receive(:connection).and_return connection
      k.parse_options(options)
      k.merge_configs
      k
    end

    let(:options) { ["--bootstrap-no-proxy", setting] }

    let(:template_file) { File.expand_path(File.join(CHEF_SPEC_DATA, "bootstrap", "no_proxy.erb")) }

    let(:rendered_template) do
      knife.render_template
    end

    context "via --bootstrap-no-proxy" do
      let(:setting) { "api.opscode.com" }

      it "renders the client.rb with a single FQDN no_proxy entry" do
        expect(rendered_template).to match(/.*no_proxy\s*"api.opscode.com".*/)
      end
    end

    context "via --bootstrap-no-proxy multiple" do
      let(:setting) { "api.opscode.com,172.16.10.*" }

      it "renders the client.rb with comma-separated FQDN and wildcard IP address no_proxy entries" do
        expect(rendered_template).to match(/.*no_proxy\s*"api.opscode.com,172.16.10.\*".*/)
      end
    end

    context "via --ssl-verify-mode none" do
      let(:options) { ["--node-ssl-verify-mode", "none"] }

      it "renders the client.rb with ssl_verify_mode set to :verify_none" do
        expect(rendered_template).to match(/ssl_verify_mode :verify_none/)
      end
    end

    context "via --node-ssl-verify-mode peer" do
      let(:options) { ["--node-ssl-verify-mode", "peer"] }

      it "renders the client.rb with ssl_verify_mode set to :verify_peer" do
        expect(rendered_template).to match(/ssl_verify_mode :verify_peer/)
      end
    end

    context "via --node-ssl-verify-mode all" do
      let(:options) { ["--node-ssl-verify-mode", "all"] }

      it "raises error" do
        expect { rendered_template }.to raise_error(RuntimeError)
      end
    end

    context "via --node-verify-api-cert" do
      let(:options) { ["--node-verify-api-cert"] }

      it "renders the client.rb with verify_api_cert set to true" do
        expect(rendered_template).to match(/verify_api_cert true/)
      end
    end

    context "via --no-node-verify-api-cert" do
      let(:options) { ["--no-node-verify-api-cert"] }

      it "renders the client.rb with verify_api_cert set to false" do
        expect(rendered_template).to match(/verify_api_cert false/)
      end
    end
  end

  describe "specifying the encrypted data bag secret key" do
    let(:secret) { "supersekret" }
    let(:options) { [] }
    let(:bootstrap_template) { File.expand_path(File.join(CHEF_SPEC_DATA, "bootstrap", "secret.erb")) }
    let(:rendered_template) do
      knife.parse_options(options)
      knife.merge_configs
      knife.render_template
    end

    it "creates a secret file" do
      expect(knife).to receive(:encryption_secret_provided_ignore_encrypt_flag?).and_return(true)
      expect(knife).to receive(:read_secret).and_return(secret)
      expect(rendered_template).to match(/#{secret}/)
    end

    it "renders the client.rb with an encrypted_data_bag_secret entry" do
      expect(knife).to receive(:encryption_secret_provided_ignore_encrypt_flag?).and_return(true)
      expect(knife).to receive(:read_secret).and_return(secret)
      expect(rendered_template).to match(%r{encrypted_data_bag_secret\s*"/etc/chef/encrypted_data_bag_secret"})
    end

  end

  describe "when transferring trusted certificates" do
    let(:rendered_template) do
      knife.merge_configs
      knife.render_template
    end

    before do
      Chef::Config[:trusted_certs_dir] = Chef::Util::PathHelper.cleanpath(File.join(CHEF_SPEC_DATA, "trusted_certs"))
    end

    it "creates /etc/chef/trusted_certs" do
      expect(rendered_template).to match(%r{mkdir -p /etc/chef/trusted_certs})
    end

    it "copies the certificates in the directory" do
      certificates = Dir[File.join(Chef::Config[:trusted_certs_dir], "*.{crt,pem}")]

      certificates.each do |cert|
        expect(rendered_template).to match(%r{cat > /etc/chef/trusted_certs/#{File.basename(cert)} <<'EOP'})
      end
    end

    it "doesn't create /etc/chef/trusted_certs if :trusted_certs_dir is empty" do
      Dir.mktmpdir do |dir|
        Chef::Config[:trusted_certs_dir] = dir
        expect(rendered_template).not_to match(%r{mkdir -p /etc/chef/trusted_certs})
      end
    end
  end

  context "when doing fips things" do
    let(:template_file) { File.expand_path(File.join(CHEF_SPEC_DATA, "bootstrap", "no_proxy.erb")) }

    before do
      Chef::Config[:knife][:bootstrap_template] = template_file
      knife.merge_configs
    end

    let(:rendered_template) do
      knife.render_template
    end

    context "when knife is in fips mode" do
      before do
        Chef::Config[:fips] = true
      end

      it "renders 'fips true'" do
        expect(rendered_template).to match("fips")
      end
    end

    context "when knife is not in fips mode" do
      before do
        # This is required because the chef-fips pipeline does
        # has a default value of true for fips
        Chef::Config[:fips] = false
      end

      it "does not render anything about fips" do
        expect(rendered_template).not_to match("fips")
      end
    end
  end

  describe "when transferring client.d" do

    let(:rendered_template) do
      knife.merge_configs
      knife.render_template
    end

    before do
      Chef::Config[:client_d_dir] = client_d_dir
    end

    context "when client_d_dir is nil" do
      let(:client_d_dir) { nil }

      it "does not create /etc/chef/client.d" do
        expect(rendered_template).not_to match(%r{mkdir -p /etc/chef/client\.d})
      end
    end

    context "when client_d_dir is set" do
      let(:client_d_dir) do
        Chef::Util::PathHelper.cleanpath(
          File.join(__dir__, "../../data/client.d_00")
        )
      end

      it "creates /etc/chef/client.d" do
        expect(rendered_template).to match("mkdir -p /etc/chef/client\.d")
      end

      context "a flat directory structure" do
        it "escapes single-quotes" do
          expect(rendered_template).to match("cat > /etc/chef/client.d/02-strings.rb <<'EOP'")
          expect(rendered_template).to match("something '\\\\''/foo/bar'\\\\''")
        end

        it "creates a file 00-foo.rb" do
          expect(rendered_template).to match("cat > /etc/chef/client.d/00-foo.rb <<'EOP'")
          expect(rendered_template).to match("d6f9b976-289c-4149-baf7-81e6ffecf228")
        end
        it "creates a file bar" do
          expect(rendered_template).to match("cat > /etc/chef/client.d/bar <<'EOP'")
          expect(rendered_template).to match("1 / 0")
        end
      end

      context "a nested directory structure" do
        let(:client_d_dir) do
          Chef::Util::PathHelper.cleanpath(
            File.join(__dir__, "../../data/client.d_01")
          )
        end
        it "creates a file foo/bar.rb" do
          expect(rendered_template).to match("cat > /etc/chef/client.d/foo/bar.rb <<'EOP'")
          expect(rendered_template).to match("1 / 0")
        end
      end
    end
  end

  describe "#connection_protocol" do
    let(:host_descriptor) { "example.com" }
    let(:config) { {} }
    let(:knife_connection_protocol) { nil }
    before do
      allow(knife).to receive(:config).and_return config
      allow(knife).to receive(:host_descriptor).and_return host_descriptor
      if knife_connection_protocol
        Chef::Config[:knife][:connection_protocol] = knife_connection_protocol
        knife.merge_configs
      end
    end

    context "when protocol is part of the host argument" do
      let(:host_descriptor) { "winrm://myhost" }

      it "returns the value provided by the host argument" do
        expect(knife.connection_protocol).to eq "winrm"
      end
    end

    context "when protocol is provided via the CLI flag" do
      let(:config) { { connection_protocol: "winrm" } }
      it "returns that value" do
        expect(knife.connection_protocol).to eq "winrm"
      end

    end
    context "when protocol is provided via the host argument and the CLI flag" do
      let(:host_descriptor) { "ssh://example.com" }
      let(:config) { { connection_protocol: "winrm" } }

      it "returns the value provided by the host argument" do
        expect(knife.connection_protocol).to eq "ssh"
      end
    end

    context "when no explicit protocol is provided" do
      let(:config) { {} }
      let(:host_descriptor) { "example.com" }
      let(:knife_connection_protocol) { "winrm" }
      it "falls back to knife config" do
        expect(knife.connection_protocol).to eq "winrm"
      end
      context "and there is no knife bootstrap_protocol" do
        let(:knife_connection_protocol) { nil }
        it "falls back to 'ssh'" do
          expect(knife.connection_protocol).to eq "ssh"
        end
      end
    end

  end

  describe "#validate_protocol!" do
    let(:host_descriptor) { "example.com" }
    let(:config) { {} }
    let(:connection_protocol) { "ssh" }
    before do
      allow(knife).to receive(:config).and_return config
      allow(knife).to receive(:connection_protocol).and_return connection_protocol
      allow(knife).to receive(:host_descriptor).and_return host_descriptor
    end

    context "when protocol is provided both in the URL and via --protocol" do

      context "and they do not match" do
        let(:connection_protocol) { "ssh" }
        let(:config) { { connection_protocol: "winrm" } }
        it "outputs an error and exits" do
          expect(knife.ui).to receive(:error)
          expect { knife.validate_protocol! }.to raise_error SystemExit
        end
      end

      context "and they do match" do
        let(:connection_protocol) { "winrm" }
        let(:config) { { connection_protocol: "winrm" } }
        it "returns true" do
          expect(knife.validate_protocol!).to eq true
        end
      end
    end

    context "and the protocol is supported" do

      Chef::Knife::Bootstrap::SUPPORTED_CONNECTION_PROTOCOLS.each do |proto|
        let(:connection_protocol) { proto }
        it "returns true for #{proto}" do
          expect(knife.validate_protocol!).to eq true
        end
      end
    end

    context "and the protocol is not supported" do
      let(:connection_protocol) { "invalid" }
      it "outputs an error and exits" do
        expect(knife.ui).to receive(:error).with(/Unsupported protocol '#{connection_protocol}'/)
        expect { knife.validate_protocol! }.to raise_error SystemExit
      end
    end
  end

  describe "#validate_policy_options!" do

    context "when only policy_name is given" do

      let(:bootstrap_cli_options) { %w{ --policy-name my-app-server } }

      it "returns an error stating that policy_name and policy_group must be given together" do
        expect { knife.validate_policy_options! }.to raise_error(SystemExit)
        expect(stderr.string).to include("ERROR: --policy-name and --policy-group must be specified together")
      end

    end

    context "when only policy_group is given" do

      let(:bootstrap_cli_options) { %w{ --policy-group staging } }

      it "returns an error stating that policy_name and policy_group must be given together" do
        expect { knife.validate_policy_options! }.to raise_error(SystemExit)
        expect(stderr.string).to include("ERROR: --policy-name and --policy-group must be specified together")
      end

    end

    context "when both policy_name and policy_group are given, but run list is also given" do

      let(:bootstrap_cli_options) { %w{ --policy-name my-app --policy-group staging --run-list cookbook } }

      it "returns an error stating that policyfile and run_list are exclusive" do
        expect { knife.validate_policy_options! }.to raise_error(SystemExit)
        expect(stderr.string).to include("ERROR: Policyfile options and --run-list are exclusive")
      end

    end

    context "when policy_name and policy_group are given with no conflicting options" do

      let(:bootstrap_cli_options) { %w{ --policy-name my-app --policy-group staging } }

      it "passes options validation" do
        expect { knife.validate_policy_options! }.to_not raise_error
      end

      it "passes them into the bootstrap context" do
        expect(knife.bootstrap_context.first_boot).to have_key(:policy_name)
        expect(knife.bootstrap_context.first_boot).to have_key(:policy_group)
      end

      it "ensures that run_list is not set in the bootstrap context" do
        expect(knife.bootstrap_context.first_boot).to_not have_key(:run_list)
      end

    end

    # https://github.com/chef/chef/issues/4131
    # Arguably a bug in the plugin: it shouldn't be setting this to nil, but it
    # worked before, so make it work now.
    context "when a plugin sets the run list option to nil" do
      before do
        knife.config[:run_list] = nil
      end

      it "passes options validation" do
        expect { knife.validate_policy_options! }.to_not raise_error
      end
    end
  end

  # TODO - this is the only cli option we validate the _option_ itself -
  #        so we'll know if someone accidentally deletes or renames use_sudo_password
  #        Is this worht keeping?  If so, then it seems we should expand it
  #        to cover all options.
  context "validating use_sudo_password option" do
    it "use_sudo_password contains description and long params for help" do
      expect(knife.options).to(have_key(:use_sudo_password)) \
        && expect(knife.options[:use_sudo_password][:description].to_s).not_to(eq(""))\
        && expect(knife.options[:use_sudo_password][:long].to_s).not_to(eq(""))
    end
  end

  context "#connection_opts" do
    let(:connection_protocol) { "ssh" }
    before do
      allow(knife).to receive(:connection_protocol).and_return connection_protocol
    end
    context "behavioral test: " do
      let(:expected_connection_opts) do
        { base_opts: true,
          ssh_identity_opts: true,
          ssh_opts: true,
          gateway_opts: true,
          host_verify_opts: true,
          sudo_opts: true,
          winrm_opts: true }
      end

      it "queries and merges only expected configurations" do
        expect(knife).to receive(:base_opts).and_return({ base_opts: true })
        expect(knife).to receive(:host_verify_opts).and_return({ host_verify_opts: true })
        expect(knife).to receive(:gateway_opts).and_return({ gateway_opts: true })
        expect(knife).to receive(:sudo_opts).and_return({ sudo_opts: true })
        expect(knife).to receive(:winrm_opts).and_return({ winrm_opts: true })
        expect(knife).to receive(:ssh_opts).and_return({ ssh_opts: true })
        expect(knife).to receive(:ssh_identity_opts).and_return({ ssh_identity_opts: true })
        expect(knife.connection_opts).to match expected_connection_opts
      end
    end

    context "functional test: " do
      context "when protocol is winrm" do
        let(:connection_protocol) { "winrm" }
        # context "and neither CLI nor Chef::Config config entries have been provided"
        # end
        context "and all supported values are provided as Chef::Config entries" do
          before do
            # Set everything to easily identifiable and obviously fake values
            # to verify that Chef::Config is being sourced instead of knife.config
            knife.config = {}
            Chef::Config[:knife][:max_wait] = 9999
            Chef::Config[:knife][:winrm_user] = "winbob"
            Chef::Config[:knife][:winrm_port] = 9999
            Chef::Config[:knife][:ca_trust_file] = "trust.me"
            Chef::Config[:knife][:kerberos_realm] = "realm"
            Chef::Config[:knife][:kerberos_service] = "service"
            Chef::Config[:knife][:winrm_auth_method] = "kerberos" # default is negotiate
            Chef::Config[:knife][:winrm_basic_auth_only] = true
            Chef::Config[:knife][:winrm_no_verify_cert] = true
            Chef::Config[:knife][:session_timeout] = 9999
            Chef::Config[:knife][:winrm_ssl] = true
            Chef::Config[:knife][:winrm_ssl_peer_fingerprint] = "ABCDEF"
          end

          context "and no CLI options have been given" do
            let(:expected_result) do
              {
                logger: Chef::Log, # not configurable
                ca_trust_path: "trust.me",
                max_wait_until_ready: 9999,
                operation_timeout: 9999,
                ssl_peer_fingerprint: "ABCDEF",
                winrm_transport: "kerberos",
                winrm_basic_auth_only: true,
                user: "winbob",
                port: 9999,
                self_signed: true,
                ssl: true,
                kerberos_realm: "realm",
                kerberos_service: "service",
              }
            end

            it "generates a config hash using the Chef::Config values" do
              knife.merge_configs
              expect(knife.connection_opts).to match expected_result
            end

          end

          context "and some CLI options have been given" do
            let(:expected_result) do
              {
                logger: Chef::Log, # not configurable
                ca_trust_path: "no trust",
                max_wait_until_ready: 9999,
                operation_timeout: 9999,
                ssl_peer_fingerprint: "ABCDEF",
                winrm_transport: "kerberos",
                winrm_basic_auth_only: true,
                user: "microsoftbob",
                port: 12,
                self_signed: true,
                ssl: true,
                kerberos_realm: "realm",
                kerberos_service: "service",
                password: "lobster",
              }
            end

            before do
              knife.config[:ca_trust_file] = "no trust"
              knife.config[:connection_user] = "microsoftbob"
              knife.config[:connection_port] = 12
              knife.config[:winrm_port] = "13" # indirectly verify we're not looking for the wrong CLI flag
              knife.config[:connection_password] = "lobster"
            end

            it "generates a config hash using the CLI options when available and falling back to Chef::Config values" do
              knife.merge_configs
              expect(knife.connection_opts).to match expected_result
            end
          end

          context "and all CLI options have been given" do
            before do
              # We'll force kerberos vi knife.config because it
              # causes additional options to populate - make sure
              # Chef::Config is different so we can be sure that we didn't
              # pull in the Chef::Config value
              Chef::Config[:knife][:winrm_auth_method] = "negotiate"
              knife.config[:connection_password] = "blue"
              knife.config[:max_wait] = 1000
              knife.config[:connection_user] = "clippy"
              knife.config[:connection_port] = 1000
              knife.config[:winrm_port] = 1001 # We should not see this value get used

              knife.config[:ca_trust_file] = "trust.the.internet"
              knife.config[:kerberos_realm] = "otherrealm"
              knife.config[:kerberos_service] = "otherservice"
              knife.config[:winrm_auth_method] = "kerberos" # default is negotiate
              knife.config[:winrm_basic_auth_only] = false
              knife.config[:winrm_no_verify_cert] = false
              knife.config[:session_timeout] = 1000
              knife.config[:winrm_ssl] = false
              knife.config[:winrm_ssl_peer_fingerprint] = "FEDCBA"
            end
            let(:expected_result) do
              {
                logger: Chef::Log, # not configurable
                ca_trust_path: "trust.the.internet",
                max_wait_until_ready: 1000,
                operation_timeout: 1000,
                ssl_peer_fingerprint: "FEDCBA",
                winrm_transport: "kerberos",
                winrm_basic_auth_only: false,
                user: "clippy",
                port: 1000,
                self_signed: false,
                ssl: false,
                kerberos_realm: "otherrealm",
                kerberos_service: "otherservice",
                password: "blue",
              }
            end
            it "generates a config hash using the CLI options and pulling nothing from Chef::Config" do
              knife.merge_configs
              expect(knife.connection_opts).to match expected_result
            end
          end
        end # with underlying Chef::Config values

        context "and no values are provided from Chef::Config or CLI" do
          before do
            # We will use knife's actual config since these tests
            # have assumptions based on CLI default values
          end
          let(:expected_result) do
            {
              logger: Chef::Log,
              operation_timeout: 60,
              self_signed: false,
              ssl: false,
              ssl_peer_fingerprint: nil,
              winrm_basic_auth_only: false,
              winrm_transport: "negotiate",
            }
          end
          it "populates appropriate defaults" do
            knife.merge_configs
            expect(knife.connection_opts).to match expected_result
          end
        end
      end # winrm

      context "when protocol is ssh" do
        let(:connection_protocol) { "ssh" }
        # context "and neither CLI nor Chef::Config config entries have been provided"
        # end
        context "and all supported values are provided as Chef::Config entries" do
          before do
            # Set everything to easily identifiable and obviously fake values
            # to verify that Chef::Config is being sourced instead of knife.config
            knife.config = {}
            Chef::Config[:knife][:max_wait] = 9999
            Chef::Config[:knife][:session_timeout] = 9999
            Chef::Config[:knife][:ssh_user] = "sshbob"
            Chef::Config[:knife][:ssh_port] = 9999
            Chef::Config[:knife][:host_key_verify] = false
            Chef::Config[:knife][:ssh_gateway_identity] = "/gateway.pem"
            Chef::Config[:knife][:ssh_gateway] = "admin@mygateway.local:1234"
            Chef::Config[:knife][:ssh_identity_file] = "/identity.pem"
            Chef::Config[:knife][:use_sudo_password] = false # We have no password.
          end

          context "and no CLI options have been given" do
            let(:expected_result) do
              {
                logger: Chef::Log, # not configurable
                max_wait_until_ready: 9999.0,
                connection_timeout: 9999,
                user: "sshbob",
                bastion_host: "mygateway.local",
                bastion_port: 1234,
                bastion_user: "admin",
                forward_agent: false,
                keys_only: true,
                key_files: ["/identity.pem", "/gateway.pem"],
                sudo: false,
                verify_host_key: "always",
                port: 9999,
                non_interactive: true,
              }
            end

            it "generates a correct config hash using the Chef::Config values" do
              knife.merge_configs
              expect(knife.connection_opts).to match expected_result
            end
          end

          context "and unsupported Chef::Config options are given in Chef::Config, not in CLI" do
            before do
              Chef::Config[:knife][:password] = "blah"
              Chef::Config[:knife][:ssh_password] = "blah"
              Chef::Config[:knife][:preserve_home] = true
              Chef::Config[:knife][:use_sudo] = true
              Chef::Config[:knife][:ssh_forward_agent] = "blah"
            end
            it "does not include the corresponding option in the connection options" do
              knife.merge_configs
              expect(knife.connection_opts.key?(:password)).to eq false
              expect(knife.connection_opts.key?(:ssh_forward_agent)).to eq false
              expect(knife.connection_opts.key?(:use_sudo)).to eq false
              expect(knife.connection_opts.key?(:preserve_home)).to eq false
            end
          end

          context "and some CLI options have been given" do
            before do
              knife.config = {}
              knife.config[:connection_user] = "sshalice"
              knife.config[:connection_port] = 12
              knife.config[:ssh_port] = "13" # canary to indirectly verify we're not looking for the wrong CLI flag
              knife.config[:connection_password] = "feta cheese"
              knife.config[:max_wait] = 150
              knife.config[:session_timeout] = 120
              knife.config[:use_sudo] = true
              knife.config[:use_sudo_pasword] = true
              knife.config[:ssh_forward_agent] = true
            end

            let(:expected_result) do
              {
                logger: Chef::Log, # not configurable
                max_wait_until_ready: 150.0, # cli
                connection_timeout: 120, # cli
                user: "sshalice", # cli
                password: "feta cheese", # cli
                bastion_host: "mygateway.local", # Config
                bastion_port: 1234,              # Config
                bastion_user: "admin",           # Config
                forward_agent: true, # cli
                keys_only: false, # implied false from config password present
                key_files: ["/identity.pem", "/gateway.pem"], # Config
                sudo: true, # ccli
                verify_host_key: "always", # Config
                port: 12, # cli
                non_interactive: true,
              }
            end

            it "generates a config hash using the CLI options when available and falling back to Chef::Config values" do
              knife.merge_configs
              expect(knife.connection_opts).to match expected_result
            end
          end

          context "and all CLI options have been given" do
            before do
              knife.config = {}
              knife.config[:max_wait] = 150
              knife.config[:session_timeout] = 120
              knife.config[:connection_user] = "sshroot"
              knife.config[:connection_port] = 1000
              knife.config[:connection_password] = "blah"
              knife.config[:forward_agent] = true
              knife.config[:use_sudo] = true
              knife.config[:use_sudo_password] = true
              knife.config[:preserve_home] = true
              knife.config[:use_sudo_pasword] = true
              knife.config[:ssh_forward_agent] = true
              knife.config[:ssh_verify_host_key] = true
              knife.config[:ssh_gateway_identity] = "/gateway-identity.pem"
              knife.config[:ssh_gateway] = "me@example.com:10"
              knife.config[:ssh_identity_file] = "/my-identity.pem"

              # We'll set these as canaries - if one of these values shows up
              # in a failed test, then the behavior of not pulling from these keys
              # out of knife.config is broken:
              knife.config[:ssh_user] = "do not use"
              knife.config[:ssh_port] = 1001
            end
            let(:expected_result) do
              {
                logger: Chef::Log, # not configurable
                max_wait_until_ready: 150,
                connection_timeout: 120,
                user: "sshroot",
                password: "blah",
                port: 1000,
                bastion_host: "example.com",
                bastion_port: 10,
                bastion_user: "me",
                forward_agent: true,
                keys_only: false,
                key_files: ["/my-identity.pem", "/gateway-identity.pem"],
                sudo: true,
                sudo_options: "-H",
                sudo_password: "blah",
                verify_host_key: true,
                non_interactive: true,
              }
            end
            it "generates a config hash using the CLI options and pulling nothing from Chef::Config" do
              knife.merge_configs
              expect(knife.connection_opts).to match expected_result
            end
          end
        end
        context "and no values are provided from Chef::Config or CLI" do
          before do
            # We will use knife's actual config since these tests
            # have assumptions based on CLI default values
            config = {}
          end

          let(:expected_result) do
            {
              forward_agent: false,
              key_files: [],
              logger: Chef::Log,
              keys_only: false,
              sudo: false,
              verify_host_key: "always",
              non_interactive: true,
              connection_timeout: 60,
            }
          end
          it "populates appropriate defaults" do
            knife.merge_configs
            expect(knife.connection_opts).to match expected_result
          end
        end

      end # ssh
    end # functional tests

  end # connection_opts

  context "#base_opts" do
    let(:connection_protocol) { nil }

    before do
      allow(knife).to receive(:connection_protocol).and_return connection_protocol
    end

    context "for all protocols" do
      context "when password is provided" do
        before do
          knife.config[:connection_port] = 250
          knife.config[:connection_user] = "test"
          knife.config[:connection_password] = "opscode"
        end

        let(:expected_opts) do
          {
            port: 250,
            user: "test",
            logger: Chef::Log,
            password: "opscode",
          }
        end
        it "generates the correct options" do
          expect(knife.base_opts).to eq expected_opts
        end

      end

      context "when password is not provided" do
        before do
          knife.config[:connection_port] = 250
          knife.config[:connection_user] = "test"
        end

        let(:expected_opts) do
          {
            port: 250,
            user: "test",
            logger: Chef::Log,
          }
        end
        it "generates the correct options" do
          expect(knife.base_opts).to eq expected_opts
        end
      end
    end
  end

  context "#host_verify_opts" do
    let(:connection_protocol) { nil }
    before do
      allow(knife).to receive(:connection_protocol).and_return connection_protocol
    end

    context "for winrm" do
      let(:connection_protocol) { "winrm" }
      it "returns the expected configuration" do
        knife.config[:winrm_no_verify_cert] = true
        expect(knife.host_verify_opts).to eq( { self_signed: true } )
      end
      it "provides a correct default when no option given" do
        expect(knife.host_verify_opts).to eq( { self_signed: false } )
      end
    end

    context "for ssh" do
      let(:connection_protocol) { "ssh" }
      it "returns the expected configuration" do
        knife.config[:ssh_verify_host_key] = false
        expect(knife.host_verify_opts).to eq( { verify_host_key: false } )
      end
      it "provides a correct default when no option given" do
        expect(knife.host_verify_opts).to eq( { verify_host_key: "always" } )
      end
    end
  end

  # TODO - test keys_only, password, config source behavior
  context "#ssh_identity_opts" do
    let(:connection_protocol) { nil }
    before do
      allow(knife).to receive(:connection_protocol).and_return connection_protocol
    end

    context "for winrm" do
      let(:connection_protocol) { "winrm" }
      it "returns an empty hash" do
        expect(knife.ssh_identity_opts).to eq({})
      end
    end

    context "for ssh" do
      let(:connection_protocol) { "ssh" }
      context "when an identity file is specified" do
        before do
          knife.config[:ssh_identity_file] = "/identity.pem"
        end
        it "generates the expected configuration" do
          expect(knife.ssh_identity_opts).to eq({
            key_files: [ "/identity.pem" ],
            keys_only: true,
          })
        end
        context "and a password is also specified" do
          before do
            knife.config[:connection_password] = "blah"
          end
          it "generates the expected configuration (key, keys_only false)" do
            expect(knife.ssh_identity_opts).to eq({
              key_files: [ "/identity.pem" ],
              keys_only: false,
            })
          end
        end

        context "and a gateway is not specified" do
          context "but a gateway identity file is specified" do
            it "does not include the gateway identity file in keys" do
              expect(knife.ssh_identity_opts).to eq({
                key_files: ["/identity.pem"],
                keys_only: true,
              })
            end

          end

        end

        context "and a gatway is specified" do
          before do
            knife.config[:ssh_gateway] = "example.com"
          end
          context "and a gateway identity file is not specified" do
            it "config includes only identity file and not gateway identity" do
              expect(knife.ssh_identity_opts).to eq({
                key_files: [ "/identity.pem" ],
                keys_only: true,
              })
            end
          end

          context "and a gateway identity file is also specified" do
            before do
              knife.config[:ssh_gateway_identity] = "/gateway.pem"
            end

            it "generates the expected configuration (both keys, keys_only true)" do
              expect(knife.ssh_identity_opts).to eq({
                key_files: [ "/identity.pem", "/gateway.pem" ],
                keys_only: true,
              })
            end
          end
        end
      end

      context "when no identity file is specified" do
        it "generates the expected configuration (no keys, keys_only false)" do
          expect(knife.ssh_identity_opts).to eq( {
            key_files: [],
            keys_only: false,
          })
        end
        context "and a gateway with gateway identity file is specified" do
          before do
            knife.config[:ssh_gateway] = "host"
            knife.config[:ssh_gateway_identity] = "/gateway.pem"
          end

          it "generates the expected configuration (gateway key, keys_only false)" do
            expect(knife.ssh_identity_opts).to eq({
              key_files: [ "/gateway.pem" ],
              keys_only: false,
            })
          end
        end
      end
    end
  end

  context "#gateway_opts" do
    let(:connection_protocol) { nil }
    before do
      allow(knife).to receive(:connection_protocol).and_return connection_protocol
    end

    context "for winrm" do
      let(:connection_protocol) { "winrm" }
      it "returns an empty hash" do
        expect(knife.gateway_opts).to eq({})
      end
    end

    context "for ssh" do
      let(:connection_protocol) { "ssh" }
      context "and ssh_gateway with hostname, user and port provided" do
        before do
          knife.config[:ssh_gateway] = "testuser@gateway:9021"
        end
        it "returns a proper bastion host config subset" do
          expect(knife.gateway_opts).to eq({
            bastion_user: "testuser",
            bastion_host: "gateway",
            bastion_port: 9021,
          })
        end
      end
      context "and ssh_gateway with only hostname is given" do
        before do
          knife.config[:ssh_gateway] = "gateway"
        end
        it "returns a proper bastion host config subset" do
          expect(knife.gateway_opts).to eq({
            bastion_user: nil,
            bastion_host: "gateway",
            bastion_port: nil,
          })
        end
      end
      context "and ssh_gateway with hostname and user is is given" do
        before do
          knife.config[:ssh_gateway] = "testuser@gateway"
        end
        it "returns a proper bastion host config subset" do
          expect(knife.gateway_opts).to eq({
            bastion_user: "testuser",
            bastion_host: "gateway",
            bastion_port: nil,
          })
        end
      end

      context "and ssh_gateway with hostname and port is is given" do
        before do
          knife.config[:ssh_gateway] = "gateway:11234"
        end
        it "returns a proper bastion host config subset" do
          expect(knife.gateway_opts).to eq({
            bastion_user: nil,
            bastion_host: "gateway",
            bastion_port: 11234,
          })
        end
      end

      context "and ssh_gateway is not provided" do
        it "returns an empty hash" do
          expect(knife.gateway_opts).to eq({})
        end
      end
    end
  end

  context "#sudo_opts" do
    let(:connection_protocol) { nil }
    before do
      allow(knife).to receive(:connection_protocol).and_return connection_protocol
    end

    context "for winrm" do
      let(:connection_protocol) { "winrm" }
      it "returns an empty hash" do
        expect(knife.sudo_opts).to eq({})
      end
    end

    context "for ssh" do
      let(:connection_protocol) { "ssh" }
      context "when use_sudo is set" do
        before do
          knife.config[:use_sudo] = true
        end

        it "returns a config that enables sudo" do
          expect(knife.sudo_opts).to eq( { sudo: true } )
        end

        context "when use_sudo_password is also set" do
          before do
            knife.config[:use_sudo_password] = true
            knife.config[:connection_password] = "opscode"
          end
          it "includes :connection_password value in a sudo-enabled configuration" do
            expect(knife.sudo_opts).to eq({
              sudo: true,
              sudo_password: "opscode",
            })
          end
        end

        context "when preserve_home is set" do
          before do
            knife.config[:preserve_home] = true
          end
          it "enables sudo with sudo_option to preserve home" do
            expect(knife.sudo_opts).to eq({
              sudo_options: "-H",
              sudo: true,
            })
          end
        end
      end

      context "when use_sudo is not set" do
        before do
          knife.config[:use_sudo_password] = true
          knife.config[:preserve_home] = true
        end
        it "returns configuration for sudo off, ignoring other related options" do
          expect(knife.sudo_opts).to eq( { sudo: false } )
        end
      end
    end
  end

  context "#ssh_opts" do
    let(:connection_protocol) { nil }
    before do
      allow(knife).to receive(:connection_protocol).and_return connection_protocol
    end

    context "for ssh" do
      let(:connection_protocol) { "ssh" }
      let(:default_opts) do
        {
          non_interactive: true,
          forward_agent: false,
          connection_timeout: 60,
        }
      end

      context "by default" do
        it "returns a configuration hash with appropriate defaults" do
          expect(knife.ssh_opts).to eq default_opts
        end
      end

      context "when ssh_forward_agent has a value" do
        before do
          knife.config[:ssh_forward_agent] = true
        end
        it "returns a default configuration hash with forward_agent set to true" do
          expect(knife.ssh_opts).to eq(default_opts.merge(forward_agent: true))
        end
      end
      context "when session_timeout has a value" do
        before do
          knife.config[:session_timeout] = 120
        end
        it "returns a default configuration hash with updated timeout value." do
          expect(knife.ssh_opts).to eq(default_opts.merge(connection_timeout: 120))
        end
      end

    end

    context "for winrm" do
      let(:connection_protocol) { "winrm" }
      it "returns an empty has because ssh is not winrm" do
        expect(knife.ssh_opts).to eq({})
      end
    end

  end

  context "#winrm_opts" do
    let(:connection_protocol) { nil }
    before do
      allow(knife).to receive(:connection_protocol).and_return connection_protocol
    end

    context "for winrm" do
      let(:connection_protocol) { "winrm" }
      let(:expected) do
        {
        winrm_transport: "negotiate",
        winrm_basic_auth_only: false,
        ssl: false,
        ssl_peer_fingerprint: nil,
        operation_timeout: 60,
      }
      end

      it "generates a correct configuration hash with expected defaults" do
        expect(knife.winrm_opts).to eq expected
      end

      context "with ssl_peer_fingerprint" do
        let(:ssl_peer_fingerprint_expected) do
          expected.merge({ ssl_peer_fingerprint: "ABCD" })
        end

        before do
          knife.config[:winrm_ssl_peer_fingerprint] = "ABCD"
        end

        it "generates a correct options hash with ssl_peer_fingerprint from the config provided" do
          expect(knife.winrm_opts).to eq ssl_peer_fingerprint_expected
        end
      end

      context "with winrm_ssl" do
        let(:ssl_expected) do
          expected.merge({ ssl: true })
        end
        before do
          knife.config[:winrm_ssl] = true
        end

        it "generates a correct options hash with ssl from the config provided" do
          expect(knife.winrm_opts).to eq ssl_expected
        end
      end

      context "with winrm_auth_method" do
        let(:winrm_auth_method_expected) do
          expected.merge({ winrm_transport: "freeaccess" })
        end

        before do
          knife.config[:winrm_auth_method] = "freeaccess"
        end

        it "generates a correct options hash with winrm_transport from the config provided" do
          expect(knife.winrm_opts).to eq winrm_auth_method_expected
        end
      end

      context "with ca_trust_file" do
        let(:ca_trust_expected) do
          expected.merge({ ca_trust_path: "/trust.me" })
        end
        before do
          knife.config[:ca_trust_file] = "/trust.me"
        end

        it "generates a correct options hash with ca_trust_file from the config provided" do
          expect(knife.winrm_opts).to eq ca_trust_expected
        end
      end

      context "with kerberos auth" do
        let(:kerberos_expected) do
          expected.merge({
            kerberos_service: "testsvc",
            kerberos_realm: "TESTREALM",
            winrm_transport: "kerberos",
          })
        end

        before do
          knife.config[:winrm_auth_method] = "kerberos"
          knife.config[:kerberos_service] = "testsvc"
          knife.config[:kerberos_realm] = "TESTREALM"
        end

        it "generates a correct options hash containing kerberos auth configuration from the config provided" do
          expect(knife.winrm_opts).to eq kerberos_expected
        end
      end

      context "with winrm_basic_auth_only" do
        before do
          knife.config[:winrm_basic_auth_only] = true
        end
        let(:basic_auth_expected) do
          expected.merge( { winrm_basic_auth_only: true } )
        end
        it "generates a correct options hash containing winrm_basic_auth_only from the config provided" do
          expect(knife.winrm_opts).to eq basic_auth_expected
        end
      end
    end

    context "for ssh" do
      let(:connection_protocol) { "ssh" }
      it "returns an empty hash because ssh is not winrm" do
        expect(knife.winrm_opts).to eq({})
      end
    end
  end
  describe "#run" do
    it "performs the steps we expect to run a bootstrap" do
      expect(knife).to receive(:check_license)
      expect(knife).to receive(:validate_name_args!).ordered
      expect(knife).to receive(:validate_protocol!).ordered
      expect(knife).to receive(:validate_first_boot_attributes!).ordered
      expect(knife).to receive(:validate_winrm_transport_opts!).ordered
      expect(knife).to receive(:validate_policy_options!).ordered
      expect(knife).to receive(:winrm_warn_no_ssl_verification).ordered
      expect(knife).to receive(:warn_on_short_session_timeout).ordered
      expect(knife).to receive(:connect!).ordered
      expect(knife).to receive(:register_client).ordered
      expect(knife).to receive(:render_template).and_return "content"
      expect(knife).to receive(:upload_bootstrap).with("content").and_return "/remote/path.sh"
      expect(knife).to receive(:perform_bootstrap).with("/remote/path.sh")
      expect(connection).to receive(:del_file!) # Make sure cleanup happens

      knife.run

      # Post-run verify expected state changes (not many directly in #run)
      expect($stdout.sync).to eq true
    end
  end

  describe "#register_client" do
    let(:vault_handler_mock) { double("ChefVaultHandler") }
    let(:client_builder_mock) { double("ClientBuilder") }
    let(:node_name) { nil }
    before do
      allow(knife).to receive(:chef_vault_handler).and_return vault_handler_mock
      allow(knife).to receive(:client_builder).and_return client_builder_mock
      knife.config[:chef_node_name] = node_name
    end

    shared_examples_for "creating the client locally" do
      context "when a valid node name is present" do
        let(:node_name) { "test" }
        before do
          allow(client_builder_mock).to receive(:client).and_return "client"
          allow(client_builder_mock).to receive(:client_path).and_return "/key.pem"
        end

        it "runs client_builder and vault_handler" do
          expect(client_builder_mock).to receive(:run)
          expect(vault_handler_mock).to receive(:run).with("client")
          knife.register_client
        end

        it "sets the path to the client key in the bootstrap context" do
          allow(client_builder_mock).to receive(:run)
          allow(vault_handler_mock).to receive(:run).with("client")
          knife.register_client
          expect(knife.bootstrap_context.client_pem).to eq "/key.pem"
        end
      end

      context "when no valid node name is present" do
        let(:node_name) { nil }
        it "shows an error and exits" do
          expect(knife.ui).to receive(:error)
          expect { knife.register_client }.to raise_error(SystemExit)
        end
      end
    end
    context "when chef_vault_handler says we're using vault" do
      let(:vault_handler_mock) { double("ChefVaultHandler") }
      before do
        allow(vault_handler_mock).to receive(:doing_chef_vault?).and_return true
      end
      it_behaves_like "creating the client locally"
    end

    context "when an non-existant validation key is specified in chef config" do
      before do
        Chef::Config[:validation_key] = "/blah"
        allow(vault_handler_mock).to receive(:doing_chef_vault?).and_return false
        allow(File).to receive(:exist?).with(%r{/blah}).and_return false
      end
      it_behaves_like "creating the client locally"
    end

    context "when a valid validation key is given and we're doing old-style client creation" do
      before do
        Chef::Config[:validation_key] = "/blah"
        allow(File).to receive(:exist?).with(%r{/blah}).and_return true
        allow(vault_handler_mock).to receive(:doing_chef_vault?).and_return false
      end

      it "shows a warning message" do
        expect(knife.ui).to receive(:warn).twice
        knife.register_client
      end
    end
  end

  describe "#perform_bootstrap" do
    let(:exit_status) { 0 }
    let(:stdout) { "" }
    let(:result_mock) { double("result", exit_status: exit_status, stderr: "A message", stdout: stdout) }

    before do
      allow(connection).to receive(:hostname).and_return "testhost"
    end
    it "runs the remote script and logs the output" do
      expect(knife.ui).to receive(:info).with(/Bootstrapping.*/)
      expect(knife).to receive(:bootstrap_command)
        .with("/path.sh")
        .and_return("sh /path.sh")
      expect(connection)
        .to receive(:run_command)
        .with("sh /path.sh")
        .and_yield("output here", nil)
        .and_return result_mock

      expect(knife.ui).to receive(:msg).with(/testhost/)
      knife.perform_bootstrap("/path.sh")
    end

    context "when the remote command fails" do
      let(:exit_status) { 1 }
      it "shows an error and exits" do
        expect(knife.ui).to receive(:info).with(/Bootstrapping.*/)
        expect(knife).to receive(:bootstrap_command)
          .with("/path.sh")
          .and_return("sh /path.sh")
        expect(connection).to receive(:run_command).with("sh /path.sh").and_return result_mock
        expect { knife.perform_bootstrap("/path.sh") }.to raise_error(SystemExit)
      end
    end

    context "when the remote command failed due to su auth error" do
      let(:exit_status) { 1 }
      let(:stdout) { "su: Authentication failure" }
      let(:connection_obj) { double("connection", transport_options: {}) }
      it "shows an error and exits" do
        allow(connection).to receive(:connection).and_return(connection_obj)
        expect(knife.ui).to receive(:info).with(/Bootstrapping.*/)
        expect(knife).to receive(:bootstrap_command)
          .with("/path.sh")
          .and_return("su - USER -c 'sh /path.sh'")
        expect(connection)
          .to receive(:run_command)
          .with("su - USER -c 'sh /path.sh'")
          .and_yield("output here", nil)
          .and_raise(Train::UserError)
        expect { knife.perform_bootstrap("/path.sh") }.to raise_error(Train::UserError)
      end
    end
  end

  describe "#connect!" do
    before do
      # These are not required at run-time because train will handle its own
      # protocol loading. In this case, we're simulating train failures and have to load
      # them ourselves.
      require "net/ssh"
      require "train/transports/ssh"
    end

    context "in the normal case" do
      it "connects using the connection_opts and notifies the operator of progress" do
        expect(knife.ui).to receive(:info).with(/Connecting to.*/)
        expect(knife).to receive(:connection_opts).and_return( { opts: "here" })
        expect(knife).to receive(:do_connect).with( { opts: "here" } )
        knife.connect!
      end
    end

    context "when a general non-auth-failure occurs" do
      let(:expected_error) { RuntimeError.new }
      before do
        allow(knife).to receive(:do_connect).and_raise(expected_error)
      end
      it "re-raises the exception" do
        expect { knife.connect! }.to raise_error(expected_error)
      end
    end

    context "when ssh fingerprint is invalid" do
      let(:expected_error) { Train::Error.new("fingerprint AA:BB is unknown for \"blah,127.0.0.1\"") }
      before do
        allow(knife).to receive(:do_connect).and_raise(expected_error)
      end
      it "warns, prompts to accept, then connects with verify_host_key of accept_new" do
        expect(knife).to receive(:do_connect).and_raise(expected_error)
        expect(knife.ui).to receive(:confirm)
          .with(/.*host 'blah \(127.0.0.1\)'.*AA:BB.*Are you sure you want to continue.*/m)
          .and_return(true)
        expect(knife).to receive(:do_connect) do |opts|
          expect(opts[:verify_host_key]).to eq :accept_new
        end
        knife.connect!
      end
    end

    context "when an auth failure occurs" do
      let(:expected_error) do
        e = Train::Error.new
        actual = Net::SSH::AuthenticationFailed.new
        # Simulate train's nested error - they wrap
        # ssh/network errors in a TrainError.
        allow(e).to receive(:cause).and_return(actual)
        e
      end

      let(:expected_error_password_prompt) do
        e = Train::ClientError.new
        reason = :no_ssh_password_or_key_available
        allow(e).to receive(:reason).and_return(reason)
        e
      end

      let(:expected_error_password_prompt_winrm) do
        e = RuntimeError.new
        message = "password is a required option"
        allow(e).to receive(:message).and_return(message)
        e
      end

      context "and password auth was used" do
        before do
          allow(connection).to receive(:password_auth?).and_return true
        end

        it "re-raises the error so as not to resubmit the same failing password" do
          expect(knife).to receive(:do_connect).and_raise(expected_error)
          expect { knife.connect! }.to raise_error(expected_error)
        end
      end

      context "and password auth was not used" do
        before do
          allow(connection).to receive(:password_auth?).and_return false
          allow(connection).to receive(:user).and_return "testuser"
          allow(knife).to receive(:connection_protocol).and_return connection_protocol
        end

        context "when using ssh" do
          let(:connection_protocol) { "ssh" }

          it "warns, prompts for password, then reconnects with a password-enabled configuration using the new password" do
            expect(knife).to receive(:do_connect).and_raise(expected_error_password_prompt)
            expect(knife.ui).to receive(:warn).with(/Failed to auth.*/)
            expect(knife.ui).to receive(:ask).and_return("newpassword")
            # Ensure that we set echo off to prevent showing password on the screen
            expect(knife).to receive(:do_connect) do |opts|
              expect(opts[:password]).to eq "newpassword"
            end
            knife.connect!
          end
        end

        context "when using winrm" do
          let(:connection_protocol) { "winrm" }

          it "warns, prompts for password, then reconnects with a password-enabled configuration using the new password for" do
            expect(knife).to receive(:do_connect).and_raise(expected_error_password_prompt_winrm)
            expect(knife.ui).to receive(:warn).with(/Failed to auth.*/)
            expect(knife.ui).to receive(:ask).and_return("newpassword")
            # Ensure that we set echo off to prevent showing password on the screen
            expect(knife).to receive(:do_connect) do |opts|
              expect(opts[:password]).to eq "newpassword"
            end
            knife.connect!
          end
        end
      end
    end
  end

  it "verifies that a server to bootstrap was given as a command line arg" do
    knife.name_args = nil
    expect(knife).to receive(:check_license)
    expect { knife.run }.to raise_error(SystemExit)
    expect(stderr.string).to match(/ERROR:.+FQDN or ip/)
  end

  describe "#bootstrap_context" do
    context "under Windows" do
      let(:windows_test) { true }
      it "creates a WindowsBootstrapContext" do
        require "chef/knife/core/windows_bootstrap_context"
        expect(knife.bootstrap_context.class).to eq Chef::Knife::Core::WindowsBootstrapContext
      end
    end

    context "under linux" do
      let(:linux_test) { true }
      it "creates a BootstrapContext" do
        require "chef/knife/core/bootstrap_context"
        expect(knife.bootstrap_context.class).to eq Chef::Knife::Core::BootstrapContext
      end
    end
  end

  describe "#config_value" do
    before do
      knife.config[:test_key_a] = "a from cli"
      knife.config[:test_key_b] = "b from cli"
      Chef::Config[:knife][:test_key_a] = "a from Chef::Config"
      Chef::Config[:knife][:test_key_c] = "c from Chef::Config"
      Chef::Config[:knife][:alt_test_key_c] = "alt c from Chef::Config"
      knife.merge_configs
      Chef::Config[:treat_deprecation_warnings_as_errors] = false
    end

    it "returns the Chef::Config value from the cli when the CLI key is set" do
      expect(knife.config_value(:test_key_a, :alt_test_key_c)).to eq "a from cli"
    end

    it "returns the Chef::Config value from the alternative key when the CLI key is not set" do
      expect(knife.config_value(:test_key_d, :alt_test_key_c)).to eq "alt c from Chef::Config"
    end

    it "returns the default value when the key is not provided by CLI or Chef::Config" do
      expect(knife.config_value(:missing_key, :missing_key, "found")).to eq "found"
    end
  end

  describe "#upload_bootstrap" do
    before do
      allow(connection).to receive(:temp_dir).and_return(temp_dir)
      allow(connection).to receive(:normalize_path) { |a| a }
    end

    let(:content) { "bootstrap script content" }
    context "under Windows" do
      let(:windows_test) { true }
      let(:temp_dir) { "C:/Temp/bootstrap" }
      it "creates a bat file in the temp dir provided by connection, using given content" do
        expect(connection).to receive(:upload_file_content!).with(content, "C:/Temp/bootstrap/bootstrap.bat")
        expect(knife.upload_bootstrap(content)).to eq "C:/Temp/bootstrap/bootstrap.bat"
      end
    end

    context "under Linux" do
      let(:linux_test) { true }
      let(:temp_dir) { "/tmp/bootstrap" }
      it "creates a 'sh file in the temp dir provided by connection, using given content" do
        expect(connection).to receive(:upload_file_content!).with(content, "/tmp/bootstrap/bootstrap.sh")
        expect(knife.upload_bootstrap(content)).to eq "/tmp/bootstrap/bootstrap.sh"
      end
    end
  end

  describe "#bootstrap_command" do
    context "under Windows" do
      let(:windows_test) { true }
      it "prefixes the command to run under cmd.exe" do
        expect(knife.bootstrap_command("autoexec.bat")).to eq "cmd.exe /C autoexec.bat"
      end

    end
    context "under Linux" do
      let(:linux_test) { true }
      it "prefixes the command to run under sh" do
        expect(knife.bootstrap_command("bootstrap.sh")).to eq "sh bootstrap.sh"
      end

      context "with --su-user option" do
        let(:connection_obj) { double("connection", transport_options: {}) }
        before do
          knife.config[:su_user] = "root"
          allow(connection).to receive(:connection).and_return(connection_obj)
        end
        it "prefixes the command to run using su -USER -c" do
          expect(knife.bootstrap_command("bootstrap.sh")).to eq "su - #{knife.config[:su_user]} -c 'sh bootstrap.sh'"
          expect(connection_obj.transport_options.key?(:pty)).to eq true
        end

        it "sudo appended if --sudo option enabled" do
          knife.config[:use_sudo] = true
          expect(knife.bootstrap_command("bootstrap.sh")).to eq "sudo su - #{knife.config[:su_user]} -c 'sh bootstrap.sh'"
          expect(connection_obj.transport_options.key?(:pty)).to eq true
        end
      end
    end
  end

  describe "#default_bootstrap_template" do
    context "under Windows" do
      let(:windows_test) { true }
      it "is windows-chef-client-msi" do
        expect(knife.default_bootstrap_template).to eq "windows-chef-client-msi"
      end

    end
    context "under Linux" do
      let(:linux_test) { true }
      it "is chef-full" do
        expect(knife.default_bootstrap_template).to eq "chef-full"
      end
    end
  end

  describe "#do_connect" do
    let(:host_descriptor) { "example.com" }
    let(:connection) { double("TrainConnector") }
    let(:connector_mock) { double("TargetResolver", targets: [ connection ]) }
    before do
      allow(knife).to receive(:host_descriptor).and_return host_descriptor
    end

    it "creates a TrainConnector and connects it" do
      expect(Chef::Knife::Bootstrap::TrainConnector).to receive(:new).and_return connection
      expect(connection).to receive(:connect!)
      knife.do_connect({})
    end

    context "when sshd configured with requiretty" do
      let(:pty_err_msg) { "Sudo requires a TTY. Please see the README on how to configure sudo to allow for non-interactive usage." }
      let(:expected_error) { Train::UserError.new(pty_err_msg, :sudo_no_tty) }
      before do
        allow(connection).to receive(:connect!).and_raise(expected_error)
      end
      it "retry with pty true request option" do
        expect(Chef::Knife::Bootstrap::TrainConnector).to receive(:new).and_return(connection).exactly(2).times
        expect(knife.ui).to receive(:warn).with("#{pty_err_msg} - trying with pty request")
        expect { knife.do_connect({}) }.to raise_error(expected_error)
      end
    end
  end

  describe "validate_winrm_transport_opts!" do
    before do
      allow(knife).to receive(:connection_protocol).and_return connection_protocol
    end

    context "when using ssh" do
      let(:connection_protocol) { "ssh" }
      it "returns true" do
        expect(knife.validate_winrm_transport_opts!).to eq true
      end
    end
    context "when using winrm" do
      let(:connection_protocol) { "winrm" }
      context "with plaintext auth" do
        before do
          knife.config[:winrm_auth_method] = "plaintext"
        end
        context "with ssl" do
          before do
            knife.config[:winrm_ssl] = true
          end
          it "will not error because we won't send anything in plaintext regardless" do
            expect(knife.validate_winrm_transport_opts!).to eq true
          end
        end
        context "without ssl" do
          before do
            knife.config[:winrm_ssl] = false
          end
          context "and no validation key exists" do
            before do
              Chef::Config[:validation_key] = "validation_key.pem"
              allow(File).to receive(:exist?).with(/.*validation_key.pem/).and_return false
            end

            it "will error because we will generate and send a client key over the wire in plaintext" do
              expect { knife.validate_winrm_transport_opts! }.to raise_error(SystemExit)
            end

          end
          context "and a validation key exists" do
            before do
              Chef::Config[:validation_key] = "validation_key.pem"
              allow(File).to receive(:exist?).with(/.*validation_key.pem/).and_return true
            end
            # TODO - don't we still send validation key?
            it "will not error because we don not send client key over the wire" do
              expect(knife.validate_winrm_transport_opts!).to eq true
            end
          end
        end
      end

      context "with other auth" do
        before do
          knife.config[:winrm_auth_method] = "kerberos"
        end

        context "and no validation key exists" do
          before do

            Chef::Config[:validation_key] = "validation_key.pem"
            allow(File).to receive(:exist?).with(/.*validation_key.pem/).and_return false
          end

          it "will not error because we're not using plaintext auth" do
            expect(knife.validate_winrm_transport_opts!).to eq true
          end
        end
        context "and a validation key exists" do
          before do
            Chef::Config[:validation_key] = "validation_key.pem"
            allow(File).to receive(:exist?).with(/.*validation_key.pem/).and_return true
          end

          it "will not error because a client key won't be sent over the wire in plaintext when a validation key is present" do
            expect(knife.validate_winrm_transport_opts!).to eq true
          end
        end

      end

    end

  end

  describe "#winrm_warn_no_ssl_verification" do
    before do
      allow(knife).to receive(:connection_protocol).and_return connection_protocol
    end

    context "when using ssh" do
      let(:connection_protocol) { "ssh" }
      it "does not issue a warning" do
        expect(knife.ui).to_not receive(:warn)
        knife.winrm_warn_no_ssl_verification
      end
    end
    context "when using winrm" do
      let(:connection_protocol) { "winrm" }
      context "winrm_no_verify_cert is set" do
        before do
          knife.config[:winrm_no_verify_cert] = true
        end

        context "and ca_trust_file is present" do
          before do
            knife.config[:ca_trust_file] = "file"
          end

          it "does not issue a warning" do
            expect(knife.ui).to_not receive(:warn)
            knife.winrm_warn_no_ssl_verification
          end
        end

        context "and winrm_ssl_peer_fingerprint is present" do
          before do
            knife.config[:winrm_ssl_peer_fingerprint] = "ABCD"
          end
          it "does not issue a warning" do
            expect(knife.ui).to_not receive(:warn)
            knife.winrm_warn_no_ssl_verification
          end
        end
        context "and neither ca_trust_file nor winrm_ssl_peer_fingerprint is present" do
          it "issues a warning" do
            expect(knife.ui).to receive(:warn)
            knife.winrm_warn_no_ssl_verification
          end
        end
      end
    end
  end

  describe "#warn_on_short_session_timeout" do
    let(:session_timeout) { 60 }

    before do
      allow(knife).to receive(:session_timeout).and_return(session_timeout)
    end

    context "timeout is not set at all" do
      let(:session_timeout) { nil }
      it "does not issue a warning" do
        expect(knife.ui).to_not receive(:warn)
        knife.warn_on_short_session_timeout
      end
    end

    context "timeout is more than 15" do
      let(:session_timeout) { 16 }
      it "does not issue a warning" do
        expect(knife.ui).to_not receive(:warn)
        knife.warn_on_short_session_timeout
      end
    end
    context "timeout is 15 or less" do
      let(:session_timeout) { 15 }
      it "issues a warning" do
        expect(knife.ui).to receive(:warn)
        knife.warn_on_short_session_timeout
      end
    end
  end
end
