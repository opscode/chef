#
# Author:: Adam Jacob (<adam@chef.io>)
# Copyright:: Copyright 2008-2016, Chef Software, Inc.
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

describe Chef::Provider::Package::Chocolatey do
  let(:timeout) { 900 }

  let(:new_resource) { Chef::Resource::ChocolateyPackage.new("git") }

  let(:provider) do
    node = Chef::Node.new
    events = Chef::EventDispatch::Dispatcher.new
    run_context = Chef::RunContext.new(node, {}, events)
    Chef::Provider::Package::Chocolatey.new(new_resource, run_context)
  end

  let(:choco_install_path) { "C:\\ProgramData\\chocolatey" }
  let(:choco_exe) { "#{choco_install_path}\\bin\\choco.exe" }

  # installed packages (ConEmu is upgradable)
  let(:local_list_stdout) do
    <<~EOF
      Chocolatey v0.9.9.11
      chocolatey|0.9.9.11
      ConEmu|15.10.25.0
    EOF
  end

  before do
    allow(provider).to receive(:choco_install_path).and_return(choco_install_path)
    allow(provider).to receive(:choco_exe).and_return(choco_exe)
    local_list_obj = double(stdout: local_list_stdout)
    allow(provider).to receive(:shell_out_compacted!).with("#{choco_exe} list -l -r", { returns: [0], timeout: timeout }).and_return(local_list_obj)
  end

  def allow_remote_list(package_names, args = nil)
    remote_list_stdout = <<~EOF
      Chocolatey v0.9.9.11
      chocolatey|0.9.9.11
      ConEmu|15.10.25.1
      Git|2.6.1
      Git|2.6.2
      munin-node|1.6.1.20130823
    EOF
    remote_list_obj = double(stdout: remote_list_stdout)
    package_names.each do |pkg|
      allow(provider).to receive(:shell_out_compacted!).with("#{choco_exe} list -r -a -e #{pkg}#{args}", { returns: [0], timeout: timeout }).and_return(remote_list_obj)
    end
  end

  describe "#initialize" do
    it "should return the correct class" do
      expect(provider).to be_kind_of(Chef::Provider::Package::Chocolatey)
    end

    it "should support arrays" do
      expect(provider.use_multipackage_api?).to be true
    end
  end

  describe "#candidate_version" do
    it "should set the candidate_version to the latest version when not pinning" do
      allow_remote_list(["git"])
      expect(provider.candidate_version).to eql(["2.6.2"])
    end

    it "should set the candidate_version to pinned version if available" do
      allow_remote_list(["git"])
      new_resource.version("2.6.1")
      expect(provider.candidate_version).to eql(["2.6.1"])
    end

    it "should set the candidate_version to nil if there is no candidate" do
      allow_remote_list(["vim"])
      new_resource.package_name("vim")
      expect(provider.candidate_version).to eql([nil])
    end

    it "should set the candidate_version correctly when there are two packages to install" do
      allow_remote_list(%w{ConEmu chocolatey})
      new_resource.package_name(%w{ConEmu chocolatey})
      expect(provider.candidate_version).to eql(["15.10.25.1", "0.9.9.11"])
    end

    it "should set the candidate_version correctly when only the first is installable" do
      allow_remote_list(%w{ConEmu vim})
      new_resource.package_name(%w{ConEmu vim})
      expect(provider.candidate_version).to eql(["15.10.25.1", nil])
    end

    it "should set the candidate_version correctly when only the last is installable" do
      allow_remote_list(%w{vim chocolatey})
      new_resource.package_name(%w{vim chocolatey})
      expect(provider.candidate_version).to eql([nil, "0.9.9.11"])
    end

    it "should set the candidate_version correctly when neither are is installable" do
      allow_remote_list(%w{vim ruby})
      new_resource.package_name(%w{vim ruby})
      expect(provider.candidate_version).to eql([nil, nil])
    end
  end

  describe "#load_current_resource" do
    it "should return a current_resource" do
      expect(provider.load_current_resource).to be_kind_of(Chef::Resource::ChocolateyPackage)
    end

    it "should set the current_resource#package_name" do
      provider.load_current_resource
      expect(provider.current_resource.package_name).to eql(["git"])
    end

    it "should load and downcase names in the installed_packages hash" do
      provider.load_current_resource
      expect(provider.send(:installed_packages)).to eql(
        { "chocolatey" => "0.9.9.11", "conemu" => "15.10.25.0" }
      )
    end

    it "should load and downcase names in the available_packages hash" do
      allow_remote_list(["git"])
      provider.load_current_resource
      expect(provider.send(:available_packages)).to eql(
        { "chocolatey" => "0.9.9.11", "conemu" => "15.10.25.1", "git" => "2.6.2", "munin-node" => "1.6.1.20130823" }
      )
    end

    it "should set the current_resource.version to nil when the package is not installed" do
      provider.load_current_resource
      expect(provider.current_resource.version).to eql([nil])
    end

    it "should set the current_resource.version to the installed version when the package is installed" do
      new_resource.package_name("ConEmu")
      provider.load_current_resource
      expect(provider.current_resource.version).to eql(["15.10.25.0"])
    end

    it "should set the current_resource.version when there are two packages that are installed" do
      new_resource.package_name(%w{ConEmu chocolatey})
      provider.load_current_resource
      expect(provider.current_resource.version).to eql(["15.10.25.0", "0.9.9.11"])
    end

    it "should set the current_resource.version correctly when only the first is installed" do
      new_resource.package_name(%w{ConEmu git})
      provider.load_current_resource
      expect(provider.current_resource.version).to eql(["15.10.25.0", nil])
    end

    it "should set the current_resource.version correctly when only the last is installed" do
      new_resource.package_name(%w{git chocolatey})
      provider.load_current_resource
      expect(provider.current_resource.version).to eql([nil, "0.9.9.11"])
    end

    it "should set the current_resource.version correctly when none are installed" do
      new_resource.package_name(%w{git vim})
      provider.load_current_resource
      expect(provider.current_resource.version).to eql([nil, nil])
    end
  end

  describe "#action_install" do
    it "should install a single package" do
      allow_remote_list(["git"])
      provider.load_current_resource
      expect(provider).to receive(:shell_out_compacted!).with("#{choco_exe} install -y git", { returns: [0], timeout: timeout }).and_return(double)
      provider.run_action(:install)
      expect(new_resource).to be_updated_by_last_action
    end

    context "when changing the timeout to 3600" do
      let(:timeout) { 3600 }
      it "sets the timeout on shell_out commands" do
        allow_remote_list(["git"])
        new_resource.timeout(timeout)
        provider.load_current_resource
        expect(provider).to receive(:shell_out_compacted!).with("#{choco_exe} install -y git", { returns: [0], timeout: timeout }).and_return(double)
        provider.run_action(:install)
        expect(new_resource).to be_updated_by_last_action
      end
    end

    it "should not install packages that are up-to-date" do
      allow_remote_list(["chocolatey"])
      new_resource.package_name("chocolatey")
      provider.load_current_resource
      expect(provider).not_to receive(:install_package)
      provider.run_action(:install)
      expect(new_resource).not_to be_updated_by_last_action
    end

    it "should not upgrade packages" do
      allow_remote_list(["ConEmu"])
      new_resource.package_name("ConEmu")
      provider.load_current_resource
      expect(provider).not_to receive(:install_package)
      provider.run_action(:install)
      expect(new_resource).not_to be_updated_by_last_action
    end

    it "should upgrade packages when given a version pin" do
      allow_remote_list(["ConEmu"])
      new_resource.package_name("ConEmu")
      new_resource.version("15.10.25.1")
      provider.load_current_resource
      expect(provider).to receive(:shell_out_compacted!).with("#{choco_exe} install -y --version 15.10.25.1 conemu", { returns: [0], timeout: timeout }).and_return(double)
      provider.run_action(:install)
      expect(new_resource).to be_updated_by_last_action
    end

    it "should handle complicated cases when the name/version array is pruned" do
      # chocolatey will be pruned by the superclass out of the args to install_package and we
      # implicitly test that we correctly pick up new_resource.version[1] instead of
      # new_version.resource[0]
      allow_remote_list(%w{chocolatey ConEmu})
      new_resource.package_name(%w{chocolatey ConEmu})
      new_resource.version([nil, "15.10.25.1"])
      provider.load_current_resource
      expect(provider).to receive(:shell_out_compacted!).with("#{choco_exe} install -y --version 15.10.25.1 conemu", { returns: [0], timeout: timeout }).and_return(double)
      provider.run_action(:install)
      expect(new_resource).to be_updated_by_last_action
    end

    it "should be case-insensitive" do
      allow_remote_list(["conemu"])
      new_resource.package_name("conemu")
      new_resource.version("15.10.25.1")
      provider.load_current_resource
      expect(provider).to receive(:shell_out_compacted!).with("#{choco_exe} install -y --version 15.10.25.1 conemu", { returns: [0], timeout: timeout }).and_return(double)
      provider.run_action(:install)
      expect(new_resource).to be_updated_by_last_action
    end

    it "should split up commands when given two packages, one with a version pin" do
      allow_remote_list(%w{ConEmu git})
      new_resource.package_name(%w{ConEmu git})
      new_resource.version(["15.10.25.1", nil])
      provider.load_current_resource
      expect(provider).to receive(:shell_out_compacted!).with("#{choco_exe} install -y --version 15.10.25.1 conemu", { returns: [0], timeout: timeout }).and_return(double)
      expect(provider).to receive(:shell_out_compacted!).with("#{choco_exe} install -y git", { returns: [0], timeout: timeout }).and_return(double)
      provider.run_action(:install)
      expect(new_resource).to be_updated_by_last_action
    end

    it "should do multipackage installs when given two packages without constraints" do
      allow_remote_list(%w{git munin-node})
      new_resource.package_name(%w{git munin-node})
      provider.load_current_resource
      expect(provider).to receive(:shell_out_compacted!).with("#{choco_exe} install -y git munin-node", { returns: [0], timeout: timeout }).and_return(double)
      provider.run_action(:install)
      expect(new_resource).to be_updated_by_last_action
    end

    context "when passing a source argument" do
      it "should pass options into the install command" do
        allow_remote_list(["git"], " -source localpackages")
        new_resource.source("localpackages")
        provider.load_current_resource
        expect(provider).to receive(:shell_out_compacted!).with("#{choco_exe} install -y -source localpackages git", { returns: [0], timeout: timeout }).and_return(double)
        provider.run_action(:install)
        expect(new_resource).to be_updated_by_last_action
      end
    end

    it "should pass options into the install command" do
      allow_remote_list(["git"], " -force")
      new_resource.options("-force")
      provider.load_current_resource
      expect(provider).to receive(:shell_out_compacted!).with("#{choco_exe} install -y -force git", { returns: [0], timeout: timeout }).and_return(double)
      provider.run_action(:install)
      expect(new_resource).to be_updated_by_last_action
    end

    it "installing a package that does not exist throws an error" do
      allow_remote_list(["package-does-not-exist"])
      new_resource.package_name("package-does-not-exist")
      provider.load_current_resource
      expect { provider.run_action(:install) }.to raise_error(Chef::Exceptions::Package)
    end

    it "installing multiple packages with a package that does not exist throws an error" do
      allow_remote_list(%w{git package-does-not-exist})
      new_resource.package_name(%w{git package-does-not-exist})
      provider.load_current_resource
      expect { provider.run_action(:install) }.to raise_error(Chef::Exceptions::Package)
    end

    context "alternate source" do
      it "installing a package that does not exist throws an error" do
        allow_remote_list(["package-does-not-exist"], " -source alternate_source")
        new_resource.package_name("package-does-not-exist")
        new_resource.source("alternate_source")
        provider.load_current_resource
        expect { provider.run_action(:install) }.to raise_error(Chef::Exceptions::Package)
      end
    end

    context "private source" do
      it "installing a package without auth options throws an error" do
        allow_remote_list(["package-without-auth"], " -source auth_source")
        new_resource.package_name("package-without-auth")
        new_resource.source("auth_source")
        provider.load_current_resource
        expect { provider.run_action(:install) }.to raise_error(Chef::Exceptions::Package)
      end

      it "installing a package with invalid credentials throws an error" do
        allow_remote_list(["package-invalid-auth"], " -source auth_source -u user -p password")
        new_resource.package_name("package-invalid-auth")
        new_resource.source("auth_source")
        new_resource.options("-u user -p password")
        provider.load_current_resource
        expect { provider.run_action(:install) }.to raise_error(Chef::Exceptions::Package)
      end

      it "installing a package with valid credentials" do
        allow_remote_list(["git"], " -source auth_source -u user -p password")
        new_resource.source("auth_source")
        new_resource.options("-u user -p password")
        provider.load_current_resource
        expect(provider).to receive(:shell_out_compacted!).with("#{choco_exe} install -y -u user -p password -source auth_source git", { returns: [0], timeout: timeout }).and_return(double)
        provider.run_action(:install)
        expect(new_resource).to be_updated_by_last_action
      end
    end
  end

  describe "#action_upgrade" do
    it "should install a package that is not installed" do
      allow_remote_list(["git"])
      provider.load_current_resource
      expect(provider).to receive(:shell_out_compacted!).with("#{choco_exe} upgrade -y git", { returns: [0], timeout: timeout }).and_return(double)
      provider.run_action(:upgrade)
      expect(new_resource).to be_updated_by_last_action
    end

    it "should upgrade a package that is installed but upgradable" do
      allow_remote_list(["ConEmu"])
      new_resource.package_name("ConEmu")
      provider.load_current_resource
      expect(provider).to receive(:shell_out_compacted!).with("#{choco_exe} upgrade -y conemu", { returns: [0], timeout: timeout }).and_return(double)
      provider.run_action(:upgrade)
      expect(new_resource).to be_updated_by_last_action
    end

    it "should be case insensitive" do
      allow_remote_list(["conemu"])
      new_resource.package_name("conemu")
      provider.load_current_resource
      expect(provider).to receive(:shell_out_compacted!).with("#{choco_exe} upgrade -y conemu", { returns: [0], timeout: timeout }).and_return(double)
      provider.run_action(:upgrade)
      expect(new_resource).to be_updated_by_last_action
    end

    it "should not install a package that is up-to-date" do
      allow_remote_list(["chocolatey"])
      new_resource.package_name("chocolatey")
      provider.load_current_resource
      expect(provider).not_to receive(:shell_out_compacted!).with("#{choco_exe} upgrade -y chocolatey", { returns: [0], timeout: timeout })
      provider.run_action(:upgrade)
      expect(new_resource).not_to be_updated_by_last_action
    end

    it "version pins work as well" do
      allow_remote_list(["git"])
      new_resource.version("2.6.2")
      provider.load_current_resource
      expect(provider).to receive(:shell_out_compacted!).with("#{choco_exe} upgrade -y --version 2.6.2 git", { returns: [0], timeout: timeout })
      provider.run_action(:upgrade)
      expect(new_resource).to be_updated_by_last_action
    end

    it "upgrading multiple packages uses a single command" do
      allow_remote_list(%w{conemu git})
      new_resource.package_name(%w{conemu git})
      expect(provider).to receive(:shell_out_compacted!).with("#{choco_exe} upgrade -y conemu git", { returns: [0], timeout: timeout }).and_return(double)
      provider.run_action(:upgrade)
      expect(new_resource).to be_updated_by_last_action
    end

    it "upgrading a package that does not exist throws an error" do
      allow_remote_list(["package-does-not-exist"])
      new_resource.package_name("package-does-not-exist")
      provider.load_current_resource
      expect { provider.run_action(:upgrade) }.to raise_error(Chef::Exceptions::Package)
    end

    it "upgrading multiple packages with a package that does not exist throws an error" do
      allow_remote_list(%w{git package-does-not-exist})
      new_resource.package_name(%w{git package-does-not-exist})
      provider.load_current_resource
      expect { provider.run_action(:upgrade) }.to raise_error(Chef::Exceptions::Package)
    end

    context "alternate source" do
      it "installing a package that does not exist throws an error" do
        allow_remote_list(["package-does-not-exist"], " -source alternate_source")
        new_resource.package_name("package-does-not-exist")
        new_resource.source("alternate_source")
        provider.load_current_resource
        expect { provider.run_action(:upgrade) }.to raise_error(Chef::Exceptions::Package)
      end
    end
  end

  describe "#action_remove" do
    it "does nothing when the package is already removed" do
      allow_remote_list(["git"])
      provider.load_current_resource
      expect(provider).not_to receive(:remove_package)
      provider.run_action(:remove)
      expect(new_resource).not_to be_updated_by_last_action
    end

    it "does nothing when all the packages are already removed" do
      allow_remote_list(%w{git package-does-not-exist})
      new_resource.package_name(%w{git package-does-not-exist})
      provider.load_current_resource
      expect(provider).not_to receive(:remove_package)
      provider.run_action(:remove)
      expect(new_resource).not_to be_updated_by_last_action
    end

    it "removes a package" do
      allow_remote_list(["ConEmu"])
      new_resource.package_name("ConEmu")
      provider.load_current_resource
      expect(provider).to receive(:shell_out_compacted!).with("#{choco_exe} uninstall -y ConEmu", { returns: [0], timeout: timeout }).and_return(double)
      provider.run_action(:remove)
      expect(new_resource).to be_updated_by_last_action
    end

    it "is case-insensitive" do
      allow_remote_list(["conemu"])
      new_resource.package_name("conemu")
      provider.load_current_resource
      expect(provider).to receive(:shell_out_compacted!).with("#{choco_exe} uninstall -y conemu", { returns: [0], timeout: timeout }).and_return(double)
      provider.run_action(:remove)
      expect(new_resource).to be_updated_by_last_action
    end

    it "removes a single package when its the only one installed" do
      pending "this is a bug in the superclass"
      allow_remote_list(%w{git conemu})
      new_resource.package_name(%w{git conemu})
      provider.load_current_resource
      expect(provider).to receive(:shell_out_compacted!).with("#{choco_exe} uninstall -y conemu", { returns: [0], timeout: timeout }).and_return(double)
      provider.run_action(:remove)
      expect(new_resource).to be_updated_by_last_action
    end
  end
end

describe "behavior when Chocolatey is not installed" do
  let(:new_resource) { Chef::Resource::ChocolateyPackage.new("git") }

  let(:provider) do
    node = Chef::Node.new
    events = Chef::EventDispatch::Dispatcher.new
    run_context = Chef::RunContext.new(node, {}, events)
    Chef::Provider::Package::Chocolatey.new(new_resource, run_context)
  end

  before do
    # the shellout sometimes returns "", but test nil to be safe.
    allow(provider).to receive(:choco_install_path).and_return(nil)
    provider.instance_variable_set("@choco_install_path", nil)

    # we don't care what this returns, but we have to let it be called.
    allow(provider).to receive(:shell_out_compacted!).and_return(double(stdout: ""))
  end

  let(:error_regex) do
    /Could not locate.*install.*cookbook.*PowerShell.*GetEnvironmentVariable/m
  end

  context "#choco_exe" do
    it "triggers a MissingLibrary exception when Chocolatey is not installed" do
      expect { provider.send(:choco_exe) }.to raise_error(Chef::Exceptions::MissingLibrary, error_regex)
    end
  end

  context "#load_current_resource" do
    it "triggers a MissingLibrary exception when Chocolatey is not installed" do
      expect { provider.load_current_resource }.to raise_error(Chef::Exceptions::MissingLibrary, error_regex)
    end
  end
end
