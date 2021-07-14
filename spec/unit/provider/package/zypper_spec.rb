#
# Author:: Adam Jacob (<adam@chef.io>)
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

describe Chef::Provider::Package::Zypper do
  let!(:new_resource) { Chef::Resource::ZypperPackage.new("cups") }

  let!(:current_resource) { Chef::Resource::ZypperPackage.new("cups") }

  let(:provider) do
    node = Chef::Node.new
    events = Chef::EventDispatch::Dispatcher.new
    run_context = Chef::RunContext.new(node, {}, events)
    Chef::Provider::Package::Zypper.new(new_resource, run_context)
  end

  let(:status) { double(stdout: "\n", exitstatus: 0) }

  before(:each) do
    allow(Chef::Resource::Package).to receive(:new).and_return(current_resource)
    allow(provider).to receive(:shell_out_compacted!).and_return(status)
    allow(provider).to receive(:`).and_return("2.0")
  end

  def shell_out_expectation(*command, **options)
    options[:timeout] ||= 900
    expect(provider).to receive(:shell_out_compacted).with(*command, **options)
  end

  def shell_out_expectation!(*command, **options)
    options[:timeout] ||= 900
    expect(provider).to receive(:shell_out_compacted!).with(*command, **options)
  end

  describe "when loading the current package state" do
    it "should create a current resource with the name of the new_resource" do
      expect(Chef::Resource::Package).to receive(:new).with(new_resource.name).and_return(current_resource)
      provider.load_current_resource
    end

    it "should set the current resources package name to the new resources package name" do
      expect(current_resource).to receive(:package_name).with(new_resource.package_name)
      provider.load_current_resource
    end

    it "should run zypper info with the package name" do
      shell_out_expectation!(
        "zypper", "--non-interactive", "info", new_resource.package_name
      ).and_return(status)
      provider.load_current_resource
    end

    it "should set the installed version to nil on the current resource if zypper info installed version is (none)" do
      allow(provider).to receive(:shell_out_compacted).and_return(status)
      expect(current_resource).to receive(:version).with([nil]).and_return(true)
      provider.load_current_resource
    end

    it "should set the installed version if zypper info has one (zypper version < 1.13.0)" do
      status = double(stdout: "Version: 1.0\nInstalled: Yes\n", exitstatus: 0)

      allow(provider).to receive(:shell_out_compacted!).and_return(status)
      expect(current_resource).to receive(:version).with(["1.0"]).and_return(true)
      provider.load_current_resource
    end

    it "should set the installed version if zypper info has one (zypper version >= 1.13.0)" do
      status = double(stdout: "Version        : 1.0                             \nInstalled      : Yes                             \n", exitstatus: 0)

      allow(provider).to receive(:shell_out_compacted!).and_return(status)
      expect(current_resource).to receive(:version).with(["1.0"]).and_return(true)
      provider.load_current_resource
    end

    it "should set the installed version if zypper info has one (zypper version >= 1.13.17)" do
      status = double(stdout: "Version        : 1.0\nInstalled      : Yes (automatically)\n", exitstatus: 0)

      allow(provider).to receive(:shell_out_compacted!).and_return(status)
      expect(current_resource).to receive(:version).with(["1.0"]).and_return(true)
      provider.load_current_resource
    end

    it "should return the current resouce" do
      expect(provider.load_current_resource).to eql(current_resource)
    end
  end

  describe "install_package" do
    it "should run zypper install with the package name and version" do
      shell_out_expectation!(
        "zypper", "--non-interactive", "install", "--auto-agree-with-licenses", "--oldpackage", "emacs=1.0"
      )
      provider.install_package(["emacs"], ["1.0"])
    end

    it "should run zypper install with gpg checks" do
      shell_out_expectation!(
        "zypper", "--non-interactive", "install", "--auto-agree-with-licenses", "--oldpackage", "emacs=1.0"
      )
      provider.install_package(["emacs"], ["1.0"])
    end

    it "setting the property should disable gpg checks" do
      new_resource.gpg_check false
      shell_out_expectation!(
        "zypper", "--non-interactive", "--no-gpg-checks", "install", "--auto-agree-with-licenses", "--oldpackage", "emacs=1.0"
      )
      provider.install_package(["emacs"], ["1.0"])
    end

    it "setting the config variable should disable gpg checks" do
      Chef::Config[:zypper_check_gpg] = false
      shell_out_expectation!(
        "zypper", "--non-interactive", "--no-gpg-checks", "install", "--auto-agree-with-licenses", "--oldpackage", "emacs=1.0"
      )
      provider.install_package(["emacs"], ["1.0"])
    end

    it "setting the property should disallow downgrade" do
      new_resource.allow_downgrade false
      shell_out_expectation!(
        "zypper", "--non-interactive", "install", "--auto-agree-with-licenses", "emacs=1.0"
      )
      provider.install_package(["emacs"], ["1.0"])
    end

    it "should add user provided options to the command" do
      new_resource.options "--user-provided"
      shell_out_expectation!(
        "zypper", "--non-interactive", "install", "--user-provided", "--auto-agree-with-licenses", "--oldpackage", "emacs=1.0"
      )
      provider.install_package(["emacs"], ["1.0"])
    end

    it "should add user provided global options" do
      new_resource.global_options "--user-provided"
      shell_out_expectation!(
        "zypper", "--user-provided", "--non-interactive", "install", "--auto-agree-with-licenses", "--oldpackage", "emacs=1.0"
      )
      provider.install_package(["emacs"], ["1.0"])
    end

    it "should add multiple user provided global options" do
      new_resource.global_options "--user-provided1 --user-provided2"
      shell_out_expectation!(
        "zypper", "--user-provided1", "--user-provided2", "--non-interactive", "install", "--auto-agree-with-licenses", "--oldpackage", "emacs=1.0"
      )
      provider.install_package(["emacs"], ["1.0"])
    end
  end

  describe "upgrade_package" do
    it "should run zypper update with the package name and version" do
      shell_out_expectation!(
        "zypper", "--non-interactive", "install", "--auto-agree-with-licenses", "--oldpackage", "emacs=1.0"
      )
      provider.upgrade_package(["emacs"], ["1.0"])
    end
    it "should run zypper update without gpg checks when setting the property" do
      new_resource.gpg_check false
      shell_out_expectation!(
        "zypper", "--non-interactive", "--no-gpg-checks", "install", "--auto-agree-with-licenses", "--oldpackage", "emacs=1.0"
      )
      provider.upgrade_package(["emacs"], ["1.0"])
    end
    it "should run zypper update without gpg checks when setting the config variable" do
      Chef::Config[:zypper_check_gpg] = false
      shell_out_expectation!(
        "zypper", "--non-interactive", "--no-gpg-checks", "install", "--auto-agree-with-licenses", "--oldpackage", "emacs=1.0"
      )
      provider.upgrade_package(["emacs"], ["1.0"])
    end
    it "should add user provided options to the command" do
      new_resource.options "--user-provided"
      shell_out_expectation!(
        "zypper", "--non-interactive", "install", "--user-provided", "--auto-agree-with-licenses", "--oldpackage", "emacs=1.0"
      )
      provider.upgrade_package(["emacs"], ["1.0"])
    end
    it "should add user provided global options" do
      new_resource.global_options "--user-provided"
      shell_out_expectation!(
        "zypper", "--user-provided", "--non-interactive", "install", "--auto-agree-with-licenses", "--oldpackage", "emacs=1.0"
      )
      provider.upgrade_package(["emacs"], ["1.0"])
    end
  end

  describe "remove_package" do

    context "when package version is not explicitly specified" do
      it "should run zypper remove with the package name" do
        shell_out_expectation!(
          "zypper", "--non-interactive", "remove", "emacs"
        )
        provider.remove_package(["emacs"], [nil])
      end
    end

    context "when package version is explicitly specified" do
      it "should run zypper remove with the package name" do
        shell_out_expectation!(
          "zypper", "--non-interactive", "remove", "emacs=1.0"
        )
        provider.remove_package(["emacs"], ["1.0"])
      end
      it "should run zypper remove without gpg checks" do
        new_resource.gpg_check false
        shell_out_expectation!(
          "zypper", "--non-interactive", "--no-gpg-checks", "remove", "emacs=1.0"
        )
        provider.remove_package(["emacs"], ["1.0"])
      end
      it "should run zypper remove without gpg checks when the config is false" do
        Chef::Config[:zypper_check_gpg] = false
        shell_out_expectation!(
          "zypper", "--non-interactive", "--no-gpg-checks", "remove", "emacs=1.0"
        )
        provider.remove_package(["emacs"], ["1.0"])
      end
      it "should add user provided options to the command" do
        new_resource.options "--user-provided"
        shell_out_expectation!(
          "zypper", "--non-interactive", "remove", "--user-provided", "emacs=1.0"
        )
        provider.remove_package(["emacs"], ["1.0"])
      end
      it "should add user provided global options" do
        new_resource.global_options "--user-provided"
        shell_out_expectation!(
          "zypper", "--user-provided", "--non-interactive", "remove", "emacs=1.0"
        )
        provider.remove_package(["emacs"], ["1.0"])
      end

      it "should run zypper remove for non existing package" do
        shell_out_expectation!(
          "zypper", "--non-interactive", "remove", "noname=1.0"
        )
        provider.remove_package(["noname"], ["1.0"])
      end
    end
  end

  describe "purge_package" do
    it "should run remove with the name and version and --clean-deps" do
      shell_out_expectation!(
        "zypper", "--non-interactive", "remove", "--clean-deps", "emacs=1.0"
      )
      provider.purge_package(["emacs"], ["1.0"])
    end
    it "should run zypper purge without gpg checks" do
      new_resource.gpg_check false
      shell_out_expectation!(
        "zypper", "--non-interactive", "--no-gpg-checks", "remove", "--clean-deps", "emacs=1.0"
      )
      provider.purge_package(["emacs"], ["1.0"])
    end
    it "should run zypper purge without gpg checks when the config is false" do
      Chef::Config[:zypper_check_gpg] = false
      shell_out_expectation!(
        "zypper", "--non-interactive", "--no-gpg-checks", "remove", "--clean-deps", "emacs=1.0"
      )
      provider.purge_package(["emacs"], ["1.0"])
    end
    it "should add user provided options to the command" do
      new_resource.options "--user-provided"
      shell_out_expectation!(
        "zypper", "--non-interactive", "remove", "--user-provided", "--clean-deps", "emacs=1.0"
      )
      provider.purge_package(["emacs"], ["1.0"])
    end
    it "should add user provided global options" do
      new_resource.global_options "--user-provided"
      shell_out_expectation!(
        "zypper", "--user-provided", "--non-interactive", "remove", "--clean-deps", "emacs=1.0"
      )
      provider.purge_package(["emacs"], ["1.0"])
    end
  end

  describe "action_lock" do
    it "should lock if the package is not already locked" do
      expect(provider).to receive(:shell_out_compacted!).with(
        "zypper", "--non-interactive", "info", new_resource.package_name, timeout: 900
      ).and_return(status)
      expect(provider).to receive(:shell_out_compacted!).with(
        "zypper", "locks", timeout: 900
      ).and_return(instance_double(
        Mixlib::ShellOut, stdout: "1 | somethingelse | package | (any)"
      ))
      expect(provider).to receive(:lock_package).with(["cups"], [nil])

      provider.load_current_resource
      provider.action_lock
    end

    it "should not lock if the package is already locked" do
      expect(provider).to receive(:shell_out_compacted!).with(
        "zypper", "--non-interactive", "info", new_resource.package_name, timeout: 900
      ).and_return(status)
      expect(provider).to receive(:shell_out_compacted!).with(
        "zypper", "locks", timeout: 900
      ).and_return(instance_double(
        Mixlib::ShellOut, stdout: "1 | cups | package | (any)"
      ))
      expect(provider).to_not receive(:lock_package)

      provider.load_current_resource
      provider.action_lock
    end
  end

  describe "lock_package" do
    it "should run zypper addlock with the package name" do
      shell_out_expectation!(
        "zypper", "--non-interactive", "addlock", "emacs"
      )
      provider.lock_package(["emacs"], [nil])
    end
    it "should run zypper addlock without gpg checks" do
      new_resource.gpg_check false
      shell_out_expectation!(
        "zypper", "--non-interactive", "--no-gpg-checks", "addlock", "emacs"
      )
      provider.lock_package(["emacs"], [nil])
    end
    it "should add user provided options to the command" do
      new_resource.options "--user-provided"
      shell_out_expectation!(
        "zypper", "--non-interactive", "addlock", "--user-provided", "emacs"
      )
      provider.lock_package(["emacs"], [nil])
    end
    it "should add user provided global options" do
      new_resource.global_options "--user-provided"
      shell_out_expectation!(
        "zypper", "--user-provided", "--non-interactive", "addlock", "emacs"
      )
      provider.lock_package(["emacs"], [nil])
    end
  end

  describe "action_unlock" do
    it "should unlock if the package is not already unlocked" do
      allow(provider).to receive(:shell_out_compacted!).with(
        "zypper", "--non-interactive", "info", new_resource.package_name, timeout: 900
      ).and_return(status)
      allow(provider).to receive(:shell_out_compacted!).with(
        "zypper", "locks", timeout: 900
      ).and_return(instance_double(
        Mixlib::ShellOut, stdout: "1 | cups | package | (any)"
      ))
      expect(provider).to receive(:unlock_package).with(["cups"], [nil])

      provider.load_current_resource
      provider.action_unlock
    end
    it "should not unlock if the package is already unlocked" do
      allow(provider).to receive(:shell_out_compacted!).with(
        "zypper", "--non-interactive", "info", new_resource.package_name, timeout: 900
      ).and_return(status)
      allow(provider).to receive(:shell_out_compacted!).with(
        "zypper", "locks", timeout: 900
      ).and_return(instance_double(
        Mixlib::ShellOut, stdout: "1 | somethingelse | package | (any)"
      ))
      expect(provider).to_not receive(:unlock_package)

      provider.load_current_resource
      provider.action_unlock
    end
  end

  describe "unlock_package" do
    it "should run zypper removelock with the package name" do
      shell_out_expectation!(
        "zypper", "--non-interactive", "removelock", "emacs"
      )
      provider.unlock_package(["emacs"], [nil])
    end
    it "should run zypper removelock without gpg checks" do
      new_resource.gpg_check false
      shell_out_expectation!(
        "zypper", "--non-interactive", "--no-gpg-checks", "removelock", "emacs"
      )
      provider.unlock_package(["emacs"], [nil])
    end
    it "should add user provided options to the command" do
      new_resource.options "--user-provided"
      shell_out_expectation!(
        "zypper", "--non-interactive", "removelock", "--user-provided", "emacs"
      )
      provider.unlock_package(["emacs"], [nil])
    end
    it "should add user provided global options" do
      new_resource.global_options "--user-provided"
      shell_out_expectation!(
        "zypper", "--user-provided", "--non-interactive", "removelock", "emacs"
      )
      provider.unlock_package(["emacs"], [nil])
    end
  end

  describe "on an older zypper" do
    before(:each) do
      allow(provider).to receive(:`).and_return("0.11.6")
    end

    describe "install_package" do
      it "should run zypper install with the package name and version" do
        shell_out_expectation!(
          "zypper", "install", "--auto-agree-with-licenses", "--oldpackage", "-y", "emacs"
        )
        provider.install_package(["emacs"], ["1.0"])
      end
    end

    describe "upgrade_package" do
      it "should run zypper update with the package name and version" do
        shell_out_expectation!(
          "zypper", "install", "--auto-agree-with-licenses", "--oldpackage", "-y", "emacs"
        )
        provider.upgrade_package(["emacs"], ["1.0"])
      end
    end

    describe "remove_package" do
      it "should run zypper remove with the package name" do
        shell_out_expectation!(
          "zypper", "remove", "-y", "emacs"
        )
        provider.remove_package(["emacs"], ["1.0"])
      end
    end
  end

  describe "when installing multiple packages" do # https://github.com/chef/chef/issues/3570
    it "should install an array of package names and versions" do
      shell_out_expectation!(
        "zypper", "--non-interactive", "install", "--auto-agree-with-licenses", "--oldpackage", "emacs=1.0", "vim=2.0"
      )
      provider.install_package(%w{emacs vim}, ["1.0", "2.0"])
    end

    it "should remove an array of package names and versions" do
      shell_out_expectation!(
        "zypper", "--non-interactive", "remove", "emacs=1.0", "vim=2.0"
      )
      provider.remove_package(%w{emacs vim}, ["1.0", "2.0"])
    end
  end
end
