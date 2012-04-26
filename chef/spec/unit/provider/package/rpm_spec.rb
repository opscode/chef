#
# Author:: Joshua Timberman (<joshua@opscode.com>)
# Author:: Daniel DeLeo (<dan@opscode.com>)
# Copyright:: Copyright (c) 2008, 2010 Opscode, Inc.
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
require 'spec_helper'

describe Chef::Provider::Package::Rpm do
  include SpecHelpers::Providers::Package

  let(:package_name) { 'emacs' }
  let(:source_file) { "/tmp/emacs-21.4-20.el5.i386.rpm" }

  let(:assume_source_file_exists) { ::File.stub!(:exists?).and_return(true) }

  let(:pid) { mock('pid') }
  let(:stdout) { mock('stdout') }
  let(:stderr) { mock('stderr') }
  let(:stdin) { mock('stdin') }

  before(:each) do
    assume_source_file_exists
    new_resource.source source_file
  end

  context "when determining the current state of the package" do
    it "should create a current resource with the name of new_resource" do
      provider.stub!(:popen4).and_return(status)
      provider.load_current_resource
      provider.current_resource.name.should eql(package_name)
    end

    it "should set the current reource package name to the new resource package name" do
      provider.stub!(:popen4).and_return(status)
      provider.load_current_resource
      provider.current_resource.package_name.should eql(package_name)
    end

    it "should raise an exception if a source is supplied but not found" do
      ::File.stub!(:exists?).and_return(false)
      lambda { provider.load_current_resource }.should raise_error(Chef::Exceptions::Package)
    end

    it "should get the source package version from rpm if provided" do
      stdout = StringIO.new("emacs 21.4-20.el5")
      provider.should_receive(:popen4).with("rpm -qp --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n' /tmp/emacs-21.4-20.el5.i386.rpm").and_yield(pid, stdin, stdout, stderr).and_return(status)
      provider.should_receive(:popen4).with("rpm -q --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n' emacs").and_return(status)
      provider.load_current_resource
      provider.current_resource.package_name.should eql(package_name)
      provider.new_resource.version.should eql("21.4-20.el5")
    end

    it "should return the current version installed if found by rpm" do
      stdout = StringIO.new("emacs 21.4-20.el5")

      provider.
        should_receive(:popen4).
        with("rpm -qp --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n' /tmp/emacs-21.4-20.el5.i386.rpm").
        and_return(status)

      provider.
        should_receive(:popen4).
        with("rpm -q --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n' emacs").
        and_yield(pid, stdin, stdout, stderr).
        and_return(status)

      provider.load_current_resource
      provider.current_resource.version.should == "21.4-20.el5"
    end

    it "should raise an exception if the source is not set but we are installing" do
      new_resource = Chef::Resource::Package.new("emacs")
      provider = Chef::Provider::Package::Rpm.new(new_resource, run_context)
      lambda { provider.load_current_resource }.should raise_error(Chef::Exceptions::Package)
    end

    it "should raise an exception if rpm fails to run" do
      status = mock("Status", :exitstatus => -1)
      provider.stub!(:popen4).and_return(status)
      lambda { provider.load_current_resource }.should raise_error(Chef::Exceptions::Package)
    end
  end

  context "after the current resource is loaded" do
    before do
      current_resource = Chef::Resource::Package.new("emacs")
      provider.current_resource = current_resource
    end

    context "when installing or upgrading" do
      it "should run rpm -i with the package source to install" do
        provider.should_receive(:shell_out_with_systems_locale!).with("rpm  -i /tmp/emacs-21.4-20.el5.i386.rpm")
        provider.install_package("emacs", "21.4-20.el5")
      end

      it "should run rpm -U with the package source to upgrade" do
        provider.current_resource.version("21.4-19.el5")
        provider.should_receive(:shell_out_with_systems_locale!).with("rpm  -U /tmp/emacs-21.4-20.el5.i386.rpm")
        provider.upgrade_package("emacs", "21.4-20.el5")
      end

      it "should install from a path when the package is a path and the source is nil" do
        new_resource = Chef::Resource::Package.new("/tmp/emacs-21.4-20.el5.i386.rpm")
        provider = Chef::Provider::Package::Rpm.new(new_resource, run_context)
        new_resource.source.should == "/tmp/emacs-21.4-20.el5.i386.rpm"
        current_resource = Chef::Resource::Package.new("emacs")
        provider.current_resource = current_resource
        provider.should_receive(:shell_out_with_systems_locale!).with("rpm  -i /tmp/emacs-21.4-20.el5.i386.rpm")
        provider.install_package("/tmp/emacs-21.4-20.el5.i386.rpm", "21.4-20.el5")
      end

      it "should uprgrade from a path when the package is a path and the source is nil" do
        new_resource = Chef::Resource::Package.new("/tmp/emacs-21.4-20.el5.i386.rpm")
        provider = Chef::Provider::Package::Rpm.new(new_resource, run_context)
        new_resource.source.should == "/tmp/emacs-21.4-20.el5.i386.rpm"
        current_resource = Chef::Resource::Package.new("emacs")
        current_resource.version("21.4-19.el5")
        provider.current_resource = current_resource
        provider.should_receive(:shell_out_with_systems_locale!).with("rpm  -U /tmp/emacs-21.4-20.el5.i386.rpm")
        provider.upgrade_package("/tmp/emacs-21.4-20.el5.i386.rpm", "21.4-20.el5")
      end

      it "installs with custom options specified in the resource" do
        provider.candidate_version = '11'
        new_resource.options("--dbpath /var/lib/rpm")
        provider.should_receive(:shell_out_with_systems_locale!).with("rpm --dbpath /var/lib/rpm -i /tmp/emacs-21.4-20.el5.i386.rpm")
        provider.install_package(new_resource.name, provider.candidate_version)
      end
    end

    context "when removing the package" do
      it "should run rpm -e to remove the package" do
        provider.should_receive(:shell_out_with_systems_locale!).with("rpm  -e emacs-21.4-20.el5")
        provider.remove_package("emacs", "21.4-20.el5")
      end
    end
  end
end

