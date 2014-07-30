#
# Author:: Bryan McLellan <btm@opscode.com>
# Copyright:: Copyright (c) 2012 Opscode, Inc.
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
require 'ostruct'

# based on the apt specs

describe Chef::Provider::Package::Ips do
  before(:each) do
    @node = Chef::Node.new
    @events = Chef::EventDispatch::Dispatcher.new
    @run_context = Chef::RunContext.new(@node, {}, @events)
    @new_resource = Chef::Resource::Package.new("crypto/gnupg", @run_context)
    @current_resource = Chef::Resource::Package.new("crypto/gnupg", @run_context)
    Chef::Resource::Package.stub(:new).and_return(@current_resource)
    @provider = Chef::Provider::Package::Ips.new(@new_resource, @run_context)
  end

  def local_output
    stdin  = StringIO.new
    stdout = ''
    stderr =<<-PKG_STATUS
pkg: info: no packages matching the following patterns you specified are
installed on the system.  Try specifying -r to query remotely:

   crypto/gnupg 
PKG_STATUS
    return OpenStruct.new(:stdout => stdout,:stdin => stdin,:stderr => stderr,:status => @status,:exitstatus => 1)
  end

  def remote_output

    stdout = <<-PKG_STATUS
          Name: security/sudo
       Summary: sudo - authority delegation tool
         State: Not Installed
     Publisher: omnios
       Version: 1.8.4.1 (1.8.4p1)
 Build Release: 5.11
        Branch: 0.151002
Packaging Date: April  1, 2012 05:55:52 PM
          Size: 2.57 MB
          FMRI: pkg://omnios/security/sudo@1.8.4.1,5.11-0.151002:20120401T175552Z
PKG_STATUS
  stdin = StringIO.new
  stderr = '' 
  return OpenStruct.new(:stdout => stdout,:stdin => stdin,:stderr => stderr,:status => @status,:exitstatus => 0)
  end

  context "when loading current resource" do
    it "should create a current resource with the name of the new_resource" do
      @provider.should_receive(:shell_out!).with("pkg info #{@new_resource.package_name}").and_return(local_output)
      @provider.should_receive(:shell_out!).with("pkg info -r #{@new_resource.package_name}").and_return(remote_output)
      Chef::Resource::Package.should_receive(:new).and_return(@current_resource)
      @provider.load_current_resource
    end

    it "should set the current resources package name to the new resources package name" do
      @provider.should_receive(:shell_out!).with("pkg info #{@new_resource.package_name}").and_return(local_output)
      @provider.should_receive(:shell_out!).with("pkg info -r #{@new_resource.package_name}").and_return(remote_output)
      @provider.load_current_resource
      @current_resource.package_name.should == @new_resource.package_name
    end

    it "should run pkg info with the package name" do
      @provider.should_receive(:shell_out!).with("pkg info #{@new_resource.package_name}").and_return(local_output)
      @provider.should_receive(:shell_out!).with("pkg info -r #{@new_resource.package_name}").and_return(remote_output)
      @provider.load_current_resource
    end

    it "should set the installed version to nil on the current resource if package state is not installed" do
      @provider.should_receive(:shell_out!).with("pkg info #{@new_resource.package_name}").and_return(local_output)
      @provider.should_receive(:shell_out!).with("pkg info -r #{@new_resource.package_name}").and_return(remote_output)
      @provider.load_current_resource
      @current_resource.version.should be_nil
    end

    it "should set the installed version if package has one" do
      local = local_output
      local.stdout = <<-INSTALLED
          Name: crypto/gnupg
       Summary: GNU Privacy Guard
   Description: A complete and free implementation of the OpenPGP Standard as
                defined by RFC4880.
      Category: Applications/System Utilities
         State: Installed
     Publisher: solaris
       Version: 2.0.17
 Build Release: 5.11
        Branch: 0.175.0.0.0.2.537
Packaging Date: October 19, 2011 09:14:50 AM
          Size: 8.07 MB
          FMRI: pkg://solaris/crypto/gnupg@2.0.17,5.11-0.175.0.0.0.2.537:20111019T091450Z
INSTALLED
      @provider.should_receive(:shell_out!).with("pkg info #{@new_resource.package_name}").and_return(local)
      @provider.should_receive(:shell_out!).with("pkg info -r #{@new_resource.package_name}").and_return(remote_output)
      @provider.load_current_resource
      @current_resource.version.should == "2.0.17"
    end

    it "should return the current resource" do
      @provider.should_receive(:shell_out!).with("pkg info #{@new_resource.package_name}").and_return(local_output)
      @provider.should_receive(:shell_out!).with("pkg info -r #{@new_resource.package_name}").and_return(remote_output)
      @provider.load_current_resource.should eql(@current_resource)
    end
  end

  context "when installing a package" do
    it "should run pkg install with the package name and version" do
      @provider.should_receive(:run_command_with_systems_locale).with({
        :command => "pkg install -q crypto/gnupg@2.0.17"
      })
      @provider.install_package("crypto/gnupg", "2.0.17")
    end


    it "should run pkg install with the package name and version and options if specified" do
      @provider.should_receive(:run_command_with_systems_locale).with({
        :command => "pkg --no-refresh install -q crypto/gnupg@2.0.17"
      })
      @new_resource.stub(:options).and_return("--no-refresh")
      @provider.install_package("crypto/gnupg", "2.0.17")
    end

    it "should not include the human-readable version in the candidate_version" do
      remote = remote_output
      remote.stdout = <<-PKG_STATUS
          Name: security/sudo
       Summary: sudo - authority delegation tool
         State: Not Installed
     Publisher: omnios
       Version: 1.8.4.1 (1.8.4p1)
 Build Release: 5.11
        Branch: 0.151002
Packaging Date: April  1, 2012 05:55:52 PM
          Size: 2.57 MB
          FMRI: pkg://omnios/security/sudo@1.8.4.1,5.11-0.151002:20120401T175552Z
PKG_STATUS
      @provider.should_receive(:shell_out!).with("pkg info #{@new_resource.package_name}").and_return(local_output)
      @provider.should_receive(:shell_out!).with("pkg info -r #{@new_resource.package_name}").and_return(remote)
      @provider.load_current_resource
      @current_resource.version.should be_nil
      @provider.candidate_version.should eql("1.8.4.1")
    end

    it "should not upgrade the package if it is already installed" do
      local = local_output
      local.stdout = <<-INSTALLED
          Name: crypto/gnupg
       Summary: GNU Privacy Guard
   Description: A complete and free implementation of the OpenPGP Standard as
                defined by RFC4880.
      Category: Applications/System Utilities
         State: Installed
     Publisher: solaris
       Version: 2.0.17
 Build Release: 5.11
        Branch: 0.175.0.0.0.2.537
Packaging Date: October 19, 2011 09:14:50 AM
          Size: 8.07 MB
          FMRI: pkg://solaris/crypto/gnupg@2.0.17,5.11-0.175.0.0.0.2.537:20111019T091450Z
INSTALLED
      remote = remote_output
      remote.stdout = <<-REMOTE
          Name: crypto/gnupg
       Summary: GNU Privacy Guard
   Description: A complete and free implementation of the OpenPGP Standard as
                defined by RFC4880.
      Category: Applications/System Utilities
         State: Not Installed
     Publisher: solaris
       Version: 2.0.18
 Build Release: 5.11
        Branch: 0.175.0.0.0.2.537
Packaging Date: October 19, 2011 09:14:50 AM
          Size: 8.07 MB
          FMRI: pkg://solaris/crypto/gnupg@2.0.18,5.11-0.175.0.0.0.2.537:20111019T091450Z
REMOTE

      @provider.should_receive(:shell_out!).with("pkg info #{@new_resource.package_name}").and_return(local)
      @provider.should_receive(:shell_out!).with("pkg info -r #{@new_resource.package_name}").and_return(remote)
      @provider.load_current_resource
      @provider.should_receive(:install_package).exactly(0).times
      @provider.action_install
    end

    context "when accept_license is true" do
      before do
        @new_resource.stub(:accept_license).and_return(true)
      end

      it "should run pkg install with the --accept flag" do
        @provider.should_receive(:run_command_with_systems_locale).with({
          :command => "pkg install -q --accept crypto/gnupg@2.0.17"
        })
        @provider.install_package("crypto/gnupg", "2.0.17")
      end
    end
  end

  context "when upgrading a package" do
    it "should run pkg install with the package name and version" do
      @provider.should_receive(:run_command_with_systems_locale).with({
        :command => "pkg install -q crypto/gnupg@2.0.17"
      })
      @provider.upgrade_package("crypto/gnupg", "2.0.17")
    end
  end

  context "when uninstalling a package" do
    it "should run pkg uninstall with the package name and version" do
      @provider.should_receive(:run_command_with_systems_locale).with({
        :command => "pkg uninstall -q crypto/gnupg@2.0.17"
      })
      @provider.remove_package("crypto/gnupg", "2.0.17")
    end

    it "should run pkg uninstall with the package name and version and options if specified" do
      @provider.should_receive(:run_command_with_systems_locale).with({
        :command => "pkg --no-refresh uninstall -q crypto/gnupg@2.0.17"
      })
      @new_resource.stub(:options).and_return("--no-refresh")
      @provider.remove_package("crypto/gnupg", "2.0.17")
    end
  end
end
