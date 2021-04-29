#
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
require "chef/mixin/shell_out"

# run this test only for following platforms.
exclude_test = !(%w{rhel fedora amazon}.include?(ohai[:platform_family]) && !File.exist?("/usr/bin/dnf"))
describe Chef::Resource::YumPackage, :requires_root, external: exclude_test do
  include Chef::Mixin::ShellOut

  # NOTE: every single test here either needs to explicitly call flush_cache or needs to explicitly
  # call preinstall (which explicitly calls flush_cache).  It is your responsibility to do one or the
  # other in order to minimize calling flush_cache a half dozen times per test.

  def flush_cache
    Chef::Resource::YumPackage.new("shouldnt-matter", run_context).run_action(:flush_cache)
  end

  def preinstall(*rpms)
    rpms.each do |rpm|
      shell_out!("rpm -ivh #{CHEF_SPEC_ASSETS}/yumrepo/#{rpm}")
    end
    flush_cache
  end

  before(:all) do
    shell_out!("yum -y install yum-utils")
  end

  before(:each) do
    File.open("/etc/yum.repos.d/chef-yum-localtesting.repo", "w+") do |f|
      f.write <<~EOF
        [chef-yum-localtesting]
        name=Chef DNF spec testing repo
        baseurl=file://#{CHEF_SPEC_ASSETS}/yumrepo
        enable=1
        gpgcheck=0
      EOF
    end
    shell_out!("rpm -qa --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | grep chef_rpm | xargs -r rpm -e")
    # next line is useful cleanup if you happen to have been testing both yum + dnf func tests on the same box and
    # have some dnf garbage left around
    FileUtils.rm_f "/etc/yum.repos.d/chef-dnf-localtesting.repo"
  end

  after(:all) do
    shell_out!("rpm -qa --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | grep chef_rpm | xargs -r rpm -e")
    FileUtils.rm_f "/etc/yum.repos.d/chef-yum-localtesting.repo"
  end

  let(:run_context) do
    Chef::RunContext.new(Chef::Node.new, {}, Chef::EventDispatch::Dispatcher.new)
  end

  let(:package_name) { "chef_rpm" }
  let(:yum_package) do
    r = Chef::Resource::YumPackage.new(package_name, run_context)
    r.options("--nogpgcheck")
    r
  end

  def pkg_arch
    ohai[:kernel][:machine]
  end

  describe ":install" do
    context "vanilla use case" do
      let(:package_name) { "chef_rpm" }

      it "installs if the package is not installed" do
        flush_cache
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
      end

      it "does not install if the package is installed" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
      end

      it "does not install twice" do
        flush_cache
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
      end

      it "does not install if the prior version package is installed" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
      end

      it "does not install if the i686 package is installed", :intel_64bit do
        skip "FIXME: do nothing, or install the #{pkg_arch} version?"
        preinstall("chef_rpm-1.10-1.i686.rpm")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.i686$")
      end

      it "does not install if the prior version i686 package is installed", :intel_64bit do
        skip "FIXME: do nothing, or install the #{pkg_arch} version?"
        preinstall("chef_rpm-1.2-1.i686.rpm")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.i686$")
      end
    end

    context "expanded idempotency checks with version variants" do
      # 0:1.10, 0:1.10-1, 0:1*-1 don't work on yum/el6
      %w{1.10 1* 1.10-1 1*-1 1.10-* 1*-* 0:1* *:1.10-* *:1*-*}.each do |vstring|
        it "installs the rpm when #{vstring} is in the package_name" do
          flush_cache
          yum_package.package_name("chef_rpm-#{vstring}")
          yum_package.run_action(:install)
          expect(yum_package.updated_by_last_action?).to be true
        end

        it "is idempotent when #{vstring} is in the package_name" do
          preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
          yum_package.package_name("chef_rpm-#{vstring}")
          yum_package.run_action(:install)
          expect(yum_package.updated_by_last_action?).to be false
        end

        it "installs the rpm when #{vstring} is in the version property" do
          flush_cache
          yum_package.package_name("chef_rpm")
          yum_package.version(vstring)
          yum_package.run_action(:install)
          expect(yum_package.updated_by_last_action?).to be true
        end

        it "is idempotent when #{vstring} is in the version property" do
          preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
          yum_package.package_name("chef_rpm")
          yum_package.version(vstring)
          yum_package.run_action(:install)
          expect(yum_package.updated_by_last_action?).to be false
        end

        it "upgrades the rpm when #{vstring} is in the package_name" do
          flush_cache
          yum_package.package_name("chef_rpm-#{vstring}")
          yum_package.run_action(:upgrade)
          expect(yum_package.updated_by_last_action?).to be true
        end

        it "is idempotent when #{vstring} is in the package_name" do
          preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
          yum_package.package_name("chef_rpm-#{vstring}")
          yum_package.run_action(:upgrade)
          expect(yum_package.updated_by_last_action?).to be false
        end

        it "upgrades the rpm when #{vstring} is in the version property" do
          flush_cache
          yum_package.package_name("chef_rpm")
          yum_package.version(vstring)
          yum_package.run_action(:upgrade)
          expect(yum_package.updated_by_last_action?).to be true
        end

        it "is idempotent when #{vstring} is in the version property" do
          preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
          yum_package.package_name("chef_rpm")
          yum_package.version(vstring)
          yum_package.run_action(:upgrade)
          expect(yum_package.updated_by_last_action?).to be false
        end
      end

      # 0:1.2 0:1.2-1 0:1*-1 don't work on yum/el6
      %w{1.2 1* 1.2-1 1*-1 1.2-* 1*-* 0:1* *:1.2-* *:1*-*}.each do |vstring|
        it "is idempotent when #{vstring} is in the version property and there is a candidate version" do
          preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
          yum_package.package_name("chef_rpm")
          yum_package.version(vstring)
          yum_package.run_action(:install)
          expect(yum_package.updated_by_last_action?).to be false
          expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        end
      end

      # 0:1.2, 0:1.2-1, 0:1*-1 don't work on yum/el6
      %w{1.2 1.2-1 1.2-* *:1.2-*}.each do |vstring|
        it "is idempotent when #{vstring} is in the version property on upgrade and it doesn't match the candidate version" do
          preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
          yum_package.package_name("chef_rpm")
          yum_package.version(vstring)
          yum_package.run_action(:upgrade)
          expect(yum_package.updated_by_last_action?).to be false
          expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        end
      end

      # 0:1.2, 0:1.2-1, 0:1*-1 don't work on yum/el6
      %w{1* 1*-1 1*-* 0:1* *:1*-*}.each do |vstring|
        it "upgrades when #{vstring} is in the version property on upgrade and it matches the candidate version" do
          preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
          yum_package.package_name("chef_rpm")
          yum_package.version(vstring)
          yum_package.run_action(:upgrade)
          expect(yum_package.updated_by_last_action?).to be true
          expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
          yum_package.run_action(:upgrade)
          expect(yum_package.updated_by_last_action?).to be false
        end
      end
    end

    context "with versions or globs in the name" do
      it "works with a version" do
        flush_cache
        yum_package.package_name("chef_rpm-1.10")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "works with an older version" do
        flush_cache
        yum_package.package_name("chef_rpm-1.2")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "works with an evra" do
        flush_cache
        yum_package.package_name("chef_rpm-0:1.2-1.#{pkg_arch}")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "works with version and release" do
        flush_cache
        yum_package.package_name("chef_rpm-1.2-1")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "works with a version glob" do
        flush_cache
        yum_package.package_name("chef_rpm-1*")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "works with a name glob + version glob" do
        flush_cache
        yum_package.package_name("chef_rp*-1*")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "upgrades when the installed version does not match the version string" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.package_name("chef_rpm-1.10")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "downgrades when the installed version is higher than the package_name version" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.allow_downgrade true
        yum_package.package_name("chef_rpm-1.2")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end
    end

    # version only matches the actual yum version, does not work with epoch or release or combined evr
    context "with version property" do
      it "matches the full version" do
        flush_cache
        yum_package.package_name("chef_rpm")
        yum_package.version("1.10")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "matches with a glob" do
        flush_cache
        yum_package.package_name("chef_rpm")
        yum_package.version("1*")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "matches the vr" do
        flush_cache
        yum_package.package_name("chef_rpm")
        yum_package.version("1.10-1")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "matches the evr" do
        flush_cache
        yum_package.package_name("chef_rpm")
        yum_package.version("0:1.10-1")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "matches with a vr glob" do
        flush_cache
        yum_package.package_name("chef_rpm")
        yum_package.version("1.10-1*")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "matches with an evr glob" do
        flush_cache
        yum_package.package_name("chef_rpm")
        yum_package.version("0:1.10-1*")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end
    end

    context "downgrades" do
      it "downgrades the package when allow_downgrade" do
        flush_cache
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.package_name("chef_rpm")
        yum_package.allow_downgrade true
        yum_package.version("1.2-1")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end
    end

    context "with arches", :intel_64bit do
      it "installs with 64-bit arch in the name" do
        flush_cache
        yum_package.package_name("chef_rpm.#{pkg_arch}")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "installs with 32-bit arch in the name" do
        flush_cache
        yum_package.package_name("chef_rpm.i686")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.i686$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "installs with 64-bit arch in the property" do
        flush_cache
        yum_package.package_name("chef_rpm")
        yum_package.arch((pkg_arch).to_s)
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "installs with 32-bit arch in the property" do
        flush_cache
        yum_package.package_name("chef_rpm")
        yum_package.arch("i686")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.i686$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "installs when the 32-bit arch is in the name and the version is in the property" do
        flush_cache
        yum_package.package_name("chef_rpm.i686")
        yum_package.version("1.10-1")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.i686$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "installs when the 64-bit arch is in the name and the version is in the property" do
        flush_cache
        yum_package.package_name("chef_rpm.#{pkg_arch}")
        yum_package.version("1.10-1")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end
    end

    context "with constraints" do
      it "with nothing installed, it installs the latest version" do
        flush_cache
        yum_package.package_name("chef_rpm >= 1.2")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "when it is met, it does nothing" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.package_name("chef_rpm >= 1.2")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
      end

      it "when it is met, it does nothing" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.package_name("chef_rpm >= 1.2")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
      end

      it "with nothing installed, it installs the latest version" do
        flush_cache
        yum_package.package_name("chef_rpm > 1.2")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "when it is not met by an installed rpm, it upgrades" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.package_name("chef_rpm > 1.2")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "with an equality constraint, when it is not met by an installed rpm, it upgrades" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.package_name("chef_rpm = 1.10")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "with an equality constraint, when it is met by an installed rpm, it does nothing" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.package_name("chef_rpm = 1.2")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
      end

      it "when it is met by an installed rpm, it does nothing" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.package_name("chef_rpm > 1.2")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
      end

      it "when there is no solution to the contraint" do
        flush_cache
        yum_package.package_name("chef_rpm > 2.0")
        expect { yum_package.run_action(:install) }.to raise_error(Chef::Exceptions::Package, /No candidate version available/)
      end

      it "when there is no solution to the contraint but an rpm is preinstalled" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.package_name("chef_rpm > 2.0")
        expect { yum_package.run_action(:install) }.to raise_error(Chef::Exceptions::Package, /No candidate version available/)
      end

      it "with a less than constraint, when nothing is installed, it installs" do
        flush_cache
        yum_package.allow_downgrade true
        yum_package.package_name("chef_rpm < 1.10")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "with a less than constraint, when the install version matches, it does nothing" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.allow_downgrade true
        yum_package.package_name("chef_rpm < 1.10")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
      end

      it "with a less than constraint, when the install version fails, it should downgrade" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.allow_downgrade true
        yum_package.package_name("chef_rpm < 1.10")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end
    end

    context "with source arguments" do
      it "raises an exception when the package does not exist" do
        flush_cache
        yum_package.package_name("#{CHEF_SPEC_ASSETS}/yumrepo/this-file-better-not-exist.rpm")
        expect { yum_package.run_action(:install) }.to raise_error(Chef::Exceptions::Package, /No candidate version available/)
      end

      it "does not raise a hard exception in why-run mode when the package does not exist" do
        Chef::Config[:why_run] = true
        flush_cache
        yum_package.package_name("#{CHEF_SPEC_ASSETS}/yumrepo/this-file-better-not-exist.rpm")
        yum_package.run_action(:install)
        expect { yum_package.run_action(:install) }.not_to raise_error
      end

      it "installs the package when using the source argument" do
        flush_cache
        yum_package.name "something"
        yum_package.package_name "somethingelse"
        yum_package.source("#{CHEF_SPEC_ASSETS}/yumrepo/chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "installs the package when the name is a path to a file" do
        flush_cache
        yum_package.package_name("#{CHEF_SPEC_ASSETS}/yumrepo/chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "downgrade on a local file is ignored when allow_downgrade is false" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.allow_downgrade false
        yum_package.version "1.2-1"
        yum_package.package_name("#{CHEF_SPEC_ASSETS}/yumrepo/chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
      end

      it "downgrade on a local file with allow_downgrade true works" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.version "1.2-1"
        yum_package.allow_downgrade true
        yum_package.package_name("#{CHEF_SPEC_ASSETS}/yumrepo/chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "does not downgrade the package with :install" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.package_name("#{CHEF_SPEC_ASSETS}/yumrepo/chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
      end

      it "does not upgrade the package with :install" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.package_name("#{CHEF_SPEC_ASSETS}/yumrepo/chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
      end

      it "is idempotent when the package is already installed" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.package_name("#{CHEF_SPEC_ASSETS}/yumrepo/chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
      end

      it "is idempotent when the package is already installed and there is a version string" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.version "1.2-1"
        yum_package.package_name("#{CHEF_SPEC_ASSETS}/yumrepo/chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
      end
    end

    context "with no available version" do
      it "works when a package is installed" do
        FileUtils.rm_f "/etc/yum.repos.d/chef-yum-localtesting.repo"
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
      end

      it "works with a local source" do
        FileUtils.rm_f "/etc/yum.repos.d/chef-yum-localtesting.repo"
        flush_cache
        yum_package.package_name("#{CHEF_SPEC_ASSETS}/yumrepo/chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end
    end

    context "multipackage with arches", :intel_64bit do
      it "installs two rpms" do
        flush_cache
        yum_package.package_name([ "chef_rpm.#{pkg_arch}", "chef_rpm.i686" ] )
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match(/^chef_rpm-1.10-1.#{pkg_arch}$/)
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match(/^chef_rpm-1.10-1.i686$/)
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "does nothing if both are installed" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm", "chef_rpm-1.10-1.i686.rpm")
        flush_cache
        yum_package.package_name([ "chef_rpm.#{pkg_arch}", "chef_rpm.i686" ] )
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "installs the second rpm if the first is installed" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.package_name([ "chef_rpm.#{pkg_arch}", "chef_rpm.i686" ] )
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match(/^chef_rpm-1.10-1.#{pkg_arch}$/)
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match(/^chef_rpm-1.10-1.i686$/)
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "installs the first rpm if the second is installed" do
        preinstall("chef_rpm-1.10-1.i686.rpm")
        yum_package.package_name([ "chef_rpm.#{pkg_arch}", "chef_rpm.i686" ] )
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match(/^chef_rpm-1.10-1.#{pkg_arch}$/)
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match(/^chef_rpm-1.10-1.i686$/)
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      # unlikely to work consistently correct, okay to deprecate the arch-array in favor of the arch in the name
      it "installs two rpms with multi-arch" do
        flush_cache
        yum_package.package_name(%w{chef_rpm chef_rpm} )
        yum_package.arch([pkg_arch, "i686"])
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match(/^chef_rpm-1.10-1.#{pkg_arch}$/)
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match(/^chef_rpm-1.10-1.i686$/)
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      # unlikely to work consistently correct, okay to deprecate the arch-array in favor of the arch in the name
      it "installs the second rpm if the first is installed (muti-arch)" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.package_name(%w{chef_rpm chef_rpm} )
        yum_package.arch([pkg_arch, "i686"])
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match(/^chef_rpm-1.10-1.#{pkg_arch}$/)
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match(/^chef_rpm-1.10-1.i686$/)
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      # unlikely to work consistently correct, okay to deprecate the arch-array in favor of the arch in the name
      it "installs the first rpm if the second is installed (muti-arch)" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.package_name(%w{chef_rpm chef_rpm} )
        yum_package.arch([pkg_arch, "i686"])
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match(/^chef_rpm-1.10-1.#{pkg_arch}$/)
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match(/^chef_rpm-1.10-1.i686$/)
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      # unlikely to work consistently correct, okay to deprecate the arch-array in favor of the arch in the name
      it "does nothing if both are installed (muti-arch)" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm", "chef_rpm-1.10-1.i686.rpm")
        yum_package.package_name(%w{chef_rpm chef_rpm} )
        yum_package.arch([pkg_arch, "i686"])
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end
    end

    context "repo controls" do
      it "should fail with the repo disabled" do
        flush_cache
        yum_package.options("--disablerepo=chef-yum-localtesting")
        expect { yum_package.run_action(:install) }.to raise_error(Chef::Exceptions::Package, /No candidate version available/)
      end

      it "should work with disablerepo first" do
        flush_cache
        yum_package.options(["--disablerepo=*", "--enablerepo=chef-yum-localtesting"])
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "should work to enable a disabled repo" do
        shell_out!("yum-config-manager --disable chef-yum-localtesting")
        flush_cache
        expect { yum_package.run_action(:install) }.to raise_error(Chef::Exceptions::Package, /No candidate version available/)
        flush_cache
        yum_package.options("--enablerepo=chef-yum-localtesting")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "when an idempotent install action is run, does not leave repos disabled" do
        flush_cache
        # this is a bit tricky -- we need this action to be idempotent, so that it doesn't recycle any
        # caches, but need it to hit whatavailable with the repo disabled.  using :upgrade like this
        # accomplishes both those goals (it would be easier if we had other rpms in this repo, but with
        # one rpm we need to do this).
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.options("--disablerepo=chef-yum-localtesting")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        # now we're still using the same cache in the yum_helper.py cache and we test to see if the
        # repo that we temporarily disabled is enabled on this pass.
        yum_package.package_name("chef_rpm-1.10-1.#{pkg_arch}")
        yum_package.options(nil)
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:install)
        expect(yum_package.updated_by_last_action?).to be false
      end
    end
  end

  describe ":upgrade" do

    context "with source arguments" do
      it "installs the package when using the source argument" do
        flush_cache
        yum_package.name "something"
        yum_package.package_name "somethingelse"
        yum_package.source("#{CHEF_SPEC_ASSETS}/yumrepo/chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "installs the package when the name is a path to a file" do
        flush_cache
        yum_package.package_name("#{CHEF_SPEC_ASSETS}/yumrepo/chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "downgrades the package when allow_downgrade is true" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.allow_downgrade true
        yum_package.package_name("#{CHEF_SPEC_ASSETS}/yumrepo/chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "upgrades the package" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.package_name("#{CHEF_SPEC_ASSETS}/yumrepo/chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "is idempotent when the package is already installed" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.package_name("#{CHEF_SPEC_ASSETS}/yumrepo/chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
      end
    end

    context "with no available version" do
      it "works when a package is installed" do
        FileUtils.rm_f "/etc/yum.repos.d/chef-yum-localtesting.repo"
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.package_name("#{CHEF_SPEC_ASSETS}/yumrepo/chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
      end

      it "works with a local source" do
        FileUtils.rm_f "/etc/yum.repos.d/chef-yum-localtesting.repo"
        flush_cache
        yum_package.package_name("#{CHEF_SPEC_ASSETS}/yumrepo/chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
      end
    end

    context "version pinning" do
      it "with a full version pin it installs a later package" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.package_name("chef_rpm")
        yum_package.version("1.10-1")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "with a full version pin in the name it downgrades the package" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.allow_downgrade true
        yum_package.package_name("chef_rpm")
        yum_package.version("1.2-1")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "with a partial (no release) version pin it installs a later package" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.package_name("chef_rpm")
        yum_package.version("1.10")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "with a partial (no release) version pin in the name it downgrades the package" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.allow_downgrade true
        yum_package.package_name("chef_rpm")
        yum_package.version("1.2")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "with a full version pin it installs a later package" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.package_name("chef_rpm-1.10-1")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "with a full version pin in the name it downgrades the package" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.allow_downgrade true
        yum_package.package_name("chef_rpm-1.2-1")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "with a partial (no release) version pin it installs a later package" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.package_name("chef_rpm-1.10")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "with a partial (no release) version pin in the name it downgrades the package" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.allow_downgrade true
        yum_package.package_name("chef_rpm-1.2")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "with a prco equality pin in the name it upgrades a prior package" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.package_name("chef_rpm = 1.10")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "with a prco equality pin in the name it downgrades a later package" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.allow_downgrade true
        yum_package.package_name("chef_rpm == 1.2")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "with a > pin in the name and no rpm installed it installs" do
        flush_cache
        yum_package.package_name("chef_rpm > 1.2")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "with a < pin in the name and no rpm installed it installs" do
        flush_cache
        yum_package.package_name("chef_rpm < 1.10")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "with a > pin in the name and matching rpm installed it does nothing" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.package_name("chef_rpm > 1.2")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
      end

      it "with a < pin in the name and no rpm installed it installs" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.package_name("chef_rpm < 1.10")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
      end

      it "with a > pin in the name and non-matching rpm installed it upgrades" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.package_name("chef_rpm > 1.2")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "with a < pin in the name and non-matching rpm installed it downgrades" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.allow_downgrade true
        yum_package.package_name("chef_rpm < 1.10")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.#{pkg_arch}$")
        yum_package.run_action(:upgrade)
        expect(yum_package.updated_by_last_action?).to be false
      end
    end
  end

  describe ":remove" do
    context "vanilla use case" do
      let(:package_name) { "chef_rpm" }
      it "does nothing if the package is not installed" do
        flush_cache
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^package chef_rpm is not installed$")
      end

      it "removes the package if the package is installed" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^package chef_rpm is not installed$")
      end

      it "does not remove the package twice" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^package chef_rpm is not installed$")
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^package chef_rpm is not installed$")
      end

      it "removes the package if the prior version package is installed" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^package chef_rpm is not installed$")
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "removes the package if the i686 package is installed", :intel_64bit do
        skip "FIXME: should this be fixed or is the current behavior correct?"
        preinstall("chef_rpm-1.10-1.i686.rpm")
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^package chef_rpm is not installed$")
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "removes the package if the prior version i686 package is installed", :intel_64bit do
        skip "FIXME: should this be fixed or is the current behavior correct?"
        preinstall("chef_rpm-1.2-1.i686.rpm")
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^package chef_rpm is not installed$")
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be false
      end
    end

    context "with 64-bit arch", :intel_64bit do
      let(:package_name) { "chef_rpm.#{pkg_arch}" }
      it "does nothing if the package is not installed" do
        flush_cache
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^package chef_rpm is not installed$")
      end

      it "removes the package if the package is installed" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm")
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^package chef_rpm is not installed$")
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "removes the package if the prior version package is installed" do
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^package chef_rpm is not installed$")
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be false
      end

      it "does nothing if the i686 package is installed" do
        preinstall("chef_rpm-1.10-1.i686.rpm")
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.i686$")
      end

      it "does nothing if the prior version i686 package is installed" do
        preinstall("chef_rpm-1.2-1.i686.rpm")
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be false
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.2-1.i686$")
      end
    end

    context "with 32-bit arch", :intel_64bit do
      let(:package_name) { "chef_rpm.i686" }
      it "removes only the 32-bit arch if both are installed" do
        preinstall("chef_rpm-1.10-1.#{pkg_arch}.rpm", "chef_rpm-1.10-1.i686.rpm")
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^chef_rpm-1.10-1.#{pkg_arch}$")
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be false
      end
    end

    context "with no available version" do
      it "works when a package is installed" do
        FileUtils.rm_f "/etc/yum.repos.d/chef-yum-localtesting.repo"
        preinstall("chef_rpm-1.2-1.#{pkg_arch}.rpm")
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be true
        expect(shell_out("rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' chef_rpm").stdout.chomp).to match("^package chef_rpm is not installed$")
        yum_package.run_action(:remove)
        expect(yum_package.updated_by_last_action?).to be false
      end
    end
  end

  describe ":lock and :unlock" do
    before(:all) do
      shell_out!("yum -y install yum-versionlock")
    end

    before(:each) do
      shell_out("yum versionlock delete '*:chef_rpm-*'") # will exit with error when nothing is locked, we don't care
    end

    it "locks an rpm" do
      flush_cache
      yum_package.package_name("chef_rpm")
      yum_package.run_action(:lock)
      expect(yum_package.updated_by_last_action?).to be true
      expect(shell_out("yum versionlock list").stdout.chomp).to match("^0:chef_rpm-")
      yum_package.run_action(:lock)
      expect(yum_package.updated_by_last_action?).to be false
    end

    it "does not lock if its already locked" do
      flush_cache
      shell_out!("yum versionlock add chef_rpm")
      yum_package.package_name("chef_rpm")
      yum_package.run_action(:lock)
      expect(yum_package.updated_by_last_action?).to be false
      expect(shell_out("yum versionlock list").stdout.chomp).to match("^0:chef_rpm-")
    end

    it "unlocks an rpm" do
      flush_cache
      shell_out!("yum versionlock add chef_rpm")
      yum_package.package_name("chef_rpm")
      yum_package.run_action(:unlock)
      expect(yum_package.updated_by_last_action?).to be true
      expect(shell_out("yum versionlock list").stdout.chomp).not_to match("^0:chef_rpm-")
      yum_package.run_action(:unlock)
      expect(yum_package.updated_by_last_action?).to be false
    end

    it "does not unlock an already locked rpm" do
      flush_cache
      yum_package.package_name("chef_rpm")
      yum_package.run_action(:unlock)
      expect(yum_package.updated_by_last_action?).to be false
      expect(shell_out("yum versionlock list").stdout.chomp).not_to match("^0:chef_rpm-")
    end

    it "check that we can lock based on provides" do
      flush_cache
      yum_package.package_name("chef_rpm_provides")
      yum_package.run_action(:lock)
      expect(yum_package.updated_by_last_action?).to be true
      expect(shell_out("yum versionlock list").stdout.chomp).to match("^0:chef_rpm-")
      yum_package.run_action(:lock)
      expect(yum_package.updated_by_last_action?).to be false
    end

    it "check that we can unlock based on provides" do
      flush_cache
      shell_out!("yum versionlock add chef_rpm")
      yum_package.package_name("chef_rpm_provides")
      yum_package.run_action(:unlock)
      expect(yum_package.updated_by_last_action?).to be true
      expect(shell_out("yum versionlock list").stdout.chomp).not_to match("^0:chef_rpm-")
      yum_package.run_action(:unlock)
      expect(yum_package.updated_by_last_action?).to be false
    end
  end
end
