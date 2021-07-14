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

require "knife_spec_helper"
require "support/shared/integration/integration_helper"
require "support/shared/context/config"
require "openssl"

describe "knife client create", :workstation do
  include IntegrationSupport
  include KnifeSupport

  include_context "default config options"

  let(:out) { "Created client[bah]\n" }

  when_the_chef_server "is empty" do
    it "creates a new client" do
      knife("client create -k bah").should_succeed stderr: out
    end

    it "creates a new validator client" do
      knife("client create -k --validator bah").should_succeed stderr: out
      knife("client show bah").should_succeed <<~EOM
        admin:     false
        chef_type: client
        name:      bah
        validator: true
      EOM
    end

    it "refuses to add an existing client" do
      pending "Knife client create must not blindly overwrite an existing client"
      knife("client create -k bah").should_succeed stderr: out
      expect { knife("client create -k bah") }.to raise_error(Net::HTTPClientException)
    end

    it "saves the private key to a file" do
      Dir.mktmpdir do |tgt|
        File.open("#{tgt}/bah.pem", "w") { |pub| pub.write("test key") }
        knife("client create -f #{tgt}/bah.pem bah").should_succeed stderr: out
        expect(File).to exist("#{tgt}/bah.pem")
      end
    end

    it "reads the public key from a file" do
      Dir.mktmpdir do |tgt|
        key = OpenSSL::PKey::RSA.generate(1024)
        File.open("#{tgt}/public.pem", "w") { |pub| pub.write(key.public_key.to_pem) }
        knife("client create -p #{tgt}/public.pem bah").should_succeed stderr: out
      end
    end

    it "refuses to run if conflicting options are passed" do
      knife("client create -p public.pem --prevent-keygen blah").should_fail stderr: "FATAL: You cannot pass --public-key and --prevent-keygen\n", stdout: /^USAGE.*/
    end
  end
end
