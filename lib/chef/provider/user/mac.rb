#
# Author:: Ryan Cragun (<ryan@chef.io>)
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

require_relative "../../resource"
require_relative "../../dsl/declare_resource"
require_relative "../../mixin/shell_out"
require_relative "../../mixin/which"
require_relative "../user"
require_relative "../../resource/user/mac_user"
autoload :Plist, "plist"

class Chef
  class Provider
    class User
      # A macOS user provider that is compatible with default TCC restrictions
      # in macOS 10.14. See resource/user/mac_user.rb for complete description
      # of the mac_user resource
      class MacUser < Chef::Provider::User
        include Chef::Mixin::Which

        provides :mac_user
        provides :user, os: "darwin"

        attr_reader :user_plist, :admin_group_plist

        def load_current_resource
          @current_resource = Chef::Resource::User::MacUser.new(new_resource.username)
          current_resource.username(new_resource.username)

          reload_admin_group_plist
          reload_user_plist

          if user_plist
            current_resource.uid(user_plist[:uid][0])
            current_resource.gid(user_plist[:gid][0])
            current_resource.home(user_plist[:home][0])
            current_resource.shell(user_plist[:shell][0])
            current_resource.comment(user_plist[:comment][0])

            if user_plist[:is_hidden]
              current_resource.hidden(user_plist[:is_hidden][0] == "1" ? true : false)
            end

            shadow_hash = user_plist[:shadow_hash]
            if shadow_hash
              current_resource.password(shadow_hash[0]["SALTED-SHA512-PBKDF2"]["entropy"].string.unpack("H*")[0])
              current_resource.salt(shadow_hash[0]["SALTED-SHA512-PBKDF2"]["salt"].string.unpack("H*")[0])
              current_resource.iterations(shadow_hash[0]["SALTED-SHA512-PBKDF2"]["iterations"].to_i)
            end

            current_resource.secure_token(secure_token_enabled?)
            current_resource.admin(admin_user?)
          else
            @user_exists = false
            logger.trace("#{new_resource} user does not exist")
          end

          current_resource
        end

        def reload_admin_group_plist
          @admin_group_plist = nil

          admin_group_xml = run_dscl("read", "/Groups/admin")
          return nil unless admin_group_xml && admin_group_xml != ""

          @admin_group_plist = Plist.new(::Plist.parse_xml(admin_group_xml))
        end

        def reload_user_plist
          @user_plist = nil

          # Load the user information.
          begin
            user_xml = run_dscl("read", "/Users/#{new_resource.username}")
          rescue Chef::Exceptions::DsclCommandFailed
            return nil
          end

          return nil if user_xml.nil? || user_xml == ""

          @user_plist = Plist.new(::Plist.parse_xml(user_xml))

          return unless user_plist[:shadow_hash]

          shadow_hash_hex = user_plist[:shadow_hash][0]
          return unless shadow_hash_hex && shadow_hash_hex != ""

          # The password information is stored in the ShadowHashData key in the
          # plist. However, parsing it is a bit tricky as the value is itself
          # another encoded binary plist. We have to extract the encoded plist,
          # decode it from hex to a binary plist and then convert the binary
          # into XML plist. From there we can extract the hash data.
          #
          # NOTE: `dscl -read` and `plutil -convert` return different values for
          # ShadowHashData.
          #
          # `dscl` returns the value encoded as a hex string and stored as a <string>
          # `plutil` returns the value encoded as a base64 string stored as <data>
          #
          #  eg:
          #
          # spellchecker: disable
          #
          # <array>
          #   <string>77687920 63616e27 74206170 706c6520 6275696c 6420636f 6e736973 74656e74 20746f6f 6c696e67</string>
          # </array>
          #
          # vs
          #
          # <array>
          #   <data>AADKAAAKAA4LAA0MAAAAAAAAAAA=</data>
          # </array>
          #
          # spellchecker: disable
          #
          begin
            shadow_binary_plist = [shadow_hash_hex.delete(" ")].pack("H*")
            shadow_xml_plist = shell_out("plutil", "-convert", "xml1", "-o", "-", "-", input: shadow_binary_plist).stdout
            user_plist[:shadow_hash] = ::Plist.parse_xml(shadow_xml_plist)
          rescue Chef::Exceptions::PlistUtilCommandFailed, Chef::Exceptions::DsclCommandFailed
            nil
          end
        end

        #
        # User Provider Callbacks
        #

        def create_user
          uid = prop_is_set?(:uid) ? new_resource.uid : get_free_uid
          # 'sysadminctl' cannot create user with specified UID
          # on Mac where Chef does not have full disk access
          # But 'dscl' can
          run_dscl('create', "/Users/#{new_resource.username}",
                   'UniqueID', uid)
          if prop_is_set?(:comment)
            run_dscl('create', "/Users/#{new_resource.username}",
                     'RealName', new_resource.comment)
          else
            # 'comment' field is optional for mac_user
            # but 'load_current_resource' above needs it
            # otherwise it will fail
            run_dscl('create', "/Users/#{new_resource.username}",
                     'RealName', new_resource.username)
          end
          run_dscl('create', "/Users/#{new_resource.username}",
                   'UserShell', new_resource.shell)
          run_dscl('create', "/Users/#{new_resource.username}",
                   'NFSHomeDirectory', new_resource.home)
          if new_resource.admin
            run_dscl('append', '/Groups/admin', 'GroupMembership',
                     new_resource.username)
          end

          # Wait for the user to show up in the ds cache
          wait_for_user

          # Reload with up-to-date user information
          reload_user_plist
          reload_admin_group_plist

          if prop_is_set?(:hidden)
            set_hidden
          end

          if prop_is_set?(:password)
            converge_by("set password") { set_password }
          end

          if prop_is_set?(:gid)
            # NOTE: Here we're managing the primary group of the user which is
            # a departure from previous behavior. We could just set the
            # PrimaryGroupID for the user and move on if we decide that actual
            # group management should be done outside of the core resource.
            group_name, group_id, group_action = user_group_info

            group group_name do
              members new_resource.username
              gid group_id if group_id
              action group_action
              append true
            end

            converge_by("create primary group ID") do
              run_dscl("create", "/Users/#{new_resource.username}", "PrimaryGroupID", group_id)
            end
          end

          # createhomedir needs user GID set first
          # otherwise createhomedir will do nothing
          # Always create homedir for all users
          # because 'sysadminctl' does but 'dscl' does not
          unless ::File.directory?(new_resource.home) && ::File.exist?(new_resource.home)
            converge_by('create home directory') do
              shell_out!("createhomedir -c -u #{new_resource.username}")
            end
          end

          if diverged?(:secure_token)
            converge_by("alter SecureToken") { toggle_secure_token }
          end

          reload_user_plist
        end

        def compare_user
          @change_desc = []
          %i{comment shell uid gid salt password admin secure_token hidden}.each do |attr|
            if diverged?(attr)
              desc = "Update #{attr}"
              unless %i{password gid secure_token hidden}.include?(attr)
                desc << " from #{current_resource.send(attr)} to #{new_resource.send(attr)}"
              end
              @change_desc << desc
            end
          end
          !@change_desc.empty?
        end

        def manage_user
          %i{uid home}.each do |prop|
            raise Chef::Exceptions::User, "cannot modify #{prop} on macOS >= 10.14" if diverged?(prop)
          end

          if diverged?(:password)
            converge_by("alter password") { set_password }
          end

          if diverged?(:comment)
            converge_by("alter comment") do
              run_dscl("create", "/Users/#{new_resource.username}", "RealName", new_resource.comment)
            end
          end

          if diverged?(:shell)
            converge_by("alter shell") do
              run_dscl("create", "/Users/#{new_resource.username}", "UserShell", new_resource.shell)
            end
          end

          if diverged?(:secure_token)
            converge_by("alter SecureToken") { toggle_secure_token }
          end

          if diverged?(:admin)
            converge_by("alter admin group membership") do
              group "admin" do
                if new_resource.admin
                  members new_resource.username
                else
                  excluded_members new_resource.username
                end

                action :create
                append true
              end

              admins = admin_group_plist[:group_members]
              if new_resource.admin
                admins << user_plist[:guid][0]
              else
                admins.reject! { |m| m == user_plist[:guid][0] }
              end

              run_dscl("create", "/Groups/admin", "GroupMembers", admins)
            end

            reload_admin_group_plist
          end

          group_name, group_id, group_action = user_group_info
          group group_name do
            gid group_id if group_id
            members new_resource.username
            action group_action
            append true
          end

          if diverged?(:gid)
            converge_by("alter group membership") do
              run_dscl("create", "/Users/#{new_resource.username}", "PrimaryGroupID", group_id)
            end
          end

          if diverged?(:hidden)
            converge_by("alter hidden") { set_hidden }
          end

          reload_user_plist
        end

        def remove_user
          cmd = ["-deleteUser", new_resource.username]
          cmd << new_resource.manage_home ? "-secure" : "-keepHome"
          if %i{admin_username admin_password}.all? { |p| prop_is_set?(p) }
            cmd += ["-adminUser", new_resource.admin_username]
            cmd += ["-adminPassword", new_resource.admin_password]
          end

          # sysadminctl doesn't exit with a non-zero exit code if it encounters
          # a problem. We'll check stderr and make sure we see that it finished
          res = run_sysadminctl(cmd)
          unless /deleting record|not found/.match?(res.downcase)
            raise Chef::Exceptions::User, "error deleting user: #{res}"
          end

          reload_user_plist
          @user_exists = false
        end

        def lock_user
          run_dscl("append", "/Users/#{new_resource.username}", "AuthenticationAuthority", ";DisabledUser;")

          reload_user_plist
        end

        def unlock_user
          auth_string = user_plist[:auth_authority].reject! { |tag| tag == ";DisabledUser;" }.join.strip

          run_dscl("create", "/Users/#{new_resource.username}", "AuthenticationAuthority", auth_string)

          reload_user_plist
        end

        def locked?
          user_plist[:auth_authority].any? { |tag| tag == ";DisabledUser;" }
        rescue
          false
        end

        def check_lock
          @locked = locked?
        end

        #
        # Methods
        #

        def diverged?(prop)
          prop = prop.to_sym

          case prop
          when :password
            password_diverged?
          when :gid
            user_group_diverged?
          when :secure_token
            secure_token_diverged?
          when :hidden
            hidden_diverged?
          else
            # Other fields are have been set on current resource so just compare
            # them.
            !new_resource.send(prop).nil? && (new_resource.send(prop) != current_resource.send(prop))
          end
        end

        # Find the next available uid on the system.
        # Starting with 200 if `system` is set, 501 otherwise.
        def get_free_uid(search_limit = 1000)
          uid = nil
          base_uid = new_resource.system ? 200 : 501
          next_uid_guess = base_uid
          users_uids = run_dscl("list", "/Users", "uid")
          while next_uid_guess < search_limit + base_uid
            if users_uids&.match?(Regexp.new("#{Regexp.escape(next_uid_guess.to_s)}\n"))
              next_uid_guess += 1
            else
              uid = next_uid_guess
              break
            end
          end
          uid || raise("uid not found. Exhausted. Searched #{search_limit} times")
        end

        # Attempt to resolve the group name, gid, and the action required for
        # associated group resource. If a group exists we'll modify it, otherwise
        # create it.
        def user_group_info
          @user_group_info ||= if new_resource.gid.is_a?(String)
                                 begin
                                   g = Etc.getgrnam(new_resource.gid)
                                   [g.name, g.gid.to_s, :modify]
                                 rescue
                                   [new_resource.gid, nil, :create]
                                 end
                               else
                                 begin
                                   g = Etc.getgrgid(new_resource.gid)
                                   [g.name, g.gid.to_s, :modify]
                                 rescue
                                   [g.username, nil, :create]
                                 end
                               end
        end

        def secure_token_enabled?
          user_plist[:auth_authority].any? { |tag| tag == ";SecureToken;" }
        rescue
          false
        end

        def secure_token_diverged?
          new_resource.secure_token ? !secure_token_enabled? : secure_token_enabled?
        end

        def toggle_secure_token
          # Check for this lazily as we only need to validate for these credentials
          # if we're toggling secure token.
          unless %i{admin_username admin_password secure_token_password}.all? { |p| prop_is_set?(p) }
            raise Chef::Exceptions::User, "secure_token_password, admin_username and admin_password properties are required to modify SecureToken"
          end

          cmd = (new_resource.secure_token ? %w{-secureTokenOn} : %w{-secureTokenOff})
          cmd += [new_resource.username, "-password", new_resource.secure_token_password]
          cmd += ["-adminUser", new_resource.admin_username]
          cmd += ["-adminPassword", new_resource.admin_password]

          # sysadminctl doesn't exit with a non-zero exit code if it encounters
          # a problem. We'll check stderr and make sure we see that it finished
          res = run_sysadminctl(cmd)
          unless /done/.match?(res.downcase)
            raise Chef::Exceptions::User, "error when modifying SecureToken: #{res}"
          end

          # HACK: When SecureToken is enabled or disabled it requires the user
          # password in plaintext, which it verifies and uses as a key. It also
          # takes the liberty of _rehashing_ the password with a random salt and
          # iterations count and saves it back into the user ShadowHashData.
          #
          # Therefore, if we're configuring a user based upon existing shadow
          # hash data we'll have to set the password again so that future runs
          # of the client don't show password drift.
          set_password if prop_is_set?(:salt)
        end

        def user_group_diverged?
          return false unless prop_is_set?(:gid)

          group_name, group_id = user_group_info
          current_resource.gid != group_id.to_i
        end

        def hidden_diverged?
          return false unless prop_is_set?(:hidden)

          (current_resource.hidden ? 1 : 0) != hidden_value.to_i
        end

        def set_hidden
          run_dscl("create", "/Users/#{new_resource.username}", "IsHidden", hidden_value.to_i)
        end

        def hidden_value
          new_resource.hidden ? 1 : 0
        end

        def password_diverged?
          # There are three options for configuring the password:
          #   * ShadowHashData which includes the hash data as:
          #     * hashed entropy as the "password"
          #     * salt
          #     * iterations
          #   * Plaintext password
          #   * Not configuring it

          # Check for no desired password configuration
          return false unless prop_is_set?(:password)

          # Check for ShadowHashData divergence by comparing the entropy,
          # salt, and iterations.
          if prop_is_set?(:salt)
            return true if %i{salt iterations}.any? { |prop| diverged?(prop) }

            return new_resource.password != current_resource.password
          end

          # Check for plaintext password divergence. We don't actually know
          # what the stored password is but we can hash the given password with
          # stored salt and iterations, and compare the resulting entropy with
          # the saved entropy.
          OpenSSL::PKCS5.pbkdf2_hmac(
            new_resource.password,
            convert_to_binary(current_resource.salt),
            current_resource.iterations.to_i,
            128,
            OpenSSL::Digest.new("SHA512")
          ).unpack("H*")[0] != current_resource.password
        end

        def admin_user?
          admin_group_plist[:group_members].any? { |mem| mem == user_plist[:guid][0] }
        rescue
          false
        end

        def convert_to_binary(string)
          string.unpack("a2" * (string.size / 2)).collect { |i| i.hex.chr }.join
        end

        def set_password
          if prop_is_set?(:salt)
            entropy = StringIO.new(convert_to_binary(new_resource.password))
            salt = StringIO.new(convert_to_binary(new_resource.salt))
          else
            salt = StringIO.new(OpenSSL::Random.random_bytes(32))
            entropy = StringIO.new(
              OpenSSL::PKCS5.pbkdf2_hmac(
                new_resource.password,
                salt.string,
                new_resource.iterations,
                128,
                OpenSSL::Digest.new("SHA512")
              )
            )
          end

          shadow_hash = user_plist[:shadow_hash] ? user_plist[:shadow_hash][0] : {}
          shadow_hash["SALTED-SHA512-PBKDF2"] = {
            "entropy" => entropy,
            "salt" => salt,
            "iterations" => new_resource.iterations,
          }

          shadow_hash_binary = StringIO.new
          shell_out("plutil", "-convert", "binary1", "-o", "-", "-",
            input: shadow_hash.to_plist,
            live_stream: shadow_hash_binary)

          # Apple seem to have killed their dsimport documentation about the
          # dsimport record format. Perhaps that means our days of being able to
          # use dsimport without an admin password or perhaps at all could be
          # numbered. Here is the record format for posterity:
          #
          # End of record character
          # Escape character
          # Field separator
          # Value separator
          # Record type (Users, Groups, Computers, ComputerGroups, ComputerLists)
          # Number of properties
          # Property 1
          # ...
          # Property N
          #
          # The user password shadow data format breaks down as:
          #
          # 0x0A                                    End of record denoted by \n
          # 0x5C                                    Escaping is denoted by \
          # 0x3A                                    Fields are separated by :
          # 0x2C                                    Values are separated by ,
          # dsRecTypeStandard:Users                 The record type we're configuring
          # 2                                       How many properties we're going to set
          # dsAttrTypeStandard:RecordName           Property 1: our users record name
          # base64:dsAttrTypeNative:ShadowHashData  Property 2: our shadow hash data

          import_file = ::File.join(Chef::Config["file_cache_path"], "#{new_resource.username}_password_dsimport")
          ::File.open(import_file, "w+", 0600) do |f|
            f.write <<~DSIMPORT
              0x0A 0x5C 0x3A 0x2C dsRecTypeStandard:Users 2 dsAttrTypeStandard:RecordName base64:dsAttrTypeNative:ShadowHashData
              #{new_resource.username}:#{::Base64.strict_encode64(shadow_hash_binary.string)}
            DSIMPORT
          end

          run_dscl("delete", "/Users/#{new_resource.username}", "ShadowHashData")
          run_dsimport(import_file, "/Local/Default", "M")
          run_dscl("create", "/Users/#{new_resource.username}", "Password", "********")
        ensure
          ::File.delete(import_file) if import_file && ::File.exist?(import_file)
        end

        def wait_for_user
          timeout = Time.now + 5

          loop do

            run_dscl("read", "/Users/#{new_resource.username}", "ShadowHashData")
            break
          rescue Chef::Exceptions::DsclCommandFailed => e
            if Time.now < timeout
              sleep 0.1
            else
              raise Chef::Exceptions::User, e.message
            end

          end
        end

        def run_dsimport(*args)
          shell_out!("dsimport", args)
        end

        def run_sysadminctl(args)
          # sysadminctl doesn't exit with a non-zero code when errors are encountered
          # and outputs everything to STDERR instead of STDOUT and STDERR. Therefore we'll
          # return the STDERR and let the caller handle it.
          shell_out!("sysadminctl", args).stderr
        end

        def run_dscl(*args)
          result = shell_out("dscl", "-plist", ".", "-#{args[0]}", args[1..])
          return "" if ( args.first =~ /^delete/ ) && ( result.exitstatus != 0 )
          raise(Chef::Exceptions::DsclCommandFailed, "dscl error: #{result.inspect}") unless result.exitstatus == 0
          raise(Chef::Exceptions::DsclCommandFailed, "dscl error: #{result.inspect}") if /No such key: /.match?(result.stdout)

          result.stdout
        end

        def run_plutil(*args)
          result = shell_out("plutil", "-#{args[0]}", args[1..])
          raise(Chef::Exceptions::PlistUtilCommandFailed, "plutil error: #{result.inspect}") unless result.exitstatus == 0

          result.stdout
        end

        def prop_is_set?(prop)
          v = new_resource.send(prop.to_sym)

          !v.nil? && v != ""
        end

        class Plist
          DSCL_PROPERTY_MAP = {
              uid: "dsAttrTypeStandard:UniqueID",
              guid: "dsAttrTypeStandard:GeneratedUID",
              gid: "dsAttrTypeStandard:PrimaryGroupID",
              home: "dsAttrTypeStandard:NFSHomeDirectory",
              shell: "dsAttrTypeStandard:UserShell",
              comment: "dsAttrTypeStandard:RealName",
              password: "dsAttrTypeStandard:Password",
              auth_authority: "dsAttrTypeStandard:AuthenticationAuthority",
              shadow_hash: "dsAttrTypeNative:ShadowHashData",
              group_members: "dsAttrTypeStandard:GroupMembers",
              is_hidden: "dsAttrTypeNative:IsHidden",
          }.freeze

          attr_accessor :plist_hash, :property_map

          def initialize(plist_hash = {}, property_map = DSCL_PROPERTY_MAP)
            @plist_hash = plist_hash
            @property_map = property_map
          end

          def get(key)
            return nil unless property_map.key?(key)

            plist_hash[property_map[key]]
          end
          alias_method :[], :get

          def set(key, value)
            return nil unless property_map.key?(key)

            plist_hash[property_map[key]] = [ value ]
          end
          alias_method :[]=, :set

        end
      end
    end
  end
end
