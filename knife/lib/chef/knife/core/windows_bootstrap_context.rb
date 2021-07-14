#
# Author:: Seth Chisamore (<schisamo@chef.io>)
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

require_relative "bootstrap_context"
require "chef-config/path_helper" unless defined?(ChefConfig::PathHelper)
require "chef-utils/dist" unless defined?(ChefUtils::Dist)

class Chef
  class Knife
    module Core
      # Instances of BootstrapContext are the context objects (i.e., +self+) for
      # bootstrap templates. For backwards compatibility, they +must+ set the
      # following instance variables:
      # * @config   - a hash of knife's config values
      # * @run_list - the run list for the node to bootstrap
      #
      class WindowsBootstrapContext < BootstrapContext
        attr_accessor :config
        attr_accessor :chef_config
        attr_accessor :secret

        def initialize(config, run_list, chef_config, secret = nil)
          @config       = config
          @run_list     = run_list
          @chef_config  = chef_config
          @secret       = secret
          super(config, run_list, chef_config, secret)
        end

        def validation_key
          if File.exist?(File.expand_path(chef_config[:validation_key]))
            IO.read(File.expand_path(chef_config[:validation_key]))
          else
            false
          end
        end

        def encrypted_data_bag_secret
          escape_and_echo(@secret)
        end

        def trusted_certs_script
          @trusted_certs_script ||= trusted_certs_content
        end

        def config_content
          # The windows: true / windows: false in the block that follows is more than a bit weird.  The way to read this is that we need
          # the e.g. var_chef_dir to be rendered for the windows value ("C:\chef"), but then we are rendering into a file to be read by
          # ruby, so we don't actually care about forward-vs-backslashes and by rendering into unix we avoid having to deal with the
          # double-backwhacking of everything.  So we expect to see:
          #
          # file_cache_path "C:/chef"
          #
          # Which is mildly odd, but should be entirely correct as far as ruby cares.
          #
          client_rb = <<~CONFIG
            chef_server_url  "#{chef_config[:chef_server_url]}"
            validation_client_name "#{chef_config[:validation_client_name]}"
            file_cache_path   "#{ChefConfig::PathHelper.escapepath(chef_config[:windows_bootstrap_file_cache_path] || "")}"
            file_backup_path  "#{ChefConfig::PathHelper.escapepath(chef_config[:windows_bootstrap_file_backup_path] || "")}"
            cache_options     ({:path => "#{ChefConfig::PathHelper.escapepath(ChefConfig::Config.etc_chef_dir(windows: true))}\\\\cache\\\\checksums", :skip_expires => true})
          CONFIG

          unless chef_config[:chef_license].nil?
            client_rb << "chef_license \"#{chef_config[:chef_license]}\"\n"
          end

          if config[:chef_node_name]
            client_rb << %Q{node_name "#{config[:chef_node_name]}"\n}
          else
            client_rb << "# Using default node name (fqdn)\n"
          end

          if chef_config[:config_log_level]
            client_rb << %Q{log_level :#{chef_config[:config_log_level]}\n}
          else
            client_rb << "log_level        :auto\n"
          end

          client_rb << "log_location       #{get_log_location}"

          # We configure :verify_api_cert only when it's overridden on the CLI
          # or when specified in the knife config.
          if !config[:node_verify_api_cert].nil? || config.key?(:verify_api_cert)
            value = config[:node_verify_api_cert].nil? ? config[:verify_api_cert] : config[:node_verify_api_cert]
            client_rb << %Q{verify_api_cert #{value}\n}
          end

          # We configure :ssl_verify_mode only when it's overridden on the CLI
          # or when specified in the knife config.
          if config[:node_ssl_verify_mode] || config.key?(:ssl_verify_mode)
            value = case config[:node_ssl_verify_mode]
                    when "peer"
                      :verify_peer
                    when "none"
                      :verify_none
                    when nil
                      config[:ssl_verify_mode]
                    else
                      nil
                    end

            if value
              client_rb << %Q{ssl_verify_mode :#{value}\n}
            end
          end

          if config[:ssl_verify_mode]
            client_rb << %Q{ssl_verify_mode :#{config[:ssl_verify_mode]}\n}
          end

          if config[:bootstrap_proxy]
            client_rb << "\n"
            client_rb << %Q{http_proxy        "#{config[:bootstrap_proxy]}"\n}
            client_rb << %Q{https_proxy       "#{config[:bootstrap_proxy]}"\n}
            client_rb << %Q{no_proxy          "#{config[:bootstrap_no_proxy]}"\n} if config[:bootstrap_no_proxy]
          end

          if config[:bootstrap_no_proxy]
            client_rb << %Q{no_proxy       "#{config[:bootstrap_no_proxy]}"\n}
          end

          if secret
            client_rb << %Q{encrypted_data_bag_secret "#{ChefConfig::PathHelper.escapepath(ChefConfig::Config.etc_chef_dir(windows: true))}\\\\encrypted_data_bag_secret"\n}
          end

          unless trusted_certs_script.empty?
            client_rb << %Q{trusted_certs_dir "#{ChefConfig::PathHelper.escapepath(ChefConfig::Config.etc_chef_dir(windows: true))}\\\\trusted_certs"\n}
          end

          if chef_config[:fips]
            client_rb << "fips true\n"
          end

          escape_and_echo(client_rb)
        end

        def get_log_location
          if chef_config[:config_log_location].equal?(:win_evt)
            %Q{:#{chef_config[:config_log_location]}\n}
          elsif chef_config[:config_log_location].equal?(:syslog)
            raise "syslog is not supported for log_location on Windows OS\n"
          elsif chef_config[:config_log_location].equal?(STDOUT)
            "STDOUT\n"
          elsif chef_config[:config_log_location].equal?(STDERR)
            "STDERR\n"
          elsif chef_config[:config_log_location].nil? || chef_config[:config_log_location].empty?
            "STDOUT\n"
          elsif chef_config[:config_log_location]
            %Q{"#{chef_config[:config_log_location]}"\n}
          else
            "STDOUT\n"
          end
        end

        def start_chef
          c_opscode_dir = ChefConfig::PathHelper.cleanpath(ChefConfig::Config.c_opscode_dir, windows: true)
          client_rb = clean_etc_chef_file("client.rb")
          first_boot = clean_etc_chef_file("first-boot.json")

          bootstrap_environment_option = bootstrap_environment.nil? ? "" : " -E #{bootstrap_environment}"

          start_chef = "SET \"PATH=%SYSTEM32%;%SystemRoot%;%SYSTEM32%\\Wbem;%SYSTEM32%\\WindowsPowerShell\\v1.0\\;C:\\ruby\\bin;#{c_opscode_dir}\\bin;#{c_opscode_dir}\\embedded\\bin\;%PATH%\"\n"
          start_chef << "#{ChefUtils::Dist::Infra::CLIENT} -c #{client_rb} -j #{first_boot}#{bootstrap_environment_option}\n"
        end

        def win_wget
          # I tried my best to figure out how to properly url decode and switch / to \
          # but this is VBScript - so I don't really care that badly.
          win_wget = <<~WGET
            url = WScript.Arguments.Named("url")
            path = WScript.Arguments.Named("path")
            proxy = null
            '* Vaguely attempt to handle file:// scheme urls by url unescaping and switching all
            '* / into \.  Also assume that file:/// is a local absolute path and that file://<foo>
            '* is possibly a network file path.
            If InStr(url, "file://") = 1 Then
            url = Unescape(url)
            If InStr(url, "file:///") = 1 Then
            sourcePath = Mid(url, Len("file:///") + 1)
            Else
            sourcePath = Mid(url, Len("file:") + 1)
            End If
            sourcePath = Replace(sourcePath, "/", "\\")

            Set objFSO = CreateObject("Scripting.FileSystemObject")
            If objFSO.Fileexists(path) Then objFSO.DeleteFile path
            objFSO.CopyFile sourcePath, path, true
            Set objFSO = Nothing

            Else
            Set objXMLHTTP = CreateObject("MSXML2.ServerXMLHTTP")
            Set wshShell = CreateObject( "WScript.Shell" )
            Set objUserVariables = wshShell.Environment("USER")

            rem http proxy is optional
            rem attempt to read from HTTP_PROXY env var first
            On Error Resume Next

            If NOT (objUserVariables("HTTP_PROXY") = "") Then
            proxy = objUserVariables("HTTP_PROXY")

            rem fall back to named arg
            ElseIf NOT (WScript.Arguments.Named("proxy") = "") Then
            proxy = WScript.Arguments.Named("proxy")
            End If

            If NOT isNull(proxy) Then
            rem setProxy method is only available on ServerXMLHTTP 6.0+
            Set objXMLHTTP = CreateObject("MSXML2.ServerXMLHTTP.6.0")
            objXMLHTTP.setProxy 2, proxy
            End If

            On Error Goto 0

            objXMLHTTP.open "GET", url, false
            objXMLHTTP.send()
            If objXMLHTTP.Status = 200 Then
            Set objADOStream = CreateObject("ADODB.Stream")
            objADOStream.Open
            objADOStream.Type = 1
            objADOStream.Write objXMLHTTP.ResponseBody
            objADOStream.Position = 0
            Set objFSO = Createobject("Scripting.FileSystemObject")
            If objFSO.Fileexists(path) Then objFSO.DeleteFile path
            Set objFSO = Nothing
            objADOStream.SaveToFile path
            objADOStream.Close
            Set objADOStream = Nothing
            End If
            Set objXMLHTTP = Nothing
            End If
          WGET
          escape_and_echo(win_wget)
        end

        def win_wget_ps
          win_wget_ps = <<~WGET_PS
            param(
               [String] $remoteUrl,
               [String] $localPath
            )

            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

            $ProxyUrl = $env:http_proxy;
            $webClient = new-object System.Net.WebClient;

            if ($ProxyUrl -ne '') {
              $WebProxy = New-Object System.Net.WebProxy($ProxyUrl,$true)
              $WebClient.Proxy = $WebProxy
            }

            $webClient.DownloadFile($remoteUrl, $localPath);
          WGET_PS

          escape_and_echo(win_wget_ps)
        end

        def install_chef
          # The normal install command uses regular double quotes in
          # the install command, so request such a string from install_command
          install_command('"') + "\n" + fallback_install_task_command
        end

        def clean_etc_chef_file(path)
          ChefConfig::PathHelper.cleanpath(etc_chef_file(path), windows: true)
        end

        def etc_chef_file(path)
          "#{bootstrap_directory}/#{path}"
        end

        def bootstrap_directory
          ChefConfig::Config.etc_chef_dir(windows: true)
        end

        def local_download_path
          "%TEMP%\\#{ChefUtils::Dist::Infra::CLIENT}-latest.msi"
        end

        # Build a URL that will redirect to the correct Chef Infra msi download.
        def msi_url(machine_os = nil, machine_arch = nil, download_context = nil)
          if config[:msi_url].nil? || config[:msi_url].empty?
            url = "https://omnitruck.chef.io/chef/download?p=windows"
            url += "&pv=#{machine_os}" unless machine_os.nil?
            url += "&m=#{machine_arch}" unless machine_arch.nil?
            url += "&DownloadContext=#{download_context}" unless download_context.nil?
            url += "&channel=#{config[:channel]}"
            url += "&v=#{version_to_install}"
          else
            config[:msi_url]
          end
        end

        def first_boot
          escape_and_echo(super.to_json)
        end

        # escape WIN BATCH special chars
        # and prefixes each line with an
        # echo
        def escape_and_echo(file_contents)
          file_contents.gsub(/^(.*)$/, 'echo.\1').gsub(/([(<|>)^])/, '^\1')
        end

        private

        def install_command(executor_quote)
          "msiexec /qn /log #{executor_quote}%CHEF_CLIENT_MSI_LOG_PATH%#{executor_quote} /i #{executor_quote}%LOCAL_DESTINATION_MSI_PATH%#{executor_quote}"
        end

        # Returns a string for copying the trusted certificates on the workstation to the system being bootstrapped
        # This string should contain both the commands necessary to both create the files, as well as their content
        def trusted_certs_content
          content = ""
          if chef_config[:trusted_certs_dir]
            Dir.glob(File.join(ChefConfig::PathHelper.escape_glob_dir(chef_config[:trusted_certs_dir]), "*.{crt,pem}")).each do |cert|
              content << "> #{bootstrap_directory}/trusted_certs/#{File.basename(cert)} (\n" +
                escape_and_echo(IO.read(File.expand_path(cert))) + "\n)\n"
            end
          end
          content
        end

        def client_d_content
          content = ""
          if chef_config[:client_d_dir] && File.exist?(chef_config[:client_d_dir])
            root = Pathname(chef_config[:client_d_dir])
            root.find do |f|
              relative = f.relative_path_from(root)
              if f != root
                file_on_node = "#{bootstrap_directory}/client.d/#{relative}".tr("/", "\\")
                if f.directory?
                  content << "mkdir #{file_on_node}\n"
                else
                  content << "> #{file_on_node} (\n" +
                    escape_and_echo(IO.read(File.expand_path(f))) + "\n)\n"
                end
              end
            end
          end
          content
        end

        def fallback_install_task_command
          # This command will be executed by schtasks.exe in the batch
          # code below. To handle tasks that contain arguments that
          # need to be double quoted, schtasks allows the use of single
          # quotes that will later be converted to double quotes
          command = install_command("'")
          <<~EOH
            @set MSIERRORCODE=!ERRORLEVEL!
            @if ERRORLEVEL 1 (
                @echo WARNING: Failed to install #{ChefUtils::Dist::Infra::PRODUCT} MSI package in remote context with status code !MSIERRORCODE!.
                @echo WARNING: This may be due to a defect in operating system update KB2918614: http://support.microsoft.com/kb/2918614
                @set OLDLOGLOCATION="%CHEF_CLIENT_MSI_LOG_PATH%-fail.log"
                @move "%CHEF_CLIENT_MSI_LOG_PATH%" "!OLDLOGLOCATION!" > NUL
                @echo WARNING: Saving installation log of failure at !OLDLOGLOCATION!
                @echo WARNING: Retrying installation with local context...
                @schtasks /create /f  /sc once /st 00:00:00 /tn chefclientbootstraptask /ru SYSTEM /rl HIGHEST /tr \"cmd /c #{command} & sleep 2 & waitfor /s %computername% /si chefclientinstalldone\"

                @if ERRORLEVEL 1 (
                    @echo ERROR: Failed to create #{ChefUtils::Dist::Infra::PRODUCT} installation scheduled task with status code !ERRORLEVEL! > "&2"
                ) else (
                    @echo Successfully created scheduled task to install #{ChefUtils::Dist::Infra::PRODUCT}.
                    @schtasks /run /tn chefclientbootstraptask
                    @if ERRORLEVEL 1 (
                        @echo ERROR: Failed to execute #{ChefUtils::Dist::Infra::PRODUCT} installation scheduled task with status code !ERRORLEVEL!. > "&2"
                    ) else (
                        @echo Successfully started #{ChefUtils::Dist::Infra::PRODUCT} installation scheduled task.
                        @echo Waiting for installation to complete -- this may take a few minutes...
                        waitfor chefclientinstalldone /t 600
                        if ERRORLEVEL 1 (
                            @echo ERROR: Timed out waiting for #{ChefUtils::Dist::Infra::PRODUCT} package to install
                        ) else (
                            @echo Finished waiting for #{ChefUtils::Dist::Infra::PRODUCT} package to install.
                        )
                        @schtasks /delete /f /tn chefclientbootstraptask > NUL
                    )
                )
            ) else (
                @echo Successfully installed #{ChefUtils::Dist::Infra::PRODUCT} package.
            )
          EOH
        end
      end
    end
  end
end
