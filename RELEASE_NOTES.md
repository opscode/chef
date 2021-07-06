This file holds "in progress" release notes for the current release under development and is intended for consumption by the Chef Documentation team. Please see <https://docs.chef.io/release_notes/> for the official Chef release notes.

## What's New in 17.3

### Compliance Phase Improvements

#### Chef InSpec 4.38

We've updated Chef InSpec from 4.37.23 to 4.38.3:

##### New Features

- Added a new mongodb_conf resource.

##### Bug Fixes

- Changed the Windows local pipe server connection to retry once on EPIPE.
- Exceptions are now handled correctly in the oracledb_session resource.
- Fixed the mysql_session resource to raise an exception if there is an error in a connection or query.
- Fixed the postgres_session resource to raise an exception if there is an error in a connection or query

### Override Run Lists with Policyfiles

You can now execute Chef Infra Client using override run lists on nodes that are managed with Policyfiles.

#### Safety With Overrides

Override run lists with Policyfiles gives you the safety of locked sets of cookbook dependencies while also giving you the flexibility of running different run lists on nodes for adhoc Chef Infra Client converges. Unlike traditional override run lists where an entire new set of dependencies is determined, override run lists with Policyfiles continues to run within the predefined set of cookbook dependencies in your Policyfile. This allows you to override run lists without bringing new, and potentially untested, cookbook dependencies.

#### How This Differs From Named Run Lists

Override run lists offer additional flexibility over named run lists and are better suited for adhoc Chef Infra Client execution. Named run lists within Policyfiles need to be defined when the Policyfile is uploaded, requiring you to predefine each potential run list you may want to run at a future data. Additionally running Chef Infra Client with a named run list saves that new run list to the Chef Infra Server, while override run lists are temporary and not saved to the server. This helps avoid potential failures from cookbooks that may search for nodes based on run lists.

### New Resources

#### windows_defender

Use the **windows_defender** resource to enable or disable the Microsoft Windows Defender service.

```ruby
windows_defender 'Configure Defender' do
  realtime_protection true
  intrusion_protection_system true
  lock_ui true
  scan_archives true
  scan_scripts true
  scan_email true
  scan_removable_drives true
  scan_network_files false
  scan_mapped_drives false
  action :enable
end
```

#### windows_defender_exclusion

Use the **windows_defender_exclusion** resource to exclude paths, processes, or file types from Windows Defender realtime protection scanning.

```ruby
windows_defender_exclusion 'Add to things to be excluded from scanning' do
  paths 'c:\\foo\\bar, d:\\bar\\baz'
  extensions 'png, foo, ppt, doc'
  process_paths 'c:\\windows\\system32'
  action :add
end
```

#### habitat_package

#### habitat_sup

#### habitat_config

#### habitat_install

#### habitat_service

#### habitat_user_toml

### Updated Resources

#### powershell_package

The `powershell_package` resource has been updated to allow passing an array of install options via the `options` property. Thanks for reporting this issue [@kimbernator](https://github.com/kimbernator)

#### windows_printer

The `windows_printer` resource has been updated to better load the current state of the printer and to allow controlling the creation of the printer port. The resource now includes a `create_port` property that allows skipping the creation of the printer port and a `port_name` property that allows specifying the name of the port to use. With these new properties, users can create advanced printer ports using the `windows_printer_port` resource and then attach a new printer to those ports using the `windows_printer` resource.

```ruby
windows_printer_port '10.4.64.39' do
  port_name 'My awesome printer port'
  snmp_enabled true
  port_protocol 2
end

windows_printer 'HP LaserJet 5th Floor' do
  driver_name 'HP LaserJet 4100 Series PCL6'
  port_name 'My awesome printer port'
  ipv4_address '10.4.64.38'
  create_port false
end
```

#### chef_client_config

The `chef_client_config` resource has been updated to...

### Chef Language Improvements

We've added several new helpers to the Chef Infra Language to make writing out various data formats easier.

#### render_json

#### render_toml

#### render_yaml

### Experimental Secrets Management

With Chef Infra Client 17.3 we're introducing experimental secrets management integration. This functionality should be considered a beta and not be used in production. We'd love to get feedback on how how this works for you and additional features you'd like or need in order to utilize secrets from secret managers within your cookbooks. E-mail us at secrets_management_beta@progress.com.

This beta adds a new `secrets` helper to the Chef Infra Language with a plugable model for different secrets management systems. In this release of Chef Infra Client we've added initial support for AWS Secrets Manager and Azure Key Vault. In future releases we hope to add support for additional secrets management systems such as HashiCorp Vault and Akeyless Vault.

### System Detection Improvements

#### virtuozzo Support

The `virtuozzo` platform is now detected as a member of the RHEL platform_family. Thanks for this addition [@robertmasztalerz](https://github.com/robertmasztalerz)!

#### Linux Livepatch Detection

A new Ohai optional plugin `:Livepatch` has been added to detect Linux kernel Livepatch modules that have been loaded on a system. This plugin can be enabled on systems using the `ohai_optional_plugins` property in the [chef_client_config resource](https://docs.chef.io/resources/chef_client_config). Thanks for this new plugin [@liu-song-6](https://github.com/liu-song-6)!


### Package Improvements

#### M1 macOS Monterey Packages

Chef Infra Client packages are now produced for Apple's macOS Monterey preview release. Packages for Intel-based Macs will ship at a later date.

#### Solaris 11.3 EOL / Solaris 11.4 Packages

Oracle Solaris 11.3 became end-of-life (EOL) in January 2021. Chef Infra Client packages are no longer produced for Solaris 11.3 and new Solaris 11.4 packages are available in their place.

#### FIPS on PPC RHEL

Failures initializing Chef Infra Client on FIPS enabled PowerPC RHEL systems have been resolved.

### Security

#### Ruby 3.0.2

Ruby has been updated to 3.0.2 to resolve a large number of bugs as well as the following CVEs:

- [CVE-2021-31810](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31810)
- [CVE-2021-32066](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-32066)
- [CVE-2021-31799](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31799)

## What's New in 17.2

### Compliance Phase Improvements

#### Chef InSpec 4.37

We've updated Chef InSpec from 4.36.4 to 4.37.8:

##### New Features

- The new `inspec automate` command replaces the `inspec compliance` command, which is now deprecated.
- Added support for `zfs_pool` and `zfs_dataset` resources on Linux.
- Improved `port` resource performance: adding more specific search while using `ss` command.
- Updated the `inspec init plugin` command with the following changes:
  - The values of flags passed to the `inspec init plugin` command are now wrapped in double quotes instead of single quotes.
  - Template files are now ERB files.
  - The `activator` flag replaces the `hook` flag, which is now an alias.

##### Bug Fixes

- Fixed an error when using profile dependencies and require_controls.
- Fixed the `windows_firewall_rule` resource when it failed to validate more than one rule.
- The `http` resource response body is now coerced into UTF-8.
- Modified the `windows_feature` resource to indicate if a feature is enabled rather than just available.
- `file` resource `more_permissive_than` matcher returns nil instead of throwing an exception when the file does not exist.
- `inspec detect --no-color` now returns color-free output.

### Slow Resource Report

Chef Infra Client now includes a `--slow-report` flag that shows the 10 slowest running resources in a Chef Infra Client run to help you troubleshoot and optimize your cookbooks. This new flag also takes an argument for the number of resources to list if you'd like to see additional resources included in the output. Our next release of Chef Workstation will include the ability to set this flag in Test Kitchen to allow testing for slow resources in the development process.

#### Example Output

```text
Starting Chef Infra Client, version 17.2.12
Patents: https://www.chef.io/patents
resolving cookbooks for run list: ["test"]
Synchronizing Cookbooks:
  - test (0.0.1)
Installing Cookbook Gems:
Compiling Cookbooks...
Converging 1 resources
Recipe: test::default
  * file[/tmp/foo.xzy] action create (up to date)

Running handlers:

Top 1 slowest resource:

resource           elapsed_time cookbook recipe  source
------------------ ------------ -------- ------- ----------------------------------------
file[/tmp/foo.xzy] 0.015114     test     default test/recipes/default.rb:2:in `from_file'

  - Chef::Handler::SlowReport
Running handlers complete
Chef Infra Client finished, 0/1 resources updated in 03 seconds
```

### Improved YAML Recipe Support

Chef Infra Client now supports both `.yaml` and `.yml` file extensions for recipes. If a `.yml` and `.yaml` recipe of the same name is present, Chef Infra Client will now fail as there is no way to determine which recipe should be loaded in this case.

### Improved Reporting to Automate

Chef Infra Client run reporting to Automate now respects attribute `allowlist` and `denylist` configurations set in the `client.rb`. This change allows users to limit the data sent to their Automate servers to prevent indexing sensitive data or to reduce the necessary storage space on the Automate server.

### Updated Resources

#### homebrew_path

The `homebrew_path` now passes the `homebrew_path` when creating or deleting taps. This change prevents failures when running homebrew in a non-standard location or on a M1 system. Thanks [@mattlqx](https://github.com/mattlqx)!

#### hostname

The `hostname` resource now sets the hostname on Windows systems using native PowerShell calls for increased reliability and allows changing the hostname on domain-attached systems. To change the hostname on a domain-attached system, pass a domain administrator account using the new `domain_user` and `domain_password` properties.

#### openssl_x509_certificate

The `openssl_x509_certificate` no longer marks the creation of the X509 certificate file as sensitive since this makes troubleshooting difficult and this content is not sensitive. Thanks [@jasonwbarnett](https://github.com/jasonwbarnett)!

#### windows_firewall_rule

The `windows_firewall_rule` resource now allows specifying multiple IP addresses in the `remote_address` property.

#### windows_pagefile

The `windows_pagefile` resource features improved performance and support for the latest releases of Windows 10. These improvements also make managing pagefiles more predictable:

- The `path` property now accepts a drive letter in addition to the full path of the pagefile on disk. For example, `C`, `C:`, or `C:\` can now be used to specify a pagefile stored at `C:\pagefile.sys`.
- Creating a new pagefile no longer disables the system-managed pagefile by default. If you wish to create a pagefile while also disabling the system-managed pagefile, set `system_managed false`.

#### windows_printer

The `windows_printer` resource includes improved logging when adding or removing printers.

#### windows_printer_port

The `windows_printer_port` resource has been refactored with several improvements:

- Better performance when adding and removing ports.
- Supports updating existing ports with new values.
- Clearer logging of changes made to ports.
- Deprecated the `description` property, which does not set a description on the ports.

#### windows_security_policy

The `windows_security_policy` resource now limits the value of `ResetLockoutCount` to any value less than `LockoutDuration` rather than limiting it to 30 minutes.

#### zypper_repository

The `zypper_repository` resource now accepts an array of GPG key locations in the `gpgkey` property. Thanks for reporting this [@bkabrda](https://github.com/bkabrda).

## What's New in 17.1

### Compliance Phase Improvements

#### cli reporter by default

The compliance phase will now default to using both the `json-file` and the new `cli` reporter by default. This gives you a visual indication of the success of the Compliance Phase and is perfect for running both on the CLI and in Test Kitchen.

#### inspec_waiver_file_entry resource

Chef Infra Client now ships with a `inspec_waiver_file_entry` resource for managing Chef InSpec waivers. With this resource you can add and remove waiver entries to a single waiver file located at `c:\chef\inspec_waiver_file.yml` on Windows or `/etc/chef/inspec_waivers.yml` on all other systems.

See the [inspec_waiver_file_entry documentation](https://docs.chef.io/resources/inspec_waiver_file_entry) for more information and usage examples.

#### Chef InSpec 4.36

We've updated Chef InSpec from 4.33.1 to 4.36.4:

- Added the selinux resource which includes support for modules and booleans.
- Added the pattern input option for DSL and metadata inputs.
- Added the `members_array` property for group & groups resources.
- Train now reads the username and port from the `.ssh/config` file and will use these values if present.
- Switch to GNU timeout-based implementation of SSH timeouts.
- Fixed the group resource when a member does not exist.

### Unified Mode Improvements

We've extended support for Unified Mode to the `edit_resource` helper and also improved the Unified Mode related deprecation warnings to provide more useful information and not warn when resources are deprecated or set to only run on older Chef Infra Client releases.

### Resource Improvements

#### service on systemd Hosts

The `service` resource on systemd hosts will now properly load the state of the service. Thanks for this fix [@ramereth](https://github.com/ramereth)!

#### systemd_unit

We updated the `systemd_unit` resource to resolve a regression in Chef Infra Client 17.0 that would re-enable and restart unit files on each Chef Infra Client run. Thanks for this fix [@gene1wood](https://github.com/gene1wood)!

#### template

We updated the `template` resource to allow passing the `cookbook_name` variable to template files.

#### Windows Resource

We fixed a failure that could occur in multiple Windows resources due to larger 64-bit values that logged the error: `RangeError: bignum too big to convert into 'long'`.

#### windows_security_policy

The `windows_security_policy` resource now supports setting `AuditPolicyChange` and `LockoutDuration`.

#### yum_package / dnf_package

We've made multiple improvements to how we interact with the systems RPM database in the `yum_package` and `dnf_package` resources. These changes improve reliability interacting with the RPM database and includes significant performance improvements, especially when no installation or upgrade action is taken by Chef Infra Client.

### Platform Detection

[Rocky Linux](https://rockylinux.org/), a RHEL clone, is now detected as a member of the `rhel` platform family.

### Packaging

#### Improved Dependencies

Chef Infra Client 17.1 is once again smaller than previous releases thanks to reduced dependencies in the packages.

#### RHEL 8 Packages

We improved our RHEL 8 packages with additional RHEL 8 optimizations and EL8 in the filename.

## What's New in 17.0

Chef Infra Client 17.0 is our yearly release for 2021. These yearly releases include new functionality, an update to the underlying Ruby release, as well as potentially breaking changes. These notes outline what's new and what you should be aware of as part of your upgrade process.

### Compliance Phase

Chef Infra Client's new Compliance Phase allows users to automatically execute compliance audits and view the results in Chef Automate as part of any Chef Infra Client Run. This new phase of the Chef Infra Client run replaces the legacy [audit cookbook](https://supermarket.chef.io/cookbooks/audit) and works using the existing audit cookbook attributes. With this new phase, you'll always have the latest compliance capabilities out of the box without the need to manage cookbook dependencies or juggle versions during Chef Infra Client updates.

The Compliance Phase also features a new compliance reporter: `cli`. This reporter mimics the InSpec command line output giving you a visual indication of your system's compliance status. Thanks for this new reporter [@aknarts](https://github.com/aknarts/).

Existing audit cookbook users can migrate to the new Compliance Phase by removing the audit cookbook from their run_list and setting the `node['audit']['compliance_phase']` attribute to `true`.

For more information see our on-demand webinar [Configure Chef Infra & Compliance Using Built-In Functionality](https://pages.chef.io/202102-Webinar-ConfigureChefInfraComplianceUsingBuilt-InFunctionality_01Register.html)

### Ruby 3

Chef Infra Client 17 packages now ship with embedded Ruby 3.0. This new release of Ruby improves performance and offers many new language improvements for those writing advanced custom resources. See the [ruby-lang.org Ruby 3.0 Announcement](https://www.ruby-lang.org/en/news/2020/12/25/ruby-3-0-0-released/) for additional details on what's new and improved in Ruby 3.0.

### Knife Moved to Workstation

For historical packaging reasons the Chef Infra Client packages have always shipped with the `knife` command for managing your Chef Infra nodes. With Chef Workstation there's no benefit to shipping knife in the Chef Infra Client package and there are several downsides. Shipping management tooling within the client is seen as a security risk to many and increases the side of the Chef Infra Client codebase by adding a large number of management dependencies. With Chef Infra Client 17 we've split knife into its own Ruby Gem, which will continue to ship in Chef Workstation, but will no longer come bundled with Chef Infra Client. We hope you'll enjoy the new faster and smaller Chef Infra Client while continuing to use knife in Chef Workstation uninterrupted.

### Breaking Changes

#### AIX Virtualization Improvements

The Ohai :Virtualization plugin on AIX systems will now properly return the `lpar_no` and `wpar_no` values as Integers instead of Strings. This makes the data much easier to work within cookbooks, but may be a breaking change depending on how AIX users consumed these values.

#### 32bit RHEL/CentOS 6 Support

We will not produce Chef Infra Client 17 packages for 32bit RHEL/CentOS 6 systems. RHEL/CentOS 6 reached EOL in November 2020. We are extending support for 64-bit RHEL/CentOS 6 until Chef Infra Client 18 (April 2022) or when an upstream platform or library changes prevent us from building on these systems that are at the end of their lifecycle.

#### Chef Client As A Service on Windows

Based on customer feedback and observations in the field we've removed the ability to run the Chef Infra Client as a service on Windows nodes. We've seen the service manager for the Chef Infra Client consume excessive memory, hang preventing runs, or prevent nodes from updating to new client releases properly. We've always seen significantly better reliability by running Chef Infra Client as a scheduled task on Windows and in July of 2006 we introduced warnings to the [chef-client cookbook](https://supermarket.chef.io/cookbooks/chef-client) when running as a service. The ability to set up the client as a service was later removed from the cookbook entirely in October of 2017.

For customers currently running Chef Infra Client as a service, we advise migrating to scheduled task-based execution. This allows for complex scheduling scenarios not possible with simple services, such as skipping Chef Infra Client execution on systems running on battery power or running the Chef Infra Client immediately after a system boot to ensure configuration.

Chef Infra Client can be configured to run as a scheduled task using the [chef-client cookbook](https://supermarket.chef.io/cookbooks/chef-client) or ideally using the [chef_client_scheduled_task resource](https://docs.chef.io/resources/chef_client_scheduled_task/) built into Chef Infra Client 16 or later. For users already running as a service setting up the scheduled task and then stopping the existing service can be performed within a Chef Infra Client run to migrate systems.

#### Gem Resource Ruby 1.9+

The `gem` resource used to install Ruby Gems into the system's Ruby installation will now assume Ruby 1.9 or later. As Ruby 1.8 and below reached end of life almost 7 years ago, we believe there is little to no impact in this change.

#### Legacy node['filesystem2'] removed on AIX/Solaris/FreeBSD

The legacy `node['filesystem2']` attributes leftover from our multi-year migration of filesystem data on AIX, Solaris, and FreeBSD systems has been removed. This same data is now available at `node['filesystem']`

#### node['filesystem'] Uses Updated Format on Windows

In Chef Infra Client 16 we introduced `node['filesystem2']` on Windows to complete our migration to a unified structure for filesystem data regardless of platform. In Chef Infra Client 17 we are updating `node['filesystem']` on Windows with this same unified format. Both node attributes now have the same data allowing users to more easily migrate `filesystem2` to `filesystem` in their cookbooks. In Chef Infra Client 18, we will remove `node['filesystem2']` completely finishing our multi-year migration of Ohai filesystem data format.

#### Removed Antergos and Pidora Detection

Ohai detection of the end-of-life Antergos and Pidora distributions has been removed. Antergos ended releases and downloads of the distribution in May 2019 and Pidora stopped receiving updates in 2014.

### Infra Language Improvements

#### Lazy Attribute Loading

A common problem when using the "wrapper cookbook" pattern is when the wrapped cookbook declares what are called "derived attributes", which are attributes that refer to other attributes. Because of the order that attribute files are parsed in, this does not work as intended when the base attribute is changed in a wrapper cookbook. By extending the use of the `lazy {}` helper to the declaration of node attributes, it makes it possible for the wrapped cookbook to cleanly allow wrapper cookbooks to override base attributes as intended.

Use the lazy helper:

```ruby
default['myapp']['dir'] = '/opt/myapp'
default['myapp']['bindir'] = lazy { "#{node['myapp']['dir']}/bin" }
```

Instead of:

```ruby
default['myapp']['dir'] = '/opt/myapp'
default['myapp']['bindir'] = "#{node['myapp']['dir']}/bin"
```

With the lazy helper the wrapper cookbook can then override the base attribute and the derived attribute will change:

```ruby
default['myapp']['dir'] = "/opt/my_better_app" # this also changes the bindir attribute correctly
```

The use of this helper is not limited to declarations in attribute files and can be used whenever attributes are being assigned. For a complete description of the capabilities of lazy attribute evaluation see https://github.com/chef/chef/pull/10861

#### Custom Resource Property Defaults

Chef Infra Client's handling of default property values in Custom Resources has been improved to avoid potential Ruby errors. These values are now duplicated internally allowing them to be modified by the user in their recipes without potentially receiving fatal frozen value modification errors.

#### effortless? helper

A new `effortless?` helper identifies if a system is running Chef Infra Client using the Effortless Pattern.

#### reboot_pending? Improvements

The `reboot_pending?` helper now works on all Debian based platforms instead of just Ubuntu.

### Resource Improvements

#### Logging Improvements

A large number of resources have seen improvements to the logging available in the `debug` log level providing better information for troubleshooting Chef Infra Client execution. Thanks for this improvement [@jaymzh](https://github.com/jaymzh)!

#### apt_package

The `apt_package` resource now properly handles downgrading package versions. Please note that full versions must be provided in the `version` property and invalid version strings will now raise an error. Thanks for this improvement [@jaymzh](https://github.com/jaymzh)!

#### chef_client_launchd / macosx_service

The `chef_client_launchd` and `macosx_service` resources have been updated to use the full path to the `launchctl` command. This avoids failures running these resources with incorrect PATH environment variables. Thanks for this improvement [@krackajak](https://github.com/krackajak)!

#### execute

The `execute` resource includes a new `login` property allowing you to run commands with a login shell. This helps ensure you have all potential environment variables defined in the user's shell.

#### hostname

The `hostname` resource now includes a new `fqdn` property to allow you to set a custom fqdn in the hostname file in addition to the system's hostname. Thanks for suggesting this improvement [@evandam](https://github.com/evandam)!

#### systemd_unit

The `systemd_unit` resource has been improved to only shell out once to determine the state of the systemd unit. This optimization should result in significant performance improvements when using large numbers of `systemd_unit` resources. Thanks [@joshuamiller01](https://github.com/joshuamiller01)!

#### windows_certificate

The `windows_certificate` resource has undergone a large overhaul, with improved support for importing and exporting certificate objects, the ability to create certificate objects from a URL, and a new `output_path` property for use with exporting.

#### windows_task

The `windows_task` resource now has a new `backup` property that allows you to control the number of XML backups that will be kept of your Windows Scheduled Task definition. This default for this setting is `5` and can be disabled by setting the property to `false`. Thanks [@ kimbernator](https://github.com/kimbernator)!

### Ohai

#### Podman Detection

Ohai now includes detection for hosts running the Podman containerization engine or Chef Infra Client running in containers under Podman.

For hosts the following attributes will be set:

```json
{
  "systems": {
    "podman": "host",
  },
  "system": "podman",
  "role": "host"
}
```

For Chef Infra Client within containers the following attributes will be set:

```json
{
  "systems": {
    "podman": "guest",
  },
  "system": "podman",
  "role": "guest"
}
```

Thanks for this addition [@ramereth](https://github.com/ramereth)!

#### Habitat Support

Ohai includes a new `:Habitat` plugin that gathers information about the Habitat installation, including installed Habitat version, installed packages, and running services.

Sample Habitat attribute output:

```json
{
  "version": "1.6.288/20210402191717",
  "packages": ["core/busybox-static/1.31.0/20200306011713",
    "core/bzip2/1.0.8/20200305225842",
    "core/cacerts/2020.01.01/20200306005234",
    "core/gcc-libs/9.1.0/20200305225533",
    "core/glibc/2.29/20200305172459",
    "core/hab-launcher/15358/20210402194815",
    "core/hab-sup/1.6.288/20210402194826",
    "core/libedit/3.1.20150325/20200319193649",
    "core/libsodium/1.0.18/20200319192446",
    "core/linux-headers/4.19.62/20200305172241",
    "core/ncurses/6.1/20200305230210",
    "core/nginx/1.18.0/20200506101012",
    "core/openssl-fips/2.0.16/20200306005307",
    "core/openssl/1.0.2t/20200306005450",
    "core/pcre/8.42/20200305232429",
    "core/zeromq/4.3.1/20200319192759",
    "core/zlib/1.2.11/20200305174519"
  ],
  "services": [{
    "identity": "core/nginx/1.18.0/20200506101012",
    "topology": "standalone",
    "state_desired": "up",
    "state_actual": "up"
  }]
}
 ```

#### Alibaba Detection

Ohai now includes detection of nodes running on the Alibaba cloud and supports gathering Alibaba instance metadata.

Sample `node['alibaba']` values:

```json
{
  "meta_data": {
    "dns_conf_": "nameservers",
    "eipv4": "47.89.242.123",
    "hibernation_": "configured",
    "hostname": "1234",
    "image_id": "aliyun_2_1903_x64_20G_alibase_20210120.vhd",
    "instance_id": "i-12345",
    "instance_": {
      "instance_type": "ecs.t6-c2m1.large",
      "last_host_landing_time": "2021-02-07 19:10:04",
      "max_netbw_egress": 81920,
      "max_netbw_ingress": 81920,
      "virtualization_solution": "ECS Virt",
      "virtualization_solution_version": 2.0
    },
    "mac": "00:16:3e:00:d9:01",
    "network_type": "vpc",
    "network_": "interfaces/",
    "ntp_conf_": "ntp-servers",
    "owner_account_id": 1234,
    "private_ipv4": "172.25.58.242",
    "region_id": "us-west-1",
    "serial_number": "ac344378-4d5d-4b9e-851b-1234",
    "source_address": "http://us1.mirrors.cloud.aliyuncs.com",
    "sub_private_ipv4_list": "172.25.58.243",
    "vpc_cidr_block": "172.16.0.0/12",
    "vpc_id": "vpc-1234",
    "vswitch_cidr_block": "172.25.48.0/20",
    "vswitch_id": "vsw-rj9eiw6yqh6zll23h0tlt",
    "zone_id": "us-west-1b"
  },
  "user_data": null,
  "dynamic": "instance-identity",
  "global_config": null,
  "maintenance": "active-system-events"
}
```

Sample `node['cloud'] values:

```json
{
  "public_ipv4_addrs": [
    "47.89.242.123"
  ],
  "local_ipv4_addrs": [
    "172.25.58.242"
  ],
  "provider": "alibaba",
  "local_hostname": "123",
  "public_ipv4": "47.89.242.123",
  "local_ipv4": "172.25.58.242"
}
```

The Chef Infra Language now includes an `alibaba?` helper method to check for instances running on Alibaba as well.

### Improved Linux CPU Data

Data collection in the `:Cpu` plugin on Linux has been greatly expanded to give enhanced information on architecture, cache, virtualization status, and overall model and configuration data. Thanks for this addition [@ramereth](https://github.com/ramereth)!

### Packaging Improvements

### PowerPC RHEL FIPS Support

We now produce FIPS capable packages for RHEL on PowerPC

### Sample client.rb on *nix Platforms

On AIX, Solaris, macOS, and Linux platforms the Chef Infra Client packages will now create the various configuration directories under `/etc/chef` as well as a sample `/etc/chef/client.rb` file to make it easier to get started running the client.

### New Deprecations

### Unified Mode in Custom Resources

In Chef Infra Client 16 we introduced Unified Mode allowing you to collapse the sometimes confusing compile and converge phases into a single unified phase. Unified mode makes it easier to write and troubleshoot failures in custom resources and for Chef Infra Client 18 we plan to make this the default execution phase for custom resources. We've backported the unified mode feature to the Chef Infra Client 14 and 15 systems and for Chef Infra Client 17 we will now begin warning if resources don't explicitly set this new mode. Enabling unified mode now lets you validate that resources will continue to function as expected in Chef Infra Client 18. To enable unified  mode in your resource add `unified_mode true` to the file.

## What's New in 16.13

### Chef InSpec 4.31

Chef InSpec has been updated from 4.29.3 to 4.31.1.

#### New Features

- Commands can now be set to timeout using the [command resource](https://docs.chef.io/inspec/resources/command/) or the [`--command-timeout`](https://docs.chef.io/inspec/cli/) option in the CLI. Commands timeout by default after one hour.
- Added the [`--docker-url`](https://docs.chef.io/inspec/cli/) CLI option, which can be used to specify the URI to connect to the Docker Engine.
- Added support for targeting Linux and Windows containers running on Docker for Windows.

#### Bug Fixes

- Hash inputs will now be loaded consistently and accessed as strings or symbols. ([#5446](https://github.com/inspec/inspec/pull/5446))

### Ubuntu FIPS Support

Our Ubuntu packages are now FIPS compliant for all your FedRAMP needs.

### Chef Language Additions

We now include a `centos_stream_platform?` helper to determine if your CentOS release is a standard [CentOS](https://www.centos.org/centos-linux/) release or a [CentOS Stream](https://www.centos.org/centos-stream/) release. This helper can be used in attributes files, recipes, and custom resources. Thanks for this new helper [@ramereth](https://github.com/ramereth)!

### Resource Improvements

#### dsc_script and dsc_resource

Our PowerShell integration has been improved to better handle failures that were silently occurring when running some DSC code in Chef Infra Client 16.8 and later. Thanks for reporting this problem [@jeremyciak](https://github.com/jeremyciak)!

### Platform Support Updates

#### Ubuntu 16.04 EOL

Packages will no longer be built for Ubuntu 16.04 as Canonical ended maintenance updates on April 30, 2021. See Chef's [Platform End-of-Life Policy](https://docs.chef.io/platforms/#platform-end-of-life-policy) for more information on when Chef ends support for an OS release.

### Improved System Detection

Ohai now includes a new `:OsRelease` plugin for Linux hosts that includes the content of `/etc/os_release`. This data can be very useful for accurately identifying the Linux distribution that Chef Infra Client is running on. Thanks for this new plugin [@ramereth](https://github.com/ramereth)!

#### Sample `:OsRelease` Output

```json
{
  "name": "Ubuntu",
  "version": "18.04.5 LTS (Bionic Beaver)",
  "id": "ubuntu",
  "id_like": [
    "debian"
  ],
  "pretty_name": "Ubuntu 18.04.5 LTS",
  "version_id": "18.04",
  "home_url": "https://www.ubuntu.com/",
  "support_url": "https://help.ubuntu.com/",
  "bug_report_url": "https://bugs.launchpad.net/ubuntu/",
  "privacy_policy_url": "https://www.ubuntu.com/legal/terms-and-policies/privacy-policy",
  "version_codename": "bionic",
  "ubuntu_codename": "bionic"
}
```

### Security

#### Ruby 2.7.3

Ruby has been updated to 2.7.3, which provides a large number of bug fixes and also resolves the following CVEs:

- [CVE-2021-28966](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28966)
- [CVE-2021-28966](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28966)

## What's New in 16.12

### Chef InSpec 4.29

Chef InSpec has been updated from 4.28 to 4.29.3.

#### New Features

- The JSON metadata pass through configuration has been moved from the Automate reporter to the JSON Reporter. ([#5430](https://github.com/inspec/inspec/pull/5430))

#### Bug Fixes

- The apt resource now correctly fetches all package repositories using the `-name` flag in an environment where ZSH is the user's default shell.  ([#5437](https://github.com/inspec/inspec/pull/5437))
- Updates how InSpec profiles are created with GCP or AWS providers so they use `inputs` instead of `attributes`. ([#5435](https://github.com/inspec/inspec/pull/5435))

### Resource Improvements

#### service and chef_client_launchd

The `service` and `chef_client_launchd` resources on macOS now use the full path to `launchctl` to avoid potential failures. Thanks [@krackajak](https://github.com/krackajak)!

#### file

Verifiers in the `file` resource are only run if the content actually changes. This can significantly speed execution of Chef Infra Client when no actual changes occur. Thanks [@joshuamiller01](https://github.com/joshuamiller01)!

#### mount

The mount resource now properly handles NFS mounts with a root of `/`. Thanks for reporting this [@eheydrick](https://github.com/eheydrick) and thanks for the fix [@ramereth](https://github.com/ramereth)!

### powershell_script and dsc_script

Our embedded PowerShell libraries have been updated for improved execution of PowerShell and DSC code on Windows systems.

### Improved System Detection

Ohai has been updated to better detect system configuration details:

- Ohai now detects Chef Infra Clients running in the Effortless pattern at `node['chef_packages']['chef']['chef_effortless']`.
- Windows packages installed for the current user are now detected in addition to system wide package installations. Thanks [@jaymzh](https://github.com/jaymzh)!
- `Sangoma Linux` is now detected as part of the `rhel` platform family. Thanks [@hron84](https://github.com/hron84)!
- Docker is now properly detected even if it's running on a virtualized system. Thanks [@jaymzh](https://github.com/jaymzh)!
- Alibaba Cloud Linux is now detected as platform `alibabalinux` and platform family `rhel`.

### Security

Upgraded OpenSSL on macOS hosts to 1.1.1k, which resolves the following CVEs:

- [CVE-2021-3450](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3450)
- [CVE-2021-3449](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3449)

## What's New in 16.11.7

### Native Apple M1 Architecture Packages

We now build and test native Apple M1 architecture builds of Chef Infra Client. These builds are available at [downloads.chef.io](https://downloads.chef.io), our `install.sh` scripts, and the [Omnitruck API](https://docs.chef.io/api_omnitruck/).

### Chef InSpec 4.28

Chef InSpec has been updated from 4.26.4 to 4.28.0.

#### New Features

- Added the option to filter out empty profiles from reports.
- Exposed the `conf_path`, `content`, and `params` properties to the `auditd_conf` resource.
- Added the ability to specify `--user` when connecting to docker containers.

#### Bug Fixes

- Fixed the `crontab` resource when passing a username to AIX.
- Stopped a backtrace from occurring when using `cmp` to compare `nil` with a non-existing file.
- Fixed `skip_control` to work on deeply nested profiles.
- The `ssh_config` and `sshd_config` resources now correctly use the first value when a setting is repeated.

### Fixes and Improvements

- Upgraded openSSL on macOS from 1.0.2 to 1.1.1 in order to support Apple M1 builds.
- Resolved an issue that caused the DNF and YUM package helpers to exit with error codes, which would show up in system logs.
- Added a new attribute to make the upcoming Compliance Phase an opt-in feature: `node['audit']['compliance_phase']`. This should prevent the Compliance Phase from incorrectly running when using named run_lists or override run_lists. If you're currently testing this new phase, make sure to set this attribute to `true`.
- `chef_client_cron`: the `append_log_file` property now sets up the cron job to use shell redirection (`>>`) instead of the `-L` flag

## What's New in 16.10.17

### Bugfixes

- Resolved installation failures on some Windows systems
- Fixed the `mount` resource for network mounts using the root level as the device. Thanks [@ramereth](https://github.com/ramereth)!
- Resolved a Compliance Phase failure with profile names using the `@` symbol.

### Security

Upgraded OpenSSL to 1.0.2y, which resolves the following CVEs:

- [CVE-2021-23841](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23841)
- [CVE-2021-23839](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23839)
- [CVE-2021-23840](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23840)

### Platform Updates

With the release of macOS 11 we will no longer produce packages for macOS 10.13 systems. See our [Platform End-of-Life Policy](https://docs.chef.io/platforms/#platform-end-of-life-policy) for details on the platform lifecycle.

## What's New in 16.10

### Improvements

#### Improved Linux Network Detection

On Linux systems, Chef Infra Client now detects all installed NICs on systems with more than 10 interfaces and will populate Ethernet pause frame information if present. Thanks for these improvements [@kuba-moo](https://github.com/kuba-moo) and [@Babar](https://github.com/Babar)!

#### AWS Instance Metadata Service Version 2 (IMDSv2) support

Chef Infra Client now supports the latest generation of AWS metadata services (IMDSv2). This allows you to secure the contents of the metadata endpoint while still exposing this data for use in Chef Infra cookbooks. Thanks for this new functionality [@wilkosz](https://github.com/wilkosz) and [@sawanoboly](https://github.com/sawanoboly)!

#### Improved AWS Metadata Gathering

On AWS instances, we now gather data from the latest metadata API versions, exposing new AWS instance information for use in Infra Cookbooks:

- elastic-gpus/associations/elastic-gpu-id
- elastic-inference/associations/eia-id
- events/maintenance/history
- events/maintenance/scheduled
- events/recommendations/rebalance
- instance-life-cycle
- network/interfaces/macs/mac/network-card-index
- placement/availability-zone-id
- placement/group-name
- placement/host-id
- placement/partition-number
- placement/region
- spot/instance-action

#### Alma Linux Detection

Chef Infra Client now maps [Alma Linux](https://almalinux.org/) to the `rhel` `platform_family` value. Alma Linux is a new open-source RHEL fork produced by the CloudLinux team. Alma Linux falls under Chef's [Community Support](https://docs.chef.io/platforms/#community-support) platform support policy providing community driven support without the extensive testing given to commercially supported platforms in Chef Infra Client.

You can test cookbooks on Alma Linux in Test Kitchen using [Alma Linux 8 Vagrant Images](https://app.vagrantup.com/bento/boxes/almalinux-8 on VirtualBox, Parallels, and VMware hypervisors as follows:

```yaml
platforms:
  - name: almalinux-8
    driver:
      box: bento/almalinux-8
```

#### Knife Bootstrapping Without Sudo

The `knife bootstrap` command now supports elevating privileges on systems without `sudo` by using the `su` command instead. Use the new `--su-user` and `--su-password` flags to specify credentials for `su`.

### Resource Updates

#### dnf_package

The `dnf_package` has been updated to maintain idempotency when using the `:upgrade` action when the RPM release "number" contains a dot (`.`).

#### windows_certificate

The `windows_certificate` resource now honors the `user_store` property to manage certificates in the User store instead of the System store.

## What's New in 16.9.32

### Improvements

- Resolved orphaned PowerShell processes when using Compliance Remediation content.
- Reduced Chef Infra Client install size by up to 5%.

### Chef InSpec 4.26.4

Chef InSpec has been updated from 4.25.1 to 4.26.4.

#### New Features

- You can now directly refer to settings in the `nginx_conf` resource using the `its` syntax. Thanks [@rgeissert](https://github.com/rgeissert)!
- You can now specify the shell type for WinRM connections using the `--winrm-shell-type` option. Thanks [@catriona1](https://github.com/catriona1)!
- Plugin settings can now be set programmatically. Thanks [@tecracer-theinen](https:/github.com/tecracer-theinen)!

#### Bug Fixes

- Updated the `oracledb_session` to use more general invocation options. Thanks [@pacopal](https://github.com/pacopal)!
- Fixed an error with the `http` resource in Chef Infra Client by including `faraday_middleware` in the gemspec.
- Fixed an incompatibility between `parslet` and `toml` in Chef Infra Client.
- Improved programmatic plugin configuration.

## What's New in 16.9.29

### Chef InSpec 4.25.1

Chef InSpec has been updated from 4.24.8 to 4.25.1:

- OpenSSH Client on Windows can now be tested with the ssh_config and sshd_config resources. Thanks [@rgeissert](https://github.com/rgeissert)!
- The `--reporter-message-truncation` option now also truncates the `code_desc` field, preventing failures when sending large reports to Automate.

### Bug Fixes

- Resolved failures from running `chef-client` on some Windows systems.
- Compliance Phase: Improved detection of the `audit` cookbook when it is used for compliance reporting.
- chef-shell: Added support for loading configs in `client.d` directories - Thanks [@jaymzh](https://github.com/jaymzh)!
- Duplicate gems in our packaging have been removed to further shrink the package sizes and improve load time.

## What's New in 16.9.20

- Updated the package resource on FreeBSD to work with recent changes to the pkgng executable. Thanks [@mrtazz](https://github.com/mrtazz/)
- Added a missing dependency in the chef-zero binary that could cause failures when running chef-zero.
- Resolved failures when running the audit cookbook from our yet-to-be-fully-released Chef Infra Compliance Phase. As it turns out, this dark launch was not as dark as we had hoped.

## What's New in 16.9

### Knife Improvements

- The `knife bootstrap` command now properly formats the `trusted_certs_dir` configuration value on Windows hosts. Thanks for this fix [@axelrtgs](https://github.com/axelrtgs)!
- The `knife bootstrap` command now only specifies the ssh option `-o IdentitiesOnly=yes` if keys are present. Thanks for this fix [@drbrain](https://github.com/drbrain)!
- The `knife status` command with the `-F json` flag no longer fails if cloud nodes have no public IP.

### Updated Resources

#### cron_d

The `cron_d` resource now respects the use of the `sensitive` property. Thanks for this fix [@axl89](https://github.com/axl89)!

#### dnf

The `dnf` resource has received a large number of improvements to provide improved idempotency and to better handle uses of the `version` and `arch` properties. Thanks for reporting these issues [@epilatow](https://github.com/epilatow) and [@Blorpy](https://github.com/Blorpy)!

#### homebrew_cask

The `homebrew_cask` resource has been updated to work with the latest command syntax requirements in the `brew` command. Thanks for reporting this issue [@bcg62](https://github.com/bcg62)!

#### locale

The allowed execution time for the `locale-gen` command in the `locale` resource has been extended to 1800 seconds to make sure the Chef Infra Client run doesn't fail before the command completes on slower systems. Thanks for reporting this issue [@janskarvall](https://github.com/janskarvall)!

#### plist / macosx_service / osx_profile / macos_userdefaults

Parsing of plist files has been improved in the `plist`, `macosx_service`, `osx_profile`, and `macos_userdefaults` resources thanks to updates to the plist gem by [@reitermarkus](https://github.com/reitermarkus) and [@tboyko](https://github.com/tboyko).

#### user

The `user` resource on Windows hosts now properly handles `uid` values passed as strings instead of integers. Thanks for reporting this issue [@jaymzh](https://github.com/jaymzh)!

#### yum_repository

The `yum_repository` resource has been updated with a new `reposdir` property to control the path where the Yum repository configuration files will be written. Thanks for suggesting this [@wildcrazyman](https://github.com/wildcrazyman)!

### Security

- The bundled Nokogiri Ruby gem has been updated to 1.11 resolve [CVE-2020-26247](https://nvd.nist.gov/vuln/detail/CVE-2020-26247).

## What's New in 16.8.14

- Updated openSSL to 1.0.2x to resolve [CVE-2020-1971](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1971).
- Updated libarchive to 3.5.0, which powers the `archive_file` resource. This new release resolves extraction failures and better handles symlinks in archives.
- `knife ssh` with the `--sudo` flag will no longer silently fail. Thanks for the fix [@rveznaver](https://github.com/rveznaver)!
- Resolve failures running the Compliance Phase introduced in the 16.8.9 release. Thanks for reporting this issue [@axelrtgs](https://github.com/axelrtgs)!

## What's New in 16.8.9

### Chef InSpec 4.24

Chef InSpec has been updated to 4.24.8 including the following improvements:

- An unset `HOME` environment variable will not cause execution failures
- You can use wildcards in `platform-name` and `release` in InSpec profiles
- The support for arrays in the `WMI` resource, so it can return multiple objects
- The `package` resource on Windows properly escapes package names
- The `grub_conf` resource succeeds even if without a `menuentry` in the grub config
- Loaded plugins won't try to re-load themselves

### Updated Resources

#### dsc_resource / dsc_script

The `dsc_resource` and `dsc_script` resources have been updated to use the `powershell_exec` helper for significantly improved performance executing the PowerShell commands.

#### hostname

The `hostname` resource has been updated to prevent failures when the default system hostname is set on macOS hosts.

#### remote_file

The `remote_file` resource has been updated to use certificates located in Chef Infra Client's `trusted_certificates` directory. Thanks for reporting this issue [@carguel](https://github.com/carguel/)!

#### windows_certificate

The `windows_certificate` has been updated with a new `exportable` property that marks PFX files as exportable in the certificate store.

### Ohai Improvements

- A new optional `Grub2` plugin can be enabled to expose GRUB2 environment variables.
- Linode cloud detection has been improved.

### Platform Packages

We are once again building packages for Solaris on Sparc and x86 platforms.

## What's New in 16.7

### Performance Enhancements

In Chef Infra Client 16.7, we've put a particular focus on optimizing the performance of the client. We've created several dozen minor optimizations that increase performance and reduce overall memory usage across all platforms. On Windows, our work has been particularly pronounced as we've improved resource execution and Chef Infra Client installation. Chef Infra Client install times on Windows are now up to 3x faster than previous releases. Resources that use PowerShell to make changes now execute significantly faster. This improvement will be the most noticeable in Chef Infra Client runs that don't make actual system changes (no-op runs), where determining the current system state was previously resource-intensive.

### Windows Bootstrap Improvements

We've improved how Windows nodes are bootstrapped when using the `knife bootstrap` command. The `knife bootstrap` `--secret` flag is now respected on Windows hosts, allowing for the proper setup of nodes to use encrypted data bags. Thanks for reporting this issue [@AMC-7](https://github.com/AMC-7)! Additionally, during the bootstrap we now force connections to use TLS 1.2, preventing failures on Windows 2012-2016. Thanks for this improvement [@TimothyTitan](https://github.com/TimothyTitan)!

### Chef Vault 4.1

We've updated the release of `chef-vault` bundled with Chef Infra Client to 4.1. Chef Vault 4.1 properly handles escape strings in secrets and greatly improves performance for users with large numbers of secrets. Thanks for the performance work [@Annih](https://github.com/Annih)!

### Updated Resources

#### build_essential

The `build_essential` resource has been updated to resolve idempotency issues and greatly improve performance on macOS hosts.

#### chef_client_config

The `chef_client_config` resource has been updated to no longer produce invalid `client.rb` content.

#### group

The `group` resource has been improved to provide log output of changes being made and on Windows now properly translates group SIDs to names in order to operate idempotently.

Thanks for these improvements [@jaymzh](https://github.com/jaymzh)!

#### homebrew_update

The `homebrew_update` has been updated to resolve failures that would occur when running the resource.

#### ifconfig

The `ifconfig` resource has been updated to better support Linux distributions that are derivatives of either Ubuntu or Debian. Support for setting the `BRIDGE` property on RHEL-based systems has also been added.

#### mount

The `mount` resource has been updated to resolve several issues:

- Idempotency failures when using labels on Linux hosts.
- Idempotency failures when using network paths that end with a slash.
- fstab entries being reordered instead of performing in-place updates.

Thanks for reporting these issues [@limitusus](https://github.com/limitusus), [@axelrtgs](https://github.com/axelrtgs), and [@scarpe01](https://github.com/scarpe01)!

#### powershell_package

The `powershell_package` resource has been updated to better force connections to use TLS 1.2 when communicating with the PowerShell Gallery on Windows Server 2012-2016. Connections must be forced to use TLS 1.2 as the system default cipher suite because Windows 2012-2016 did not include TLS 1.2.

#### powershell_script

The `powershell_script` resource has been updated to not fail when using a `not_if` or `only_if` guard when specifying the `user` property. Thanks for reporting this issue [@Blorpy](https://github.com/Blorpy)!

#### user

The `user` resource has been improved to provide log output of changes being made.

Thanks for this improvement [@jaymzh](https://github.com/jaymzh)!

#### zypper_package

The `zypper_package` resource has been refactored to improve idempotency when specifying a version of the package to either install or downgrade.

### Ohai Improvements

- The `Joyent` plugin has been removed as the Joyent public cloud was shutdown 11/2019
- `pop_os` is now detected as having the `platform_family` of `debian`. Thanks for this improvement [@chasebolt](https://github.com/chasebolt)!
- Recent `openindiana` releases are now properly detected.
- The `Hostnamectl` plugin properly detects hostnames that contain a colon. Thanks for reporting this [@ziggythehamster](https://github.com/ziggythehamster)!
- The `Zpool` plugin now properly detects ZFS zpools that include `nvme` or `xvd` drives. Thanks for reporting this [@ziggythehamster](https://github.com/ziggythehamster)!
- The `Zpool` plugin now properly detects ZFS zpools that use disk labels/guids instead of traditional drive designations.
- Performance of system configuration gathering on AIX systems has been improved
- The `Virtualization` plugin on AIX systems now gathers a state `state` per WPAR and properly gathers LPAR names that include spaces

## What's New in 16.6

### pwsh Support

We've updated multiple parts of the Chef Infra Client to fully support Microsoft's `pwsh` (commonly known as PowerShell Core) in addition to our previous support for `PowerShell`.

#### powershell_script resource

The `powershell_script` resource includes a new `interpreter` property that accepts either `powershell` or `pwsh`.

```ruby
powershell_script 'check version table' do
  code '$PSVersionTable'
  interpreter 'pwsh'
end
```

#### powershell_out / powershell_exec helpers

The `powershell_out` and `powershell_exec` helpers for use in custom resources have been updated to support `pwsh` with a new argument that accepts either `:pwsh` or `:powershell`.

```ruby
powershell_exec('$PSVersionTable', :pwsh)
```

### Enhanced 32-bit Windows Support

The `powershell_exec` helper now supports the 32-bit version of Windows. This ensures many of the newer PowerShell based resources in Chef Infra Client will function as expected on 32-bit systems.

### New Resources

#### chef_client_config

The `chef_client_config` resource allows you to manage Chef Infra Client's `client.rb` file without the need for the `chef-client` cookbook.

##### Example

```ruby
chef_client_config 'Create client.rb' do
  chef_server_url 'https://chef.example.dmz'
end
```

##### chef-client Cookbook Future

With the inclusion of the `chef_client_config` resource in Chef Infra Client 16.6, it is now possible to fully manage the Chef Infra Client without the need for the `chef-client` cookbook. We highly recommend using the `chef_client_config`, `chef_client_trusted_certificate`, and `chef_client_*` service resources to manage your clients instead of the `chef-client` cookbook. In the future we will mark that cookbook as deprecated, at which time it will no longer receive updates.

Here's a sample of fully managing Linux hosts with the built-in resources:

```ruby
chef_client_config 'Create client.rb' do
  chef_server_url 'https://chef.example.dmz'
end

chef_client_trusted_certificate "chef.example.dmz" do
  certificate <<~CERT
  -----BEGIN CERTIFICATE-----
  MIIDeTCCAmGgAwIBAgIJAPziuikCTox4MA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNV
  BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNp
  c2NvMQ8wDQYDVQQKDAZCYWRTU0wxFTATBgNVBAMMDCouYmFkc3NsLmNvbTAeFw0x
  OTEwMDkyMzQxNTJaFw0yMTEwMDgyMzQxNTJaMGIxCzAJBgNVBAYTAlVTMRMwEQYD
  VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ8wDQYDVQQK
  DAZCYWRTU0wxFTATBgNVBAMMDCouYmFkc3NsLmNvbTCCASIwDQYJKoZIhvcNAQEB
  BQADggEPADCCAQoCggEBAMIE7PiM7gTCs9hQ1XBYzJMY61yoaEmwIrX5lZ6xKyx2
  PmzAS2BMTOqytMAPgLaw+XLJhgL5XEFdEyt/ccRLvOmULlA3pmccYYz2QULFRtMW
  hyefdOsKnRFSJiFzbIRMeVXk0WvoBj1IFVKtsyjbqv9u/2CVSndrOfEk0TG23U3A
  xPxTuW1CrbV8/q71FdIzSOciccfCFHpsKOo3St/qbLVytH5aohbcabFXRNsKEqve
  ww9HdFxBIuGa+RuT5q0iBikusbpJHAwnnqP7i/dAcgCskgjZjFeEU4EFy+b+a1SY
  QCeFxxC7c3DvaRhBB0VVfPlkPz0sw6l865MaTIbRyoUCAwEAAaMyMDAwCQYDVR0T
  BAIwADAjBgNVHREEHDAaggwqLmJhZHNzbC5jb22CCmJhZHNzbC5jb20wDQYJKoZI
  hvcNAQELBQADggEBAGlwCdbPxflZfYOaukZGCaxYK6gpincX4Lla4Ui2WdeQxE95
  w7fChXvP3YkE3UYUE7mupZ0eg4ZILr/A0e7JQDsgIu/SRTUE0domCKgPZ8v99k3A
  vka4LpLK51jHJJK7EFgo3ca2nldd97GM0MU41xHFk8qaK1tWJkfrrfcGwDJ4GQPI
  iLlm6i0yHq1Qg1RypAXJy5dTlRXlCLd8ufWhhiwW0W75Va5AEnJuqpQrKwl3KQVe
  wGj67WWRgLfSr+4QG1mNvCZb2CkjZWmxkGPuoP40/y7Yu5OFqxP5tAjj4YixCYTW
  EVA0pmzIzgBg+JIe3PdRy27T0asgQW/F4TY61Yk=
  -----END CERTIFICATE-----
  CERT
end

chef_client_systemd_timer "Run chef-client as a systemd timer" do
  interval "1hr"
  cpu_quota 50
end
```

### Target Mode Improvements

Chef Infra Client 16 introduced an experimental Target Mode feature for executing resources remotely against hosts that do not have a Chef Infra Client or even Ruby installed. For Chef Infra Client 16.6 we've improved this functionality by converting the majority of the Ohai plugins to run remotely. This means when using Target Mode you'll have the majority of Ohai data as if the Chef Infra Client was installed on the node. Keep in mind this data collection can be time consuming over high latency network connections, and cloud plugins which fetch metadata cannot currently be run remotely. Ohai also now includes a `--target` option for remote data gathering, which accepts a Train URI: `ohai --target ssh://foobar.example.org/`. We still consider Target Mode to be an experimental feature, and we'd love your feedback on what works and what doesn't in your environment. A super huge thanks for the countless hours of work put in by [tecRacer](https://www.tecracer.de/), [@tecracer-theinen](https://github.com/tecracer-theinen), and [burtlo](https://github.com/burtlo) to make this a reality.

### Updated Resources

#### ifconfig

The `ifconfig` resource has been updated to no longer add empty blank lines to the configuration files. Thanks for this improvement [@jmherbst](https://github.com/jmherbst/)!

#### windows_audit_policy

The `windows_audit_policy` resource has been updated to fix a bug on failure-only auditing.

### Ohai Improvements

#### Passwd Plugin For Windows

The optional Ohai `Passwd` plugin now supports Windows hosts in addition to Unix-like systems. To collect user/group data on Windows hosts you can use the `ohai_optional_plugins` property in the new `chef_client_config` resource to enable this plugin.

```ruby
chef_client_config 'Create client.rb' do
  chef_server_url 'https://chef.example.dmz'
  ohai_optional_plugins [:Passwd]
end
```

Thanks for adding Windows support to this plugin [@jaymzh](https://github.com/jaymzh)!

#### Improved Azure Detection

The `Azure` plugin has been improved to better detect Windows hosts running on Azure. The plugin will now look for DHCP with the domain of `reddog.microsoft.com`. Thanks for this improvement [@jasonwbarnett](https://github.com/jasonwbarnett/)!

#### EC2 IAM Role Data

Ohai now collects IAM Role data on EC2 hosts including the role name and info. To address potential security concerns the data we collect is sanitized to ensure we don't report security credentials to the Chef Infra Server. Thanks for this improvement [@kcbraunschweig](https://github.com/kcbraunschweig)!

### Security

Ruby has been updated to 2.7.2, which includes a fix for [CVE-2020-25613](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25613).

## Whats New in 16.5.77

- Added missing requires to prevent errors when loading `chef/policy_builder/dynamic`.
- The `homebrew_package` resource will now check for the full and short package names. Both `homebrew_package 'homebrew/core/vim'` and `homebrew_package 'vim'` styles should now work correctly.
- Resolved errors that occurred in cookbooks requiring `addressable/uri`.
- Improved the license acceptance flow to give helpful information if the user passes an invalid value in the environment variable or command line argument.
- Updated Chef InSpec to 4.23.11 in order to resolve issues when running the new `junit2` reporter.
- Additional performance improvements to reduce the startup time of the `chef-client` and `knife` commands.
- `knife vault` commands now output proper JSON or YAML when using the `-f json` or `-f yaml` flags.

## What's New in 16.5

### Performance Improvements

We continue to reduce the size of the Chef Infra Client install and optimize the performance of the client. With Chef Infra Client 16.5 we've greatly reduced the startup time of the `chef-client` process. Startup times on macOS, Linux, and Windows hosts are now approximately 2x faster than the 16.4 release.

### CLI Improvements

- The client license acceptance logic has been improved to provide helpful error messages when an incorrect value is passed and to accept license values in any text case.
- A new `chef-client` process exit code of 43 has been added to signal that an invalid configuration was specified. Thanks [@NaomiReeves](https://github.com/NaomiReeves)!
- The `knife ssh` command no longer hangs when connecting to Windows nodes over SSH.
- The `knife config` commands have been renamed to make them shorter and table output has been improved:
  - knife config get-profile -> knife config use
  - knife config use-profile [NAME] -> knife config use [NAME]
  - knife config list-profiles -> knife config list
  - knife config get -> knife config show

### Chef InSpec 4.23.4

Chef InSpec has been updated from 4.22.1 to 4.23.4. This new release includes the following improvements:

- A new mechanism marks inputs as sensitive: true and replaces their values with `***`.
- Use the `--no-diff` CLI option to suppress diff output for textual tests.
- Control the order of controls in output, but not execution order, with the `--sort_results_by=none|control|file|random` CLI option.
- Disable caching of inputs with a cache_inputs: true setting.

### New Resources

#### chef_client_launchd

The `chef_client_launchd` resource allows you to configure Chef Infra Client to run as a global launchd daemon on macOS hosts. This resource mirrors the configuration of other `chef_client_*` resources and allows for simple out-of-the-box configuration of the daemon, while also providing advanced tunables. If you've used the `chef-client` cookbook in the past, you'll notice a number of improvements in the new resource including configuration update handling, splay times support, nice level support, and an out-of-the-box configuration of low IO priority execution. In order to handle restarting the Chef Infra Client launchd daemon when configuration changes occur, the resource also installs a new `com.chef.restarter` daemon. This daemon watches for daemon configuration changes and gracefully handles the restart to ensure the client process continues to run.

```ruby
chef_client_launchd 'Setup the Chef Infra Client to run every 30 minutes' do
  interval 30
  action :enable
end
```

#### chef_client_trusted_certificate

The `chef_client_trusted_certificate` resource allows you to add a certificate to Chef Infra Client's trusted certificate directory. The resource handles platform-specific locations and creates the trusted certificates directory if it doesn't already exist. Once a certificate is added, it will be used by the client itself to communicate with the Chef Infra Server and by resources such as `remote_file`.

```ruby
chef_client_trusted_certificate 'self-signed.badssl.com' do
  certificate <<~CERT
  -----BEGIN CERTIFICATE-----
  MIIDeTCCAmGgAwIBAgIJAPziuikCTox4MA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNV
  BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNp
  c2NvMQ8wDQYDVQQKDAZCYWRTU0wxFTATBgNVBAMMDCouYmFkc3NsLmNvbTAeFw0x
  OTEwMDkyMzQxNTJaFw0yMTEwMDgyMzQxNTJaMGIxCzAJBgNVBAYTAlVTMRMwEQYD
  VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ8wDQYDVQQK
  DAZCYWRTU0wxFTATBgNVBAMMDCouYmFkc3NsLmNvbTCCASIwDQYJKoZIhvcNAQEB
  BQADggEPADCCAQoCggEBAMIE7PiM7gTCs9hQ1XBYzJMY61yoaEmwIrX5lZ6xKyx2
  PmzAS2BMTOqytMAPgLaw+XLJhgL5XEFdEyt/ccRLvOmULlA3pmccYYz2QULFRtMW
  hyefdOsKnRFSJiFzbIRMeVXk0WvoBj1IFVKtsyjbqv9u/2CVSndrOfEk0TG23U3A
  xPxTuW1CrbV8/q71FdIzSOciccfCFHpsKOo3St/qbLVytH5aohbcabFXRNsKEqve
  ww9HdFxBIuGa+RuT5q0iBikusbpJHAwnnqP7i/dAcgCskgjZjFeEU4EFy+b+a1SY
  QCeFxxC7c3DvaRhBB0VVfPlkPz0sw6l865MaTIbRyoUCAwEAAaMyMDAwCQYDVR0T
  BAIwADAjBgNVHREEHDAaggwqLmJhZHNzbC5jb22CCmJhZHNzbC5jb20wDQYJKoZI
  hvcNAQELBQADggEBAGlwCdbPxflZfYOaukZGCaxYK6gpincX4Lla4Ui2WdeQxE95
  w7fChXvP3YkE3UYUE7mupZ0eg4ZILr/A0e7JQDsgIu/SRTUE0domCKgPZ8v99k3A
  vka4LpLK51jHJJK7EFgo3ca2nldd97GM0MU41xHFk8qaK1tWJkfrrfcGwDJ4GQPI
  iLlm6i0yHq1Qg1RypAXJy5dTlRXlCLd8ufWhhiwW0W75Va5AEnJuqpQrKwl3KQVe
  wGj67WWRgLfSr+4QG1mNvCZb2CkjZWmxkGPuoP40/y7Yu5OFqxP5tAjj4YixCYTW
  EVA0pmzIzgBg+JIe3PdRy27T0asgQW/F4TY61Yk=
  -----END CERTIFICATE-----
  CERT
end
```

### Resource Updates

#### chef_client_cron

The `chef_client_cron` resource has been updated with a new `nice` property that allows you to set the nice level for the `chef-client` process. Nice level changes only apply to the `chef-client` process and not any subprocesses like `ohai` or system utility calls. If you need to ensure that the `chef-client` process does not negatively impact system performance, we highly recommend instead using the `cpu_quota` property in the `chef_client_systemd_timer` resource which applies to all child processes.

#### chef_client_systemd_timer

The `chef_client_systemd_timer` resource has been updated with a new `cpu_quota` property that allows you to control the systemd `CPUQuota` value for the `chef-client` process. This allows you to ensure `chef-client` execution doesn't adversely impact performance on your systems.

#### launchd

The `launchd` resource has been updated to better validate inputs to the `nice` property so we can make sure these are acceptable nice values.

#### mount

The `mount` resource on Linux has new improved idempotency in some scenarios by switching to `findmnt` to determine the current state of the system. Thanks for reporting this issue [@pollosp](https://github.com/pollosp)!

#### osx_profile

The `osx_profile` resource will now allow you to remove profiles from macOS 11 (Big Sur) systems. Due to security changes in macOS 11, it is no longer possible to locally install profiles, but this will allow you to cleanup existing profiles left over after an upgrade from an earlier macOS release. The resource has been updated to resolve a regression introduced in Chef Infra Client 16.4 that caused the resource to attempt to update profiles on each converge. Thanks for reporting these issues [@chilcote](https://github.com/chilcote)!

#### rhsm_register

The `rhsm_register` resource has been updated to reduce the load on the RedHat Satellite server when checking if a system is already registered. Thanks for reporting this issue [@donwlewis](https://github.com/donwlewis)! A new `system_name` property has also been added to allow you to register a name other than the system's hostname. Thanks for this improvement [@jasonwbarnett](https://github.com/jasonwbarnett/)!

#### windows_ad_join

The `windows_ad_join` resource has been updated with a new `reboot_delay` property which allows you to control the delay time before restarting systems.

#### windows_firewall_profile

The `windows_firewall_profile` resource was updated to prevent NilClass errors from loading the firewall state.

#### windows_user_privilege

The `windows_user_privilege` resource has been updated to better validate the `privilege` property and to allow the `users` property to accept String values. Thanks for reporting this issue [@jeremyciak](https://github.com/jeremyciak)!

#### Windows securable resources

All Windows securable resources now support using SID in addition to user or group name when specifying `owner`, `group`, or `rights` principal. These resources include the `template`, `file`, `remote_file`, `cookbook_file`, `directory`, and `remote_directory` resources. When using a SID, you may use either the standard string representation of a SID (S-R-I-S-S) or one of the [SDDL string constants](https://docs.microsoft.com/en-us/windows/win32/secauthz/sid-strings).

### Ohai Improvements

- Ohai now uses the same underlying code for shelling out to external commands as Chef Infra Client. This may resolve issues from determining the state on some non-English systems.
- The `Packages` plugin has been updated to gather package installation information on macOS hosts.

### Platform Packages

- We are once again building Chef Infra Client packages for RHEL 7 / SLES 12 on the S390x architecture. In addition to these packages, we've also added S390x packages for RHEL 8 / SLES 15.
- We now produce packages for Apple's upcoming macOS 11 Big Sur release.

### Security

OpenSSL has been updated to 1.0.2w which includes a fix for [CVE-2020-1968](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2020-1968).

## What's New in 16.4

### Resource Updates

#### chef_client_systemd_timer

The `chef_client_systemd_timer` resource has been updated to prevent failures running the `:remove` action.

#### openssl resource

The various openssl_* resources were refactored to better report the changed state of the resource to Automate or other handlers.

#### osx_profile

The `osx_profile` resource has been refactored as a custom resource internally. This update also better reports the changed state of the resource to Automate or other handlers and no longer silently continues if the attempts to shellout fail.

#### powershell_package_source

The `powershell_package_source` resource no longer requires the `url` property to be set when using the `:unregister` action. Thanks for this fix [@kimbernator](https://github.com/kimbernator)!

#### powershell_script

The `powershell_script` resource has been refactored to better report the changed state of the resource to Automate or other handlers.

#### windows_feature

The `windows_feature` resource has been updated to allow installing features that have been removed if a source location is provided. Thanks for reporting this [@stefanwb](https://github.com/stefanwb)!

#### windows_font

The `windows_font` resource will no longer fail on newer releases of Windows if a font is already installed. Thanks for reporting this [@bmiller08](https://github.com/bmiller08)!

#### windows_workgroup

The `windows_workgroup` resource has been updated to treat the `password` property as a sensitive property. The value of the `password` property will no longer be shown in logs or handlers.

### Security

#### CA Root Certificates

The included `cacerts` bundle in Chef Infra Client has been updated to the 7-22-2020 release. This new release removes 4 legacy root certificates and adds 4 additional root certificates.

#### Reduced Dependencies

We've audited the included dependencies that we ship with Chef Infra Client to reduce the 3rd party code we ship. We've removed many of the embedded binaries that shipped with the client in the past, but were not directly used. We've also reduced the feature set built into many of the libraries that we depend on, and removed several Ruby gem dependencies that were no longer necessary. This reduces the future potential for CVEs in the product and reduces package size at the same time.

## What's New in 16.3.45

- Resolved failures negotiating protocol versions with the Chef Infra Server.
- Improved log output on Windows systems in the `hostname` resource.
- Added support to the `archive_file` resource for `pzstd` compressed files.

## What's New in 16.3.38

### Renamed Client Configuration Options

We took a hard look at many of the terms we've historically used throughout the Chef Infra Client configuration sub-system and came to the realization that we weren't living up to the words of our [Community Code of Conduct](https://community.chef.io/code-of-conduct/). From the code of conduct: "Be careful in the words that you choose. Be kind to others. Practice empathy". Terms such as blacklist and sanity don't meet that bar so we've chosen to rename these configuration options:

- `automatic_attribute_blacklist` -> `blocked_automatic_attributes`
- `default_attribute_blacklist` -> `blocked_default_attributes`
- `normal_attribute_blacklist` -> `blocked_normal_attributes`
- `override_attribute_blacklist` -> `blocked_override_attributes`
- `automatic_attribute_whitelist` -> `allowed_automatic_attributes`
- `default_attribute_whitelist` -> `allowed_default_attributes`
- `normal_attribute_whitelist` -> ``allowed_normal_attributes``
- `override_attribute_whitelist` -> `allowed_override_attributes`
- `enforce_path_sanity` -> `enforce_default_paths`

Existing configuration options will continue to function for now, but will raise a deprecation warning and will be removed entirely from a future release of Chef Infra Client.

### Chef InSpec 4.22.1

Chef InSpec has been updated from 4.21.1 to 4.22.1. This new release includes the following improvements:

- The `=` character is now allowed for command line inputs
- `apt-cdrom` repositories are now skipped when parsing out the list of apt repositories
- Faulty profiles are now reported instead of causing a crash
- Errors are no longer logged to stdout with the `html2` reporter
- macOS Big Sur is now correctly identified as macOS

### New Resources

#### windows_firewall_profile

The `windows_firewall_profile` allows you to `enable`, `disable`, or `configure` Windows Firewall profiles. For example, you can now set up default actions and configure rules for the `Public` profile using this single resource instead of managing your own PowerShell code in a `powershell_script` resource:

```ruby
windows_firewall_profile 'Public' do
  default_inbound_action 'Block'
  default_outbound_action 'Allow'
  allow_inbound_rules false
  display_notification false
  action :enable
end
```

For a complete guide to all properties and additional examples, see the [windows_firewall_profile documentation](https://docs.chef.io/resources/windows_firewall_profile).

### Resource Updates

#### build_essential

Log output has been improved in the `build_essential` resource when running on macOS systems.

#### chef_client_scheduled_task

The `chef_client_scheduled_task` resource no longer sets up the schedule task with invalid double quoting around the specified command. Thanks for reporting this issue [@tiobagio](https://github.com/tiobagio/).

#### execute

The `user` property in the `execute` resource can now accept user IDs as Integers.

#### git

The `git` resource will no longer fail if syncing a branch that already exists locally. Thanks for fixing this [@lotooo](https://github.com/lotooo/).

#### macos_user_defaults

The `macos_user_defaults` has received a ground-up refactoring with new actions, additional properties, and better overall reliability:

- Improved idempotency by properly loading the current state of domains.
- Improved how we set `dict` and `array` type data.
- Improved logging to show the existing key/value pair that is changed, and improved the property state data that the resource sends to handlers and/or Chef Automate.
- Fixed a failure when setting keys or values that included a space.
- Replaced the existing non-functional `global` property with a new default for the `domain` property. To set a key/value pair on the `NSGlobalDomain` domain, you can either set that value explicitly or just skip the `domain` property entirely and Chef Infra Client will default to `NSGlobalDomain`. The existing property has been marked as deprecated and we will ship a Cookstyle rule to detect cookbooks using this property in the future.
- Fixed the `type` property to only accept valid inputs. Previously typos or otherwise incorrect values would just be ignored resulting in unexpected behavior. This may cause failures in your codebase if you previously used incorrect values. We will be shipping a Cookstyle rule to detect and correct these values in the future.
- Added a new `delete` action to allow users to remove a key from a domain.
- Added a new `host` property that lets you set per-host values. If you set this to `:current` it sets the -currentHost flag.

#### windows_dns_record

The `windows_dns_record` resource includes a new optional property, `dns_server`, allowing you to make changes against remote servers. Thanks for this addition [@jeremyciak](https://github.com/jeremyciak/).

#### windows_package

A Chef Infra Client 16 regression within `windows_package` that prevented specifying `path` in the `remote_file_attributes` property has been resolved. Thanks for reporting this issue [@asvinours](https://github.com/asvinours/).

#### windows_security_policy

The `windows_security_policy` resource has been refactored to improve idempotency and improve log output when changes are made. You'll now see more complete change information in logs and any handler consuming this data will also receive more detailed change information.

### Knife Improvements

- Ctrl-C can now be used to exit knife even when being prompted for input.
- `knife bootstrap` will now properly error if attempting to bootstrap an AIX system using an account with an expired password.
- `knife profile` commands will no longer error if an invalid profile was previously set.
- The `-o` flag for `knife cookbook upload` can now be used on Windows systems.
- `knife ssh` now once again accepts legacy DSS host keys although we highly recommend upgrading to a more secure key algorithm if possible.
- Several changes were made to knife to that may prevent intermittent failures running cookbook commands

### Habitat Package Improvements

Habitat packages for Windows, Linux and Linux2 are now built and tested against each pull request to Chef Infra Client. Additionally we've improved how these packages are built to reduce the size of the package, which reduces network utilization when using the Effortless deployment pattern.

## What's New in 16.2.72

- Habitat packages for Chef Infra Client 16 are now published with full support for the `powershell_exec` helper now added.
- Added a new `clear` action to the `windows_user_privilege` resource.
- Resolved a regression in Chef Infra Client 16.1 and later that caused failures running on FIPS enabled systems.
- Resolved failures in the `archive_file` resource when running on Windows hosts.
- Resolved a failure when running `chef-apply` with the `-j` option. Thanks [@komazarari](https://github.com/komazarari).
- Chef Infra Client running within GitHub Actions is now properly identified as running in a Docker container. Thanks [@jaymzh](http://github.com/jaymzh).
- SSH connections are now reused, improving the speed of knife bootstrap and remote resources on slow network links. Thanks [@tecracer-theinen](https://github.com/tecracer-theinen).
- `node['network']['interfaces']` data now correctly identifies IPv6 next hops for IPv4 routes. Thanks [@cooperlees](https://github.com/cooperlees).
- Updated  InSpec from 4.20.10 to 4.21.1.

## What's New in 16.2.50

- Correctly identify the new macOS Big Sur (11.0) beta as platform "mac_os_x".
- Fix `knife config use-profile` to fail if an invalid profile is provided.
- Fix failures running the `windows_security_policy` resource.
- Update InSpec from 4.20.6 to 4.20.10.

## What's New in 16.2.44

### Breaking Change in Resources

In Chef Infra Client 16.0, we changed the way that custom resource names are applied in order to resolve some longstanding edge-cases. This change had several unintended side effects, so we're further changing how custom names are set in this release of Chef Infra Client.

Previously you could set a custom name for a resource via `resource_name` and under the hood this would also magically set the `provides` for the resource. Magic is great when it works, but is confusing when it doesn't. We've decided to remove some of this magic and instead rely on more explicit `provides` statements in resources. For cookbooks that support just Chef Infra Client 16 and later, you should change any `resource_name` calls to `provides` instead. If you need to support older releases of Chef Infra Client as well as 16+, you'll want to include both `resource_name` and `provides` for full compatibility.

**Pre-16 code:**

```ruby
resource_name :foo
```

**Chef Infra Client 16+ code**

```ruby
provides :foo
```

**Chef Infra Client < 16 backwards compatible code**

```ruby
resource_name :foo
provides :foo
```

We've introduced several Cookstyle rules to detect both custom resources and legacy HWRPs that need to be updated for this change:

**[ChefDeprecations/ResourceUsesOnlyResourceName](https://github.com/chef/cookstyle/blob/master/docs/cops_chefdeprecations.md#chefdeprecationsresourceusesonlyresourcename)**: detects resources that only set resource_name and automatically adds a provides call as well.

**[ChefDeprecations/HWRPWithoutProvides](https://github.com/chef/cookstyle/blob/master/docs/cops_chefdeprecations.md#chefdeprecationshwrpwithoutprovides)**: detects legacy HWRPs that don't include the necessary provides and resource_name calls for Chef Infra Client 16.

### Chef InSpec 4.20.6

Chef InSpec has been updated from 4.18.114 to 4.2.0.6. This new release includes the following improvements:

- Develop your own Chef InSpec Reporter plugins to control how Chef InSpec will report result data.
- The `inspec archive` command packs your profile into a `tar.gz` file that includes the profile in JSON form as the inspec.json file.
- Certain substrings within a `.toml` file no longer cause unexpected crashes.
- Accurate InSpec CLI input parsing for numeric values and structured data, which were previously treated as strings. Numeric values are cast to an `integer` or `float` and `YAML` or `JSON` structures are converted to a hash or an array.
- Suppress deprecation warnings on inspec exec with the `--silence-deprecations` option.

### New Resources

#### windows_audit_policy

The `windows_audit_policy` resource is used to configure system-level and per-user Windows advanced audit policy settings. See the [windows_audit_policy Documentation](/resources/windows_audit_policy/) for complete usage information.

For example, you can enable auditing of successful credential validation:

```ruby
windows_audit_policy "Set Audit Policy for 'Credential Validation' actions to 'Success'" do
  subcategory  'Credential Validation'
  success true
  failure false
  action :set
end
```

#### homebrew_update

The `homebrew_update` resource is used to update the available package cache for the Homebrew package system similar to the behavior of the `apt_update` resource. See the [homebrew_update Documentation](/resources/homebrew_update/) for complete usage information. Thanks for adding this new resource, [@damacus](http://github.com/damacus).

### Resource Updates

#### All resources now include umask property

All resources, including custom resources, now have a `umask` property which allows you to specify a umask for file creation. If not specified the system default will continue to be used.

#### archive_file

The `archive_file` resource has been updated with two important fixes. The resource will no longer fail with uninitialized constant errors under some scenarios. Additionally, the behavior of the `mode` property has been improved to prevent incorrect file modes from being applied to the decompressed files. Due to how file modes and Integer values are processed in Ruby, this resource will now produce a deprecation warning if integer values are passed. Using string values lets us accurately pass values such as '644' or '0644' without ambiguity as to the user's intent. Thanks for reporting these issues [@sfiggins](http://github.com/sfiggins) and [@hammerhead](http://github.com/hammerhead).

#### chef_client_scheduled_task

The `chef_client_scheduled_task` resource has been updated to default the `frequency_modifier` property to `30` if the `frequency` property is set to `minutes`, otherwise it still defaults to `1`. This provides a more predictable schedule behavior for users.

#### cron / cron_d

The `cron` and `cron_d` resources have been updated using the new Custom Resource Partials functionality introduced in Chef Infra Client 16. This has allowed us to standardize the properties used to declare cron job timing between the two resources. The timing properties in both resources all accept the same types and ranges, and include the same validation, which makes moving from `cron` to `cron_d` seamless.

#### cron_access

The `cron_access` resource has been updated to support Solaris and AIX systems. Thanks [@aklyachkin](http://github.com/aklyachkin).

#### execute

The `execute` resource has a new `input` property which allows you to pass `stdin` input to the command being executed.

#### powershell_package

The `powershell_package` resource has been updated to use TLS 1.2 when communicating with the PowerShell Gallery on Windows Server 2012-2016. Previously this resource used the system default cipher suite which did not include TLS 1.2. The PowerShell Gallery now requires TLS 1.2 for all communication, which caused failures on Windows Server 2012-2016. Thanks for reporting this issue [@Xorima](http://github.com/Xorima).

#### remote_file

The `remote_file` resource has a new property `ssl_verify_mode` which allows you to control SSL validation at the property level. This can be used to verify certificates (Chef Infra Client's defaults) with `:verify_peer` or to skip verification in the case of a self-signed certificate with `:verify_none`. Thanks [@jaymzh](http://github.com/jaymzh).

#### script

The various `script` resources such as `bash` or `ruby` now pass the provided script content to the interpreter using system pipes instead of writing to a temporary file and executing it. Executing script content using pipes is faster, more secure as potentially sensitive scripts aren't written to disk, and bypasses issues around user privileges.

#### snap_package

Multiple issues with the `snap_package` resource have been resolved, including an infinite wait that occurred, and issues with specifying the package version or channel. Thanks [@jaymzh](http://github.com/jaymzh).

#### zypper_repository

The `zypper_repository` resource has been updated to work with the newer release of GPG in openSUSE 15 and SLES 15. This prevents failures when importing GPG keys in the resource.

### Knife bootstrap updates

- Knife bootstrap will now warn when bootstrapping a system using a validation key. Users should instead use `validatorless bootstrapping` with `knife bootstrap` which generates node and client keys using the client key of the user bootstrapping the node. This method is far more secure as an org-wide validation key does not not need to be distributed or rotated. Users can switch to `validatorless bootstrapping` by removing any `validation_key` entries in their `config.rb (knife.rb)` file.
- Resolved an error bootstrapping Linux nodes from Windows hosts
- Improved information messages during the bootstrap process

### Platform Packages

- Debian 8 packages are no longer being produced as Debian 8 is now end-of-life.
- We now produce Windows 8 packages

## What's New in 16.1.16

This release resolves high-priority bugs in the 16.1 release of Chef Infra Client:

- Resolved a critical performance regression in the Rubygems release within Ruby 2.7, which was discovered by a Chef engineer.
- Resolved several Ruby 2.7 deprecation warnings.
- Added `armv6l` and `armv7l` architectures to the `arm?` and `armhf?` helpers
- Resolved failures in the Windows bootstrap script
- Resolved incorrect paths when bootstrapping Windows nodes

### Security Updates

#### openSSL

openSSL has been updated from 1.0.2u to 1.0.2v which does not address any particular CVEs, but includes multiple security hardening updates.

## What's New in 16.1

### Ohai 16.1

Ohai 16.1 includes a new `Selinux` plugin which exposes `node['selinux']['status']`, `node['selinux']['policy_booleans']`, `node['selinux']['process_contexts']`, and `node['selinux']['file_contexts']`. Thanks [@davide125](http://github.com/davide125) for this contribution. This new plugin is an optional plugin which is disabled by default. It can be enabled within your `client.rb`:

```ruby
ohai.optional_plugins = [ :Selinux ]
```

### Chef InSpec 4.18.114

InSpec has been updated from 4.18.111 to 4.18.114. This update adds new `--reporter_message_truncation` and `--reporter_backtrace_inclusion` reporter options to truncate messages and suppress backtraces.

### Debian 10 aarch64

Chef Infra Client packages are now produced for Debian 10 on the aarch64 architecture. These packages are available at [downloads.chef.io](https://downloads.chef.io/chef/).

### Bug Fixes

- Resolved a regression in the `launchd` resource that prevented it from converging.
- The `:disable` action in the `launchd` resource no longer fails if the plist was not found.
- Several Ruby 2.7 deprecation warnings have been resolved.

## What's New in 16.0.287

The Chef Infra Client 16.0.287 release includes important bug fixes for the Chef Infra Client 16 release:

- Fixes the failure to install Windows packages on the 2nd convergence of the Chef Infra Client.
- Resolves several failures in the `launchd` resource.
- Removes an extra `.java` file on Windows installations that would cause a failure in the IIS 8.5 Server Security Technical Implementation Guide audit.
- Updates the `windows_printer` resource so that the driver property will only be required when using the `:create` action.
- Fixes the incorrectly spelled `knife user invite recind` command to be `knife user invite rescind`. [//]: # "cspell:disable-line"
- Update Chef InSpec to 4.8.111 with several minor improvements.

## What's New in 16.0.275

The Chef Infra Client 16.0.275 release includes important regression fixes for the Chef Infra Client 16 release:

- Resolved failures when using the `windows_package` resource. Thanks for reporting this issue [@cookiecurse](https://github.com/cookiecurse).
- Resolved log warnings when running `execute` resources.
- The appropriate `cron` or `cron_d` resource call is now called when using the `:delete` action in chef_client_cron. Thanks for reporting this issue [jimwise](https://github.com/jimwise).
- The `chef_client_cron` resource now creates the log directory with `750` permissions not `640`. Thanks for this fix [DhaneshRaghavan](https://github.com/DhaneshRaghavan).
- The `knife yaml convert` command now correctly converts symbol values.
- The `sysctl`, `apt_preference`, and `cron_d` remove actions no longer fail with missing property warnings.

## What's New in 16.0

### Breaking Changes

#### Log Resource Notification Behavior

The `log` resource in a recipe or resource will no longer trigger notifications by default. This allows authors to more liberally use `log` resources without impacting the updated resources count or impacting reporting to Chef Automate. This change will impact users that used the `log` resource to aggregate notifications from other resources, so they could limit the number of times a notification would fire. If you used the `log` resource to aggregate multiple notifications, you should convert to using the `notify group` resource, which was introduced in Chef Infra Client 15.8.

Example of notification aggregation with `log` resource:

```ruby
template '/etc/foo' do
  source 'foo.erb'
  notifies :write, 'log[Aggregate notifications using a single log resource]', :immediately
end

template '/etc/bar' do
  source 'bar.erb'
  notifies :write, 'log[Aggregate notifications using a single log resource]', :immediately
end

log 'Aggregate notifications using a single log resource' do
  notifies :restart, 'service[foo]', :delayed
end
```

Example of notification aggregation with `notify_group` resource:

```ruby
template '/etc/foo' do
  source 'foo.erb'
  notifies :run, 'notify_group[Aggregate notifications using a single notify_group resource]', :immediately
end

template '/etc/bar' do
  source 'bar.erb'
  notifies :run, 'notify_group[Aggregate notifications using a single notify_group resource]', :immediately
end

notify_group 'Aggregate notifications using a single notify_group resource' do
  notifies :restart, 'service[foo]', :delayed
end
```

The `ChefDeprecations/LogResourceNotifications` cop in Cookstyle 6.0 and later detects using the `log` resource for notifications in cookbooks.

To restore the previous behavior, set `count_log_resource_updates true` in your `client.rb`.

#### HWRP Style Resources Now Require resource_name / provides

Legacy HWRP-style resources, written as Ruby classes in the libraries directory of a cookbook, will now require either the use of `resource_name` or `provides` methods to define the resource names. Previously, Chef Infra Client would infer the desired resource name from the class, but this magic was problematic and has been removed.

The `ChefDeprecations/ResourceWithoutNameOrProvides` cop in Cookstyle 6.0 and later detects this deprecation.

#### build_essential GCC Updated on Solaris

On Solaris systems, we no longer constrain the version of GCC to 4.8.2 in the `build_essential` resource to allow for GCC 5 installations.

#### git Resource Branch Checkout Changes

The `git` resource no longer checks out to a new branch named `deploy` by default. Many users found this branching behavior confusing and unexpected so we've decided to implement a more predictable default. The resource will now default to either checking out the branch specified with the `checkout_branch` property or a detached HEAD state. If you'd like to revert to the previous behavior you can set the `checkout_branch` to `deploy`.

#### s390x Packaging

As outlined in our blog post at <https://blog.chef.io/chef-infra-end-of-life-announcement-for-linux-client-on-ibm-s390x-architecture/>, we will no longer be producing s390x platform packages for Chef Infra Client.

#### filesystem2 Node Data Replaces filesystem on FreeBSD / AIX / Solaris

In Chef Infra Client 14 we introduced a modernized filesystem layout of Ohai data on FreeBSD, AIX, and Solaris at `node['fileystem2']`. With the release of 16.0, we are now replacing the existing data at `node['filesystem']` with this updated filesystem data. This data has a standardized format that matches Linux and macOS data to make it easier to write cross-platform cookbooks. In a future release of Chef Infra Client we'll remove the `node['filesystem2']` as we complete this migration.

#### required: true on Properties Now Behaves As Expected

The behavior of `required: true` has been changed to better align with the expected behavior. Previously, if you set a property `required: true` on a custom resource property and did not explicitly reference the property in an action, then Chef Infra Client would not raise an exception. This meant many users would add their own validation to raise for resources they wanted to ensure they were always set. `required: true` will now properly raise if a property has not been set.

We have also expanded the `required` field for added flexibility in defining exactly which actions a property is required for. See [Improved property require behavior](#improved-property-require-behavior) below for more details.

#### Removal of Legacy metadata.rb depends Version Constraints

Support for the `<<` and `>>` version constraints in metadata.rb has been removed. This was an undocumented feature from the Chef 0.10 era, which is not used in any cookbooks on the Supermarket. We are mentioning it since it is technically a breaking change, but it unlikely that this change will be impacting.

Examples:

```ruby
depends 'windows', '<< 1.0'
depends 'windows', '>> 1.0'
```

#### Logging Improvements May Cause Behavior Changes

We've made low-level changes to how logging behaves in Chef Infra Client that resolves many complaints we've heard over the years. With these change you'll now see the same logging output when you run `chef-client` on the command line as you will in logs from a daemonized client run. This also corrects often confusing behavior where running `chef-client` on the command line would log to the console, but not to the log file location defined your `client.rb`. In that scenario you'll now see logs in your console and in your log file. We believe this is the expected behavior and will mean that your on-disk log files can always be the source of truth for changes that were made by Chef Infra Client. This may cause unexpected behavior changes for users that relied on using the command line flags to override the `client.rb` log location - in this case logging will be sent to _both_ the location in the `client.rb` and on the command line. If you have daemons running that log using the command line options you want to make sure that `client.rb` log location either matches or isn't defined.

#### Red Hat / CentOS 6 Systems Require C11 GCC for Some Gem Installations

The included release of Ruby in Chef Infra Client 16 now requires a [C99](https://en.wikipedia.org/wiki/C99) compliant compiler when using the `chef_gem` resource with gems that require compilation. Some systems, such as RHEL 6, do not ship with a C99 compiler and will fail if the gems they're attempting to install require compilation. If it is necessary to install compiled gems into the Chef Infra Client installation on one of these systems you can upgrade to a modern GCC release.

CentOS:

```bash
yum install centos-release-scl
yum install devtoolset-7
scl enable devtoolset-7 bash
```

Red Hat:

```bash
yum-config-manager --enable rhel-server-rhscl-7-rpms
yum install devtoolset-7
scl enable devtoolset-7 bash
```

#### Changes to Improve Gem Source behavior

We've improved the behavior for those that use custom rubygem sources, particularly those operating in air-gapped installations. These improvements involved changes to many of the default `client.rb` values and `gem_package`/`chef_gem` properties that require updating your usage of `chef_gem` and `gem_package` resources

The default value of the `clear_sources` property of `gem_package` and `chef_gem` resources has been changed to `nil`. The possible behaviors for clear_sources are now:

- `true`: Always clear sources.
- `false`: Never clear sources.
- `nil`: Clear sources if `source` property is set, but don't clear sources otherwise.

The default value of the `include_default_source` property of `gem_package` and `chef_gem` resources has been changed to `nil`. The possible behaviors for include_default_source are now:

- `true`: Always include the default source.
- `false`: Never include the default source.
- `nil`: Include the default source if `rubygems_url` `client.rb` value is set or if `source` and `clear_sources` are not set on the resource.

The default values of the `rubygems_url` `client.rb` config option has been changed to `nil`. Setting to nil previously had similar behavior to setting `clear_sources` to true, but with some differences. The new behavior is to always use `https://rubygems.org` as the default rubygems repo unless explicitly changed, and whether to use this value is determined by `clear_sources` and `include_default_source`.

#### Behavior Changes in Knife

**knife status --long uses cloud attribute**

The `knife status --long` resource now uses Ohai's cloud data instead of ec2 specific data. This improves, but changes, the data output for users on non-AWS clouds.

**knife download role/environment format update**

The `knife download role` and `knife download environment` commands now include all possible data fields including those without any data set. This new output behavior matches the behavior of other commands such as `knife role show` or `knife environment show`

**Deprecated knife cookbook site command removed**

The previously deprecated `knife cookbook site` commands have been removed. Use the `knife supermarket` commands instead.

**Deprecated knife data bag create -s short option removed**

The deprecated `knife data bag create -s` option that was not properly honored has been removed. Use the `--secret` option instead to set a data bag secret file during data bag creation.

**sites-cookbooks directory no longer in cookbook_path**

The legacy `sites-cookbooks` directory is no longer added to the default `cookbook_path` value. With this change, any users with a legacy `sites-cookbooks` directory will need to use the `-O` flag to override the cookbook directory when running commands such as `knife cookbook upload`.

If you have a repository that contains a `site-cookbooks` directory, we highly recommend using Policyfiles or Berkshelf to properly resolve these external cookbook dependencies without the need to copy them locally. Alternatively, you can move the contents of this folder into your main cookbook directory and they will continue to be seen by knife commands.

### New Resources

#### alternatives

Use the `alternatives` resource to manage symbolic links to specify default command versions on Linux hosts. See the [alternatives documentation](https://docs.chef.io/resources/alternatives/) for full usage information. Thanks [@vkhatri](https://github.com/vkhatri) for the original cookbook alternatives resource.

#### chef_client resources

We've added new resources to Chef Infra Client for setting the client to run on an interval using native system schedulers. We believe that these native schedulers provide a more flexible and reliable method for running the client than the traditional method of running as a full service. Using the native schedulers reduces hung clients and eases upgrades. This is the first of many steps towards removing the need for the `chef-client` cookbook and allowing Chef Infra Client to configure itself out of the box.

**chef_client_cron**

Use the `chef_client_cron` resource to setup the Chef Infra Client to run on a schedule using cron on Linux, Solaris, and AIX systems. See the [chef_client_cron documentation](https://docs.chef.io/resources/chef_client_cron/) for full usage information.

**chef_client_systemd_timer**

Use the `chef_client_systemd_timer` resource to setup the Chef Infra Client to run on a schedule using a systemd timer on systemd based Linux systems (RHEL 7+, Debian 8+, Ubuntu 16.04+ SLES 12+). See the [chef_client_systemd_timer documentation](https://docs.chef.io/resources/chef_client_systemd_timer/) for full usage information.

**chef_client_scheduled_task**

Use the `chef_client_scheduled_task` resource to setup the Chef Infra Client to run on a schedule using Windows Scheduled Tasks. See the [chef_client_scheduled_task documentation](https://docs.chef.io/resources/chef_client_scheduled_task) for full usage information.

#### plist

Use the `plist` resource to generate plist files on macOS hosts. See the [plist documentation](https://docs.chef.io/resources/plist/) for full usage information. Thanks Microsoft and [@americanhanko](https://github.com/americanhanko) for the original work on this resource in the [macos cookbook](https://supermarket.chef.io/cookbooks/macos).

#### user_ulimit

Use the `user_ulimit` resource to set per user ulimit values on Linux systems. See the [user_ulimit documentation](https://docs.chef.io/resources/user_ulimit/) for full usage information. Thanks [@bmhatfield](https://github.com/bmhatfield) for the original work on this resource in the [ulimit cookbook](https://supermarket.chef.io/cookbooks/ulimit).

#### windows_security_policy

Use the `windows_security_policy` resource to modify location security policies on Windows hosts. See the [windows_security_policy documentation](https://docs.chef.io/resources/windows_security_policy/) for full usage information.

#### windows_user_privilege

Use the `windows_user_privilege` resource to add users and groups to the specified privileges on Windows hosts. See the [windows_user_privilege documentation](https://docs.chef.io/resources/windows_user_privilege/) for full usage information.

### Improved Resources

#### compile_time on all resources

The `compile_time` property is now available for all resources so that they can be set to run at compile time without the need to force the action.

Set the `compile_time` property instead of forcing the resource to run at compile time:

```ruby
  my_resource "foo" do
    action :nothing
  end.run_action(:run)
```

With the simpler `compile_time` property:

```ruby
  my_resource "foo" do
    compile_time true
  end
```

#### build_essential

The `build_essential` resource includes a new `:upgrade` action for macOS systems that allows you to install updates to the Xcode Command Line Tools available via Software Update.

#### cron

The `cron` resource has been updated to use the same property validation for cron times that the `cron_d` resource uses. This improves failure messages when invalid inputs are set and also allows for `jan`-`dec` values to be used in the `month` property.

#### dnf_package

The `dnf_package` resource, which provides `package` under the hood on any system shipping with DNF, has been greatly refactored to resolve multiple issues. The version behavior and overall resource capabilities now match that of the `yum_package` resource.

- The `:lock` action now works on RHEL 8.
- Fixes to prevent attempting to install the same package during each Chef Infra Client run.
- Resolved several idempotency issues.
- Resolved an issue where installing a package with `options '--enablerepo=foo'` would fail.

#### git

The `git` resource now fully supports why-run mode and no longer checks out the `deploy` branch by default as mentioned in the breaking changes section.

#### locale

The `locale` resource now supports setting the system locale on Windows hosts.

#### msu_package resource improvements

The `msu_package` resource has been improved to work better with Microsoft's cumulative update packages. Newer releases of these cumulative update packages will not correctly install over the previous versions. We also extended the default timeout for installing MSU packages to 60 minutes. Thanks for reporting the timeout issue, [@danielfloyd](https://github.com/danielfloyd).

#### package

The `package` resource on macOS and Arch Linux systems now supports passing multiple packages into a single package resource via an array. This allows you to collapse multiple resources into a single resource for simpler cookbook authoring, which is significantly faster as it requires fewer calls to the packaging systems. Thanks for the Arch Linux support, [@ingobecker](https://github.com/ingobecker)!

Using multiple resources to install a package:

```ruby
package 'git'
package 'curl'
package 'packer'
```

or

```ruby
%w(git curl packer).each do |pkg|
  package pkg
end
```

can now be simplified to:

```ruby
package %w(git curl packer)
```

#### service

The `service` resource has been updated to support newer releases of `update-rc.d` so that it properly disables sys-v init services on Debian Linux distributions. Thanks [@robuye](https://github.com/robuye)!

#### windows_firewall_rule

The `windows_firewall_rule` resource has been greatly improved thanks to work by [@pschaumburg](https://github.com/pschaumburg) and [@tecracer-theinen](https://github.com/tecracer-theinen).

- New `icmp_type` property, which allows setting the ICMP type when setting up ICMP protocol rules.
- New `displayname` property, which allows defining the display name of the firewall rule.
- New `group` property, which allows you to specify that only matching firewall rules of the indicated group association are copied.
- The `description` property will now update if changed.
- Fixed setting rules with multiple profiles.

#### windows_package

The `windows_package` resource now considers `3010` to be a valid exit code by default. The `3010` exit code means that a package has been successfully installed, but requires a reboot.

**knife-acl is now built-in**

The `knife-acl` gem is now part of Chef Infra Client. This gives you the ability to manage Chef organizations and ACLs directly.

### YAML Recipes

We added support for writing recipes in YAML to provide a low-code syntax for simple use cases. To write recipes in YAML, Chef resources and any user-defined parameters can be added as elements in a `resources` hash, such as the example below:

```yaml
---
resources:
  - type: "package"
    name: "httpd"
  - type: "template"
    name: "/var/www/html/index.html"
    source: "index.html.erb"
  - type: "service"
    name: "httpd"
    action:
      - enable
      - start
```

This implementation is restrictive and does not support arbitrary Ruby code, helper functions, or attributes. However, if the need for additional customization arises, YAML recipes can be automatically converted into the DSL via the `knife yaml convert` command.

### Custom Resource Improvements

#### Improved property require behavior

As noted in the breaking changes above, we improved how the required value is set on custom resource properties, in order to give a more predictable behavior. This new behavior now allows you to specify actions where individual properties are required. This is especially useful when `:create` actions require certain properties that may not be required for a `:remove` type property.

Example required field defining specific actions:

```ruby
property :password, String, required: [:create]

action :create do
  # code to create something
end

action :remove do
  # code to remove it that doesn't need a password
end
```

#### Resource Partials

Resource partials allow you to define reusable portions of code that can be included in multiple custom resources. This feature is particularly useful when there are common properties, such as authentication properties, that you want to define in a single location, but use for multiple resources. Internally in the Chef Infra Client codebase, we have already used this feature to remove duplicate properties from our `subversion` and `git` resources and make them easier to maintain.

Resource partials are stored in a cookbook's `/resources` directory just like existing custom resources, but they start with the `_` prefix. They're then called using a new `use` helper within the resource where they're needed:

`resources/_api_auth_properties.rb:`

```ruby
property :api_endpoint, String
property :api_key, String
property :api_retries, Integer
```

`resources/mything.rb`:

```ruby
property :another_property, String
property :yet_another_property, String

use 'api_auth_properties'

action :create do
  # some create logic
end
```

The example above shows a resource partial that contains properties for use in multiple resources. You can also use resource partials to define helper methods that you want to use in your actions instead of defining the same helper methods in each action_class.

`resources/_api_auth_helpers.rb:`

```ruby
def make_api_call(endpoint, value)
  # API call code here
end
```

`resources/mything.rb`:

```ruby
property :another_property, String
property :yet_another_property, String

action :create do
  # some create logic
end

action_class do
  use 'api_auth_helpers'
end
```

#### after_resource

A new `after_resource` state has been added to resources that allows you to better control the resource state information reported to Chef Automate when a resource converges. If your custom resource uses the `load_current_value` helper, then this after state is calculated automatically. If you don't utilize the `load_current_value` helper and would like fine grained control over the state information sent to Chef Automate, you can use a new `load_after_resource` helper to load the state of each property for reporting.

#### identity Improvements

A resource's name property is now set to be the identity property by default and to have `desired_state: false` set by default. This eliminates the need to set `identity: true, desired_state: false` on these properties and better exposes identity data to handler and reporting.

#### compile_time property

The `compile_time` property is now defined for all custom resources,  so there is no need to add your own compile-time logic to your resource.

### Other Improvements

#### Up to 33% smaller on disk

We optimized the files that ship with Chef Infra Client and eliminated many unnecessary files from the installation, reducing the on-disk size of Chef Infra Client by up to 33%.

#### Windows Performance Improvements

We've optimized the Chef Infra Client for modern Windows releases and improved the performance on these systems.

#### Simpler Version Comparisons with node['platform_version']

The `node['platform_version']` attribute returned from Ohai can now be intelligently compared as a version instead of as a String or Integer. Previously, to compare the platform_version, many users would first convert the version String to a Float with `node['platform_version']`. This introduced problems on many platforms, such as macOS, where macOS 10.9 would appear to be a greater version number than 10.15. You can now directly compare the version without converting it first.

Greater than or equal comparison:

```ruby
node['platform_version'] >= '10.15'
```

Comparison using Ruby's pessimistic operator:

```ruby
node['platform_version'] =~ '~> 10.15'
```

#### New helpers for recipes and resources

Several helpers introduced in Chef Infra Client 15.5 are now available for use in any resource or recipe. These helpers include:

`sanitized_path`

`sanitize_path` is a cross-platform method that returns the system's path along with the Chef Infra Client Ruby bin dir / gem bin dir and common system paths such as `/sbin` and `/usr/local/bin`.

`which(foo)`

The `which` helper searches the system's path and returns the first occurrence of a binary, similar to the `which` command on *nix systems. It also allows you to pass an `extra_path` value for additional directories to search.

```ruby
which('systemctl')
```

```ruby
which('my_app', extra_path: '/opt/my_app/bin')
```

#### eager_load_libraries metadata.rb setting

By default, Chef Infra Client eagerly loads all ruby files in each cookbook's libraries directory at runtime. A new metadata.rb option `eager_load_libraries` has been introduced and allows you to control if and when a cookbook library is loaded. Depending on the construction of your libraries, this new option may greatly improve the runtime performance of your cookbook. With eager loading disabled, you may manually load libraries included in your cookbook using Ruby's standard `require` method. Metadata.rb configuration options:

```ruby
eager_load_libraries false # disable eager loading all libraries
eager_load_libraries 'helper_library.rb' # eager load just the file helper_library.rb
eager_load_libraries %w(helper_library_1.rb helper_library_2.rb) # eager load both helper_library_1.rb and helper_library_2.rb files
```

Note: Unless you are experiencing performance issues in your libraries, we advise against changing the loading behavior.

#### always_dump_stacktrace client.rb option

A new `always_dump_stacktrace` client.rb configuration option and command line option allows you to have any Ruby stacktraces from Chef Infra Client logged directly to the log file. This may help troubleshooting when used in conjunction with centralized logging systems such as Splunk. To enable this new option, run `chef-client --always-dump-stacktrace` or add the following to your `client.rb`:

```ruby
always_dump_stacktrace true
```

#### Chef Vault Functionality Out of the Box

Chef Infra Client now ships with built-in Chef Vault functionality, so there's no need to depend on the `chef-vault` cookbook or gem. Chef Vault helpers `chef_vault_item`, `chef_vault`, and `chef_vault_item_for_environment` are included, as well as the `chef_vault_secret` resource. Additionally, the Chef Vault knife commands are also available out of the box. We do not recommend new users adopt the Chef Vault workflow due to limitations with autoscaling new systems, so these resources should only be consumed by existing Chef Vault users.

#### Ruby 2.7

Chef Infra Client's ruby installation has been updated to from Ruby 2.6 to Ruby 2.7, which includes many features available for use in resources and libraries.

See <https://medium.com/rubyinside/whats-new-in-ruby-2-7-79c98b265502> for details on many of the new features.

#### Ohai 16 Improvements

Ohai has been improved to gather additional system configuration information for use when authoring recipes and resources.

**filesystem2 Node Data available on Windows**

In previous Chef Infra Clients we've introduced a modernized filesystem layout of Ohai data for many platforms. In Chef Infra Client 16.0, Windows now has this layout available in `node['filesystem2']`. In Chef Infra Client 17, it will replace `node['filesystem']` to match all other platforms.

**Extended Azure Metadata**

The `Azure` Ohai plugin now gathers the latest version of the metadata provided by the Azure metadata endpoint. This greatly expands the information available on Azure instances. See [Ohai PR 1427](https://github.com/chef/ohai/pull/1427) for an example of the new data gathered.

**New Ohai Plugins**

New `IPC` and `Interupts` plugins have been added to Ohai. The IPC plugin exposes SysV IPC shmem information and interupts plugin exposes data from `/proc/interrupts` and `/proc/irq`. Thanks [@jsvana](https://github.com/jsvana) and [@davide125](https://github.com/davide125) for these new plugins.

Note: Both `IPC` and `Interupts` plugins are optional plugins, which are disabled by default. They can be enabled via your `client.rb`:

```ruby
ohai.optional_plugins = [
  :IPC,
  :Interupts
]
```

**Improved Linux Network Plugin Data**

The Linux Network plugin has been improved to gather additional information from the `ethtool` utility. This includes the number of queues (`ethtool -l`), the coalesce parameters (`ethtool -c`), and information about the NIC driver (`ethtool -i`). Thanks [@matt-c-clark](https://github.com/matt-c-clark) for these improvements.

**Windows DMI plugin**

Windows systems now include a new `DMI` plugin which presents data in a similar format to the `DMI` plugin on *nix systems. This makes it easier to detect system information like manufacturer, serial number, or asset tag number in a cross-platform way.

### New Platforms

Over the last quarter, we worked to greatly expand the platforms that we support with the addition of Chef Infra Client packages for Ubuntu 20.04 amd64, Amazon Linux 2 x86_64/aarch64, and Debian 10 amd64. With the release of Chef Infra Client 16, we expanded our platform support again with the following new platforms:

- RHEL 8 aarch64
- Ubuntu 20.04 aarch64
- SLES 16 aarch64

### Newly Introduced Deprecations

Several legacy Windows helpers have been deprecated as they will always return true when running on Chef Infra Client's currently supported platforms. The helpers previously detected systems prior to Windows 2012 and systems running Windows Nano, which has been discontinued by Microsoft. These helpers were never documented externally so their usage is most likely minimal. A new Cookstyle rule has been introduced to detect the usage of `older_than_win_2012_or_8?`: [ChefDeprecations/DeprecatedWindowsVersionCheck](https://github.com/chef/cookstyle/blob/master/docs/cops_chefdeprecations.md#chefdeprecationsdeprecatedwindowsversioncheck).

- Chef::Platform.supports_msi?
- Chef::Platform.older_than_win_2012_or_8?
- Chef::Platform.supports_powershell_execution_bypass?
- Chef::Platform.windows_nano_server?

## What's new in 15.17

### Chef InSpec 4.32

Updated Chef InSpec from 4.29.3 to 4.32.

#### New Features

- Commands can now be set to timeout using the [command resource](https://docs.chef.io/inspec/resources/command/) or the [`--command-timeout`](https://docs.chef.io/inspec/cli/) option in the CLI. Commands timeout by default after one hour.
- Added the [`--docker-url`](https://docs.chef.io/inspec/cli/) CLI option, which can be used to specify the URI to connect to the Docker Engine.
- Added support for targeting Linux and Windows containers running on Docker for Windows.
- Added ability to pass inputs to InSpec shell using input file and cli. For more information, see [How can I set Inputs?](https://docs.chef.io/inspec/inputs/#how-can-i-set-inputs) in the InSpec documentation.

#### Bug Fixes

- Hash inputs will now be loaded consistently and accessed as strings or symbols. ([#5446](https://github.com/inspec/inspec/pull/5446))

### Security

#### Ruby

We updated Ruby from 2.6.6 to 2.6.7 to resolve a large number of bugs as well as the following CVEs:

- [CVE-2021-28966](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28966)
- [CVE-2021-28965](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28965)
- [CVE-2020-25613](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25613)

## What's new in 15.16

### Fixes and Improvements

- Improved license acceptance failure messaging if incorrect values are provided.
- License acceptance values are no longer case sensitive.
- Resolved several failures that could occur in the `windows_certificate` resource.
- Improved handling of WinRM connections when bootstrapping Windows nodes.
- Switched docker containers back to EL6 packages to prevent failures running the containers with Kitchen Dokken to test RHEL 6 systems.
- Fixed non-0 exit codes in the Yum and DNF helper scripts which caused errors in system logs.
- Fixed package failures in FreeBSD due to changes in `pkgng` exit codes.
- Added support for `client.d` configuration files in `chef-shell`.

### Chef InSpec

Chef InSpec has been updated from 4.24.8 to 4.29.3.

#### New Features

- The JSON metadata pass-through configuration has been moved from the Automate reporter to the JSON Reporter.
- Added the option to filter out empty profiles from reports.
- Exposed the `conf_path`, `content`, and `params` properties to the `auditd_conf` resource.
- You can now directly refer to settings in the `nginx_conf` resource using the `its` syntax. Thanks [@rgeissert](https://github.com/rgeissert)!
- Plugin settings can now be set programmatically. Thanks [@tecracer-theinen](https:/github.com/tecracer-theinen)!
- OpenSSH Client on Windows can now be tested with the `ssh_config` and `sshd_config` resources. Thanks [@rgeissert](https://github.com/rgeissert)!

#### Bug Fixes

- The `--reporter-message-truncation` option now also truncates the `code_desc` field, preventing failures when sending large reports to Automate.
- Fixed `skip_control` to work on deeply nested profiles.
- The `ssh_config` and `sshd_config` resources now correctly use the first value when a setting is repeated.
- Fixed the `crontab` resource when passing a username to AIX.
- Stopped a backtrace from occurring when using `cmp` to compare `nil` with a non-existing file.
- The `apt` resource now correctly fetches all package repositories using the `-name` flag in an environment where ZSH is the user's default shell.
- The `--controls` option in `inspec exec` now correctly filters the controls by name.
- Updates how InSpec profiles are created with GCP or AWS providers so they use `inputs` instead of `attributes`.
- `inspec exec` will now fetch profiles via Git regardless of the name of the default branches now correctly use the first value when a setting is repeated.
- Updated the `oracledb_session` to use more general invocation options. Thanks [@pacopal](https://github.com/pacopal)!
- Fixed an error with the `http` resource in Chef Infra Client by including `faraday_middleware` in the gemspec.
- Fixed an incompatibility between `parslet` and `toml` in Chef Infra Client.
- Improved programmatic plugin configuration.

### Security

Upgraded OpenSSL to 1.0.2y, which resolves the following CVEs:

- [CVE-2021-23841](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23841)
- [CVE-2021-23839](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23839)
- [CVE-2021-23840](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23840)

### Platform Updates

With the release of macOS 11, we will no longer produce packages for macOS 10.13 systems. See our [Platform End-of-Life Policy](https://docs.chef.io/platforms/#platform-end-of-life-policy) for details on the platform lifecycle.

## What's new in 15.15

### Chef InSpec 4.24.8

Chef InSpec has been updated from 4.22.22 to 4.24.8 with the following improvements:

- An unset `HOME environment variable will not cause execution failures
- You can use wildcards in `platform-name` and `release` in InSpec profiles
- The support for arrays in the `WMI` resource, so it can return multiple objects
- The `package` resource on Windows properly escapes package names
- The `grub_conf` resource succeeds even if without a `menuentry` in the grub config
- Loaded plugins won't try to re-load themselves
- A new mechanism marks inputs as sensitive: true and replaces their values with `***`.
- Use the `--no-diff` CLI option to suppress diff output for textual tests.
- Control the order of controls in output, but not execution order, with the `--sort_results_by=none|control|file|random` CLI option.
- Disable caching of inputs with a cache_inputs: true setting.

### Chef Vault 4.1

We've updated the release of `chef-vault` bundled with Chef Infra Client to 4.1. Chef Vault 4.1 properly handles escape strings in secrets and greatly improves performance for users with large numbers of secrets. Thanks for the performance work [@Annih](https://github.com/Annih)!

### Resource Improvements

#### cron_d

The `cron_d` resource now respects the use of the `sensitive` property. Thanks for this fix [@axl89](https://github.com/axl89)!

#### homebrew_cask

The `homebrew_cask` resource has been updated to work with the latest command syntax requirements in the `brew` command. Thanks for reporting this issue [@bcg62](https://github.com/bcg62)!

#### locale

The allowed execution time for the `locale-gen` command in the `locale` resource has been extended to 1800 seconds to make sure the Chef Infra Client run doesn't fail before the command completes on slower systems. Thanks for reporting this issue [@janskarvall](https://github.com/janskarvall)!

#### plist / macosx_service / osx_profile / macos_userdefaults

Parsing of plist files has been improved in the `plist`, `macosx_service`, `osx_profile`, and `macos_userdefaults` resources thanks to updates to the plist gem by [@reitermarkus](https://github.com/reitermarkus) and [@tboyko](https://github.com/tboyko).

### Security

- The bundled Nokogiri Ruby gem has been updated to 1.11 resolve [CVE-2020-26247](https://nvd.nist.gov/vuln/detail/CVE-2020-26247).
- openSSL has been updated to 1.0.2x to resolve [CVE-2020-1971](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1971).

## What's New In 15.14

### Chef InSpec 4.22.22

Chef InSpec has been updated from 4.22.1 to 4.22.22. This new release includes the following improvements:

- Fix mysql_session stdout, stderr and exit_status parameters. Thanks [@ramereth](https://github.com/ramereth)!
- Add new windows_firewall and windows_firewall_rule resources. Thanks [@tecracer-theinen](https://github.com/tecracer-theinen)!

### Fixes and Improvements

- The `knife ssh` command no longer hangs when connecting to Windows nodes over SSH.
- Resolved several failures that could occur in the included chef-vault gem.

### Resource Updates

#### hostname

The `hostname` resource has been updated to improve logging on Windows systems.

#### windows_feature

The `windows_feature` resource has been updated to allow installing features that have been removed if a source location is provided. Thanks for reporting this [@stefanwb](https://github.com/stefanwb)!

#### windows_font

The `windows_font` resource will no longer fail on newer releases of Windows if a font is already installed. Thanks for reporting this [@bmiller08](https://github.com/bmiller08)!

### Platform Packages

- We are once again building Chef Infra Client packages for RHEL 7 / SLES 12 on the S390x architecture. In addition to these packages, we've also added S390x packages for SLES 15.
- We now produce packages for Apple's upcoming macOS 11 Big Sur release.

### Security

#### OpenSSL

OpenSSL has been updated to 1.0.2w which includes a fix for [CVE-2020-1968](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2020-1968).

#### CA Root Certificates

The included `cacerts` bundle in Chef Infra Client has been updated to the 7-22-2020 release. This new release removes 4 legacy root certificates and adds 4 additional root certificates.

## What's New In 15.13

### Chef InSpec 4.22.1

Chef InSpec has been updated from 4.20.6 to 4.22.1. This new release includes the following improvements:

- `apt-cdrom` repositories are now skipped when parsing out the list of apt repositories
- Faulty profiles are now reported instead of causing a crash
- Errors are no longer logged to stdout with the `html2` reporter
- macOS Big Sur is now correctly identified as macOS
- macOS/BSD support added to the interface resource along with new `ipv4_address`, `ipv4_addresses`, `ipv4_addresses_netmask`, `ipv4_cidrs`, `ipv6_addresses`, and `ipv6_cidrs` properties

### Fixes and Improvements

- Support for legacy DSA host keys has been restored in `knife ssh` and `knife bootstrap` commands.
- The collision warning error message when a cookbook includes a resource that now ships in Chef Infra Client has been improved to better explain the issue.
- Package sizes have been reduced with fewer installed files on disk.
- The `archive_file` resource now supports `pzstd` compressed files.

### New Deprecations

Chef Infra Client 16.2 and later require `provides` when assigning a name to a custom resource. In order to prepare for Chef Infra Client 16, make sure to include both `resource_name` and `provides` in resources when specifying a custom name.

## What's New In 15.12

### Chef InSpec 4.20.6

Chef InSpec has been updated from 4.18.114 to 4.2.0.6. This new release includes the following improvements:

- Develop your own Chef InSpec Reporter plugins to control how Chef InSpec will report result data.
- The `inspec archive` command packs your profile into a `tar.gz` file that includes the profile in JSON form as the inspec.json file.
- Certain substrings within a `.toml` file no longer cause unexpected crashes.
- Accurate InSpec CLI input parsing for numeric values and structured data, which were previously treated as strings. Numeric values are cast to an `integer` or `float` and `YAML` or `JSON` structures are converted to a hash or an array.
- Suppress deprecation warnings on `inspec exec` with the `--silence-deprecations` option.

### Resource Updates

#### archive_file

The `archive_file` resource has been updated with two important fixes. The resource will no longer fail with uninitialized constant errors under some scenarios. Additionally, the behavior of the `mode` property has been improved to prevent incorrect file modes from being applied to the decompressed files. Due to how file modes and Integer values are processed in Ruby, this resource will now produce a deprecation warning if integer values are passed. Using string values lets us accurately pass values such as '644' or '0644' without ambiguity as to the user's intent. Thanks for reporting these issues [@sfiggins](http://github.com/sfiggins) and [@hammerhead](http://github.com/hammerhead).

#### cron_access

The `cron_access` resource has been updated to support Solaris and AIX systems. Thanks [@aklyachkin](http://github.com/aklyachkin).

#### msu_package resource improvements

The `msu_package` resource has been improved to work better with Microsoft's cumulative update packages. Newer releases of these cumulative update packages will not correctly install over the previous versions. We also extended the default timeout for installing MSU packages to 60 minutes. Thanks for reporting the timeout issue [@danielfloyd](https://github.com/danielfloyd).

#### powershell_package

The `powershell_package` resource has been updated to use TLS 1.2 when communicating with the PowerShell Gallery on Windows Server 2012-2016. Previously, this resource used the system default cipher suite which did not include TLS 1.2. The PowerShell Gallery now requires TLS 1.2 for all communication, which caused failures on Windows Server 2012-2016. Thanks for reporting this issue [@Xorima](http://github.com/Xorima).

#### snap_package

Multiple issues with the `snap_package` resource have been resolved, including an infinite wait that occurred and issues with specifying the package version or channel. Thanks [@jaymzh](http://github.com/jaymzh).

#### zypper_repository

The `zypper_repository` resource has been updated to work with the newer release of GPG in openSUSE 15 and SLES 15. This prevents failures when importing GPG keys in the resource.

### Knife bootstrap updates

- Knife bootstrap will now warn when bootstrapping a system using a validation key. Users should instead use `validatorless bootstrapping` with `knife bootstrap` which generates node and client keys using the client key of the user bootstrapping the node. This method is far more secure as an org-wide validation key does not not need to be distributed or rotated. Users can switch to `validatorless bootstrapping` by removing any `validation_key` entries in their `config.rb (knife.rb)` file.
- Resolved an error bootstrapping Linux nodes from Windows hosts
- Improved information messages during the bootstrap process

### SSH Improvements

The `net-ssh` library used by the `knife ssh` and `knife bootstrap` commands has been updated bringing improvements to SSH connectivity:

- Support for additional key exchange and transport algorithms
- Support algorithm subtraction syntax in the `ssh_config` file
- Support empty lines and comments in `known_hosts` file

### Initial macOS Big Sur Support

Chef Infra Client now correctly detects macOS Big Sur (11.0) beta as being platform "mac_os_x". Chef Infra Client 15.12 has not been fully qualified for macOS Big Sur, but we will continue to validate against this release and provide any additional support updates.

### Platform Packages

- Debian 8 packages are no longer being produced as Debian 8 is now end-of-life.
- We now produce Windows 8 packages

## What's New In 15.11

### Bootstrapping Bugfixes

This release of Chef Infra Client resolves multiple issues when using `knife bootstrap` to bootstrap new nodes to a Chef Infra Server:

- Bootstrapping from a Windows host to a Linux host with an ED25519 ssh key no longer fails
- Resolved failures in the Windows bootstrap script
- Incorrect paths when bootstrapping Windows nodes have been resolved

### Chef InSpec 4.18.114

Chef InSpec was updated from 4.18.104 to 4.18.114 with the following improvements:

- Added new `--reporter_message_truncation` and `--reporter_backtrace_inclusion` reporter options to truncate messages and suppress backtraces.
- Fixed a warning when an input is provided
- Inputs and controls can now have the same name

### Resource Improvements

#### windows_firewall

The `windows_firewall` resource has been updated to support firewall rules that are associated with more than one profile. Thanks [@tecracer-theinen](https://github.com/tecracer-theinen).

#### chocolatey_package

The `chocolatey_package` resource has been updated to properly handle quotes within the `options` property. Thanks for reporting this issue [@dave-q](https://github.com/dave-q).

### Platform Support

#### Additional aarch64 Builds

Chef Infra Client is now tested on Debian 10, SLES 15, and Ubuntu 20.04 on the aarch64 architecture with packages available on the [Chef Downloads Page](https://downloads.chef.io/chef).

### Security Updates

#### openSSL

openSSL has been updated from 1.0.2u to 1.0.2v which does not address any particular CVEs, but includes multiple security hardening updates.

## What's New in 15.10

### Improvements

- The `systemd_unit` resource now respects the `sensitive` property and will no longer output the contents of the unit file to logs if this is set.
- A new `arm?` helper has been added which can be used in recipes and resources to determine if a system is on the ARM architecture.

### Bug Fixes

- Resolved a bug that prevented users from bootstrapping nodes using knife when specifying the `--use_sudo_password`.
- Resolved a bug that prevented the `--bootstrap-version` flag from being honored when bootstrapping in knife.

### Chef InSpec 4.18.104

- Resolved a regression that prevented the `service` resource from working correctly on Windows. Thanks [@Axuba](https://github.com/Axuba)
- Implemented VMware and Hyper-V detection on Linux systems
- Implemented VMware, Hyper-V, Virtualbox, KVM and Xen detection on Windows systems
- Added helpers `virtual_system?` and `physical_system?`. Thanks [@tecracer-theinen](https://github.com/tecracer-theinen)

### Ohai 15.9

- Improve the resiliency of the `Shard` plugin when `dmidecode` cannot be found on a system. Thanks [@jaymzh](https://github.com/jaymzh)
- Fixed detection of Openstack guests via DMI data. Thanks [@ramereth](https://github.com/ramereth)

### Platform Support

#### Amazon Linux 2

Chef Infra Client is now tested on Amazon Linux 2 running on x86_64 and aarch64 with packages available on the [Chef Downloads Page](https://downloads.chef.io/chef).

## What's New in 15.9

### Chef InSpec 4.18.100

Chef InSpec has been updated from 4.18.85 to 4.18.100:

- Resolved several failures in executing resources
- Fixed `auditd` resource processing of action and list
- Fixed platform detection when running in Habitat
- "inspec schema" has been revised to be in the JSON Schema draft 7 format
- Improved the functionality of the `oracledb_session` resource

### Ohai 15.8

Ohai has been updated to 15.8.0 which includes a fix for failures that occurred in the OpenStack plugin (thanks [@sawanoboly](https://github.com/sawanoboly/)) and improved parsing of data in the `optional_plugins` config option (thanks [@salzig](https://github.com/salzig/)).

### Resource Improvements

#### build_essential

The `build_essential` resource has been updated to better detect if the Xcode CLI Tools package needs to be installed on macOS. macOS 10.15 (Catalina) is now supported with this update. Thank you [@w0de](https://github.com/w0de/) for kicking this work off, [@jazaval](https://github.com/jazaval/) for advice on macOS package parsing, and Microsoft for their work in the macOS cookbook.

#### rhsm_errata / rhsm_errata_level

The `rhsm_errata` and `rhsm_errata_level` resources have been updated to properly function on RHEL 8 systems.

#### rhsm_register

The `rhsm_register` resource has a new property `https_for_ca_consumer` that enables using https connections during registration. Thanks for this improvement [@jasonwbarnett](https://github.com/jasonwbarnett/). This resource has also been updated to properly function on RHEL 8.

#### windows_share

Resolved failures in the `windows_share` resource when setting the `path` property. Thanks for reporting this issue [@Kundan22](https://github.com/Kundan22/).

### Platform Support

#### Ubuntu 20.04

Chef Infra Client is now tested on Ubuntu 20.04 (AMD64) with packages available on the [Chef Downloads Page](https://downloads.chef.io/chef).

#### Ubuntu 18.04 aarch64

Chef Infra Client is now tested on Ubuntu 18.04 aarch64 with packages available on the [Chef Downloads Page](https://downloads.chef.io/chef).

#### Windows 10

Our Windows 10 Chef Infra Client packages now receive an additional layer of testing to ensure they function as expected.

### Security Updates

#### Ruby

Ruby has been updated from 2.6.5 to 2.6.6 to resolve the following CVEs:

  - [CVE-2020-16255](https://www.ruby-lang.org/en/news/2020/03/19/json-dos-cve-2020-10663/): Unsafe Object Creation Vulnerability in JSON (Additional fix)
  - [CVE-2020-10933](https://www.ruby-lang.org/en/news/2020/03/31/heap-exposure-in-socket-cve-2020-10933/): Heap exposure vulnerability in the socket library

#### libarchive

libarchive has been updated from 3.4.0 to 3.4.2 to resolve multiple security vulnerabilities including the following CVEs:

  - [CVE-2019-19221](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19221): archive_wstring_append_from_mbs in archive_string.c has an out-of-bounds read because of an incorrect mbrtowc or mbtowc call
  - [CVE-2020-9308](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9308): archive_read_support_format_rar5.c in libarchive before 3.4.2 attempts to unpack a RAR5 file with an invalid or corrupted header

## What's New in 15.8

### New notify_group functionality

Chef Infra Client now includes a new `notify_group` feature that can be used to extract multiple common notifies out of individual resources to reduce duplicate code in your cookbooks and custom resources. Previously cookbook authors would often use a `log` resource to achieve a similar outcome, but using the log resource results in unnecessary Chef Infra Client log output. The `notify_group` method produces no additional logging, but fires all defined notifications when the `:run` action is set.

Example notify_group that stops, sleeps, and then starts service when a service config is updated:

```ruby
service "crude" do
  action [ :enable, :start ]
end

chef_sleep "60" do
  action :nothing
end

notify_group "crude_stop_and_start" do
  notifies :stop, "service[crude]", :immediately
  notifies :sleep, "chef_sleep[60]", :immediately
  notifies :start, "service[crude]", :immediately
end

template "/etc/crude/crude.conf" do
  source "crude.conf.erb"
  variables node["crude"]
  notifies :run, "notify_group[crude_stop_and_start]", :immediately
end
```

### Chef InSpec 4.18.85

Chef InSpec has been updated from 4.18.39 to 4.18.85. This release includes a large number of bug fixes in addition to some great resource enhancements:

- The service resource features new support for yocto-based linux distributions. Thank you to [@michaellihs](https://github.com/michaellihs) for this addition!
- The package resource now includes support for FreeBSD. Thank you to [@fzipi](https://github.com/fzipi) for this work!
- We standardized the platform for the etc_hosts, virtualization, ini, and xml resources.
- The oracledb_session resource works again due to a missing quote fix.
- The groups resource on macOS no longer reports duplicates anymore.
command.exist? now conforms to POSIX standards. Thanks to [@PiQuer](https://github.com/PiQuer)!
- Changed the postfix_conf resource's supported platform to the broader unix. Thank you to [@fzipi](https://github.com/fzipi) for this fix!

### New Cookbook Helpers

New helpers have been added to make writing cookbooks easier.

#### Platform Version Helpers

New helpers for checking platform versions have been added. These helpers return parsed version strings so there's no need to convert the returned values to Integers or Floats before comparing them. Additionally, comparisons with version objects properly understand the order of versions so `5.11` will compare as larger than `5.9`, whereas converting those values to Floats would result in `5.9` being larger than `5.11`.

- `windows_nt_version` returns the NT kernel version which often differs from Microsoft's marketing versions. This helper offers a good way to find desktop and server releases that are based on the same codebase. For example, NT 6.3 is both Windows 8.1 and Windows 2012 R2.
- `powershell_version` returns the version of PowerShell installed on the system.
- `platform_version` returns the value of node['platform_version'].

Example comparison using windows_nt_version:

```ruby
if windows_nt_version >= 10
  some_modern_windows_things
end
```

#### Cloud Helpers

The cloud helpers from chef-sugar have been ported to Chef Infra Client:

- `cloud?` - if the node is running in any cloud, including internal clouds
- `ec2?` - if the node is running in ec2
- `gce?` - if the node is running in gce
- `rackspace?` - if the node is running in rackspace
- `eucalyptus?` - if the node is running under eucalyptus
- `linode?` - if the node is running in linode
- `openstack?` - if the node is running under openstack
- `azure?` - if the node is running in azure
- `digital_ocean?` - if the node is running in digital ocean
- `softlayer?` - if the node is running in softlayer

#### Virtualization Helpers

The virtualization helpers from chef-sugar have been ported to Chef Infra Client and extended with helpers to detect hypervisor hosts, physical, and guest systems.

- `kvm?` - if the node is a kvm guest
- `kvm_host?` - if the node is a kvm host
- `lxc?` - if the node is an lxc guest
- `lxc_host?` - if the node is an lxc host
- `parallels?`- if the node is a parallels guest
- `parallels_host?`- if the node is a parallels host
- `vbox?` - if the node is a virtualbox guest
- `vbox_host?` - if the node is a virtualbox host
- `vmware?` - if the node is a vmware guest
- `vmware_host?` - if the node is a vmware host
- `openvz?` - if the node is an openvz guest
- `openvz_host?` - if the node is an openvz host
- `guest?` - if the node is detected as any kind of guest
- `hypervisor?` - if the node is detected as being any kind of hypervisor
- `physical?` - the node is not running as a guest (may be a hypervisor or may be bare-metal)
- `vagrant?` - attempts to identify the node as a vagrant guest (this check may be error-prone)

#### include_recipe? helper

chef-sugar's `include_recipe?` has been added to Chef Infra Client providing a simple way to see if a recipe has been included on a node already.

Example usage in a not_if conditional:

```ruby
execute 'install my_app'
  command '/tmp/my_app_install.sh'
  not_if { include_recipe?('my_app::install') }
end
```

### Updated Resources

#### ifconfig

The `ifconfig` resource now supports the newer `ifconfig` release that ships in Debian 10.

#### mac_user

The `mac_user` resource, used when creating a user on Mac systems, has been improved to work better with macOS Catalina (10.15). The resource now properly looks up the numeric GID when creating a user, once again supports the `system` property, and includes a new `hidden` property which prevents the user from showing on the login screen. Thanks [@chilcote](https://github.com/chilcote) for these fixes and improvements.

#### sysctl

The `sysctl` resource has been updated to allow the inclusion of descriptive comments. Comments may be passed as an array or as a string. Any comments provided are prefixed with '#' signs and precede the `sysctl` setting in generated files.

An example:

```ruby
sysctl 'vm.swappiness' do
  value 10
  comment [
     "define how aggressively the kernel will swap memory pages.",
     "Higher values will increase aggressiveness",
     "lower values decrease the amount of swap.",
     "A value of 0 instructs the kernel not to initiate swap",
     "until the amount of free and file-backed pages is less",
     "than the high water mark in a zone.",
     "The default value is 60."
    ]
end
```

which results in `/etc/sysctl.d/99-chef-vm.swappiness.conf` as follows:

```
# define how aggressively the kernel will swap memory pages.
# Higher values will increase aggressiveness
# lower values decrease the amount of swap.
# A value of 0 instructs the kernel not to initiate swap
# until the amount of free and file-backed pages is less
# than the high water mark in a zone.
# The default value is 60.
vm.swappiness = 10
```

### Platform Support

- Chef Infra Clients packages are now validated for Debian 10.

### macOS Binary Signing

Each binary in the macOS Chef Infra Client installation is now signed to improve the integrity of the installation and ensure compatibility with macOS Catalina security requirements.

## What's New in 15.7

### Updated Resources

#### archive_file

The `archive_file` resource will now only change ownership on files and directories that were part of the archive itself. This prevents changing permissions on important high level directories such as /etc or /bin when you extract a file into those directories. Thanks for this fix, [@bobchaos](https://github.com/bobchaos/).

#### cron and cron_d

The `cron` and `cron_d` resources now include a `timeout` property, which allows you to configure actions to perform when a job times out. This property accepts a hash of timeout configuration options:

- `preserve-status`: `true`/`false` with a default of `false`
- `foreground`: `true`/`false` with a default of `false`
- `kill-after`: `Integer` for the timeout in seconds
- `signal`: `String` or `Integer` to send to the process such as `HUP`

#### launchd

The `launchd` resource has been updated to properly capitalize `HardResourceLimits`. Thanks for this fix, [@rb2k](https://github.com/rb2k/).

#### sudo

The `sudo` resource no longer fails on the second Chef Infra Client run when using a `Cmnd_Alias`. Thanks for reporting this issue, [@Rudikza](https://github.com/Rudikza).

#### user

The `user` resource on AIX no longer forces the user to change the password after Chef Infra Client modifies the password. Thanks for this fix, [@Triodes](https://github.com/Triodes).

The `user` resource on macOS 10.15 has received several important fixes to improve logging and prevent failures.

#### windows_task

The `windows_task` resource is now idempotent when a system is joined to a domain and the job runs under a local user account.

#### x509_certificate

The `x509_certificate` resource now includes a new `renew_before_expiry` property that allows you to auto renew certificates a specified number of days before they expire. Thanks [@julienhuon](https://github.com/julienhuon/) for this improvement.

### Additional Recipe Helpers

We have added new helpers for identifying Windows releases that can be used in any part of your cookbooks.

#### windows_workstation?

Returns `true` if the system is a Windows Workstation edition.

#### windows_server?

Returns `true` if the system is a Windows Server edition.

#### windows_server_core?

Returns `true` if the system is a Windows Server Core edition.

### Notable Changes and Fixes

- `knife upload` and `knife cookbook upload` will now generate a metadata.json file from metadata.rb when uploading a cookbook to the Chef Infra Server.
- A bug in `knife bootstrap` behavior that caused failures when bootstrapping Windows hosts from non-Windows hosts and vice versa has been resolved.
- The existing system path is now preserved when bootstrapping Windows nodes. Thanks for this fix, [@Xorima](https://github.com/Xorima/).
- Ohai now properly returns the drive name on Windows and includes new drive_type fields to allow you to determine the type of attached disk. Thanks for this improvement [@sshock](https://github.com/sshock/).
- Ohai has been updated to properly return DMI data to Chef Infra Client. Thanks for troubleshooting this, [@zmscwx](https://github.com/zmscwx) and [@Sliim](https://github.com/Sliim).

### Platform Support

- Chef Infra Clients packages are no longer produced for Windows 2008 R2 as this release reached its end of life on Jan 14th, 2020.
- Chef Infra Client packages are no longer produced for RHEL 6 on the s390x platform. Builds will continue to be published for RHEL 7 on the s390x platform.

### Security Updates

#### OpenSSL

OpenSSL has been updated to 1.0.2u to resolve [CVE-2019-1551](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1551)

## What's New in 15.6

### Updated Resources

### apt_repository

The `apt_repository` resource now properly escapes repository URIs instead of quoting them. This prevents failures when using the `apt-file` command, which was unable to parse the quoted URIs. Thanks for reporting this [@Seb-Solon](https://github.com/Seb-Solon)

### file

The `file` resource now shows the output of any failures when running commands specified in the `verify` property. This means you can more easily validate config files before potentially writing an incorrect file to disk. Chef Infra Client will shellout to any specified command and will show the results of failures for further troubleshooting.

### user

The `user` resource on Linux systems now continues successfully when `usermod` returns an exit code of 12. Exit code 12 occurs when a user's home directory is changed and the underlying directory already exists. Thanks [@skippyj](https://github.com/skippyj) for this fix.

### yum_repository

The `yum_repository` now properly formats the repository configuration when multiple `baseurl` values are present. Thanks [@bugok](https://github.com/bugok) for this fix.

### Performance Improvements

This release of Chef Infra Client ships with several optimizations to our Ruby installation to improve the performance of loading the chef-client and knife commands. These improvements are particularly noticeable on non-SSD hosts and on Windows.

### Smaller Install Footprint

We've further optimized our install footprint and reduced the size of `/opt/chef` by ~7% by removing unnecessary test files and libraries that shipped in previous releases.

### filesystem2 Ohai Data on Windows

Ohai 15.6 includes new `node['filesystem2']` data on Windows hosts. Filesystem2 presents filesystem data by both mountpoint and by device name. This data structure matches that of the filesystem plugin on Linux and other *nix operating systems. Thanks [@jaymzh](https://github.com/jaymzh) for this new data structure.

## What's New in 15.5.15

The Chef Infra Client 15.5.15 release includes fixes for two regressions. A regression in the `build_essential` resource caused failures on `rhel` platforms and a second regression caused Chef Infra Client to fail when starting with `enforce_path_sanity` enabled. As part of this fix we've added a new property, `raise_if_unsupported`, to the `build-essential` resource. Instead of silently continuing, this property will fail a Chef Infra Client run if an unknown platform is encountered.

We've also updated the `windows_package` resource. The resource will now provide better error messages if invalid options are passed to the `installer_type` property and the `checksum` property will now accept uppercase SHA256 checksums.

## What's New in 15.5.9

### New Cookbook Helpers

Chef Infra Client now includes a new `chef-utils` gem, which ships with a large number of helpers to make writing cookbooks easier. Many of these helpers existed previously in the `chef-sugar` gem. We have renamed many of the named helpers for consistency, while providing backwards compatibility with existing `chef-sugar` names. Existing cookbooks written with `chef-sugar` should work unmodified with any of these new helpers. Expect a Cookstyle rule in the near future to help you update existing `chef-sugar` code to use the newer built-in helpers.

For more information all all of the new helpers available, see the [chef-utils readme](https://github.com/chef/chef/blob/master/chef-utils/README.md)

### Chefignore Improvements

We've reworked how chefignore files are handled in `knife`, which has allowed us to close out a large number of long outstanding bugs. `knife` will now traverse all the way up the directory structure looking for a chefignore file. This means you can place a chefignore file in each cookbook or any parent directory in your repository structure. Additionally, we have made fixes that ensure that commands like `knife diff` and `knife cookbook upload` always honor your chefignore files.

### Windows Habitat Plan

Official Habitat packages of Chef Infra Client are now available for Windows. It has all the executables of the traditional omnibus packages, but in Habitat form. You can find it in the Habitat Builder under [chef/chef-infra-client](https://bldr.habitat.sh/#/pkgs/chef/chef-infra-client/latest/windows).

### Performance Improvements

This release of Chef Infra Client ships with several optimizations to our Ruby installation that improve the performance of the chef-client and knife commands, especially on Windows systems. Expect to see more here in future releases.

### Chef InSpec 4.18.39

Chef InSpec has been updated from 4.17.17 to 4.18.38. This release includes a large number of bug fixes in addition to some great resource enhancements:

- Inputs can now be used within a `describe.one` block
- The `service` resource now includes a `startname` property for Windows and systemd services
- The `interface` resource now includes a `name` property
- The `user` resource now better supports Windows with the addition of `passwordage`, `maxbadpasswords`, and `badpasswordattempts` properties
- The `nginx` resource now includes parsing support for wildcard, dot prefix, and regex
- The `iis_app_pool` resource now handles empty app pools
- The `filesystem` resource now supports devices with very long names
- The `apt` better handles URIs and supports repos with an `arch`
- The `oracledb_session` has received multiple fixes to make it work better
- The `npm` resource now works under sudo on Unix and on Windows with a custom PATH

### New Resources

#### chef_sleep

The `chef_sleep` resource can be used to sleep for a specified number of seconds during a Chef Infra Client run. This may be helpful to use with other commands that return a completed status before they are actually ready. In general, do not use this resource unless you truly need it.

Using with a Windows service that starts, but is not immediately ready:

```ruby
service 'Service that is slow to start and reports as started' do
  service_name 'my_database'
  action :start
  notifies :sleep, chef_sleep['wait for service start']
end

chef_sleep 'wait for service start' do
  seconds 30
  action :nothing
end
```

### Updated Resources

### systemd_unit / service

The `systemd_unit` and `service` resources (when on systemd) have been updated to not re-enable services with an indirect status. Thanks [@jaymzh](https://github.com/jaymzh) for this fix.

### windows_firewall

The `windows_firewall` resource has been updated to support passing in an array of profiles in the `profile` property. Thanks [@Happycoil](https://github.com/Happycoil) for this improvement.

### Security Updates

#### libxslt

libxslt has been updated to 1.1.34 to resolve [CVE-2019-13118](https://nvd.nist.gov/vuln/detail/CVE-2019-13118).

## What's New in 15.4

### converge_if_changed Improvements

Chef Infra Client will now take into account any `default` values specified in custom resources when making converge determinations with the `converge_if_changed` helper. Previously, default values would be ignored, which caused necessary changes to be skipped. Note: This change may cause behavior changes for some users, but we believe this original behavior is an impacting bug for enough users to make it outside of a major release. Thanks [@ jakauppila](https://github.com/jakauppila) for reporting this.

### Bootstrap Improvements

Several improvements have been made to the `knife bootstrap` command to make it more reliable and secure:

- File creation is now wrapped in a umask to avoid potential race conditions
- `NameError` and `RuntimeError` failures during bootstrap have been resolved
- `Undefined method 'empty?' for nil:NilClass` during bootstrap have been resolved
- Single quotes in attributes during bootstrap no longer result in bootstrap failures
- The bootstrap command no longer appears in PS on the host while bootstrapping is running

### knife supermarket list Improvements

The `knife supermarket list` command now includes two new options:

- `--sort-by [recently_updated recently_added most_downloaded most_followed]`: Sort cookbooks returned from the Supermarket API
- `--owned_by`: Limit returned cookbooks to a particular owner

### Updated Resources

#### chocolatey_package

The `chocolatey_package` resource no longer fails when passing options with the `options` property. Thanks for reporting this issue [@kenmacleod](https://github.com/kenmacleod).

#### kernel_module

The `kernel_module` resource includes a new `options` property, which allows users to set module specific parameters and settings. Thanks [@ramereth](https://github.com/ramereth) for this new feature.

Example of a kernel_module resource using the new options property:

```ruby
  kernel_module 'loop' do
  options [ 'max_loop=4', 'max_part=8' ]
  end
```

#### remote_file

The `remote_file` resource has been updated to better display progress when using the `show_progress` resource. Thanks for reporting this issue [@isuftin](https://github.com/isuftin).

#### sudo

The `sudo` resource now runs sudo config validation against all of the sudo configuration files on the system instead of only the file being written. This allows us to detect configuration errors that occur when configs conflict with each other. Thanks for reporting this issue [@drzewiec](https://github.com/drzewiec).

#### windows_ad_join

The `windows_ad_join` has a new `:leave` action for leaving an Active Directory domain and rejoining a workgroup. This new action also has a new `workgroup_name` property for specifying the workgroup to join upon leaving the domain. Thanks [@jasonwbarnett](https://github.com/jasonwbarnett) for adding this new action.

Example of leaving a domain

```ruby
windows_ad_join 'Leave the domain' do
  workgroup_name 'local'
  action :leave
end
```

#### windows_package

The `windows_package` resource no longer updates environmental variables before installing the package. This prevents potential modifications that may cause a package installation to fail. Thanks [@jeremyhage](https://github.com/jeremyhage) for this fix.

#### windows_service

The `windows_service` resource no longer updates the service and triggers notifications if the case of the `run_as_user` property does not match the user set on the service. Thanks [@jasonwbarnett](https://github.com/jasonwbarnett) for this fix.

#### windows_share

The `windows_share` resource is now fully idempotent by better validating the provided `path` property from the user. Thanks [@Happycoil](https://github.com/Happycoil) for this fix.

### Security Updates

#### Ruby

Ruby has been updated from 2.6.4 to 2.6.5 in order to resolve the following CVEs:

- [CVE-2019-16255](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16255): A code injection vulnerability of Shell#[] and Shell#test
- [CVE-2019-16254](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16254): HTTP response splitting in WEBrick (Additional fix)
- [CVE-2019-15845](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-15845): A NUL injection vulnerability of File.fnmatch and File.fnmatch?
- [CVE-2019-16201](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16201): Regular Expression Denial of Service vulnerability of WEBrick's Digest access authentication

## What's New in 15.3

### Custom Resource Unified Mode

Chef Infra Client 15.3 introduces an exciting new way to easily write custom resources that mix built-in Chef Infra resources with Ruby code. Previously custom resources would use Chef Infra's standard compile and converge phases, which meant that Ruby would be evaluated first and then the resources would be converged. This often results in confusing and undesirable behavior when you are trying to mix resources with Ruby logic. Many custom resource authors would attempt to get around this by forcing resources to run at compile time so that all the code in their resource would execute during the compile phase.

An example of forcing a resource to run at compile time:

```ruby
resource_name 'foo' do
  action :nothing
end.run_action(:some_action)
```

With unified mode, you opt in to a single phase per resource where all Ruby and Chef Infra resources are executed at once. This makes it far easier to determine how your code will be evaluated and run. Additionally, you no longer need to force any resources to run at compile time, as all code is run in the compile phase. To enable this new mode just add `unified_mode true` to your resources like this:

```ruby
property :Some_property, String

unified_mode true

action :create do
  # some code
end
```

### Interval Mode Now Fails on Windows

Chef Infra Client 15.3 will now raise an error if you attempt to keep the chef-client process running long-term by enabling interval runs. Interval runs have already raised failures on non-Windows platforms and we've suggested that users move away from them on Windows for many years. The long-running chef-client process on Windows will load and reload cookbooks over each other in memory. This could produce a running state which is not a representation of the cookbook code that the authors wrote or tested, and behavior that may be wildly different depending on how long the chef-client process has been running and on the sequence that the cookbooks were uploaded.

### Updated Resources

#### ifconfig

The `ifconfig` resource has been updated to properly support interfaces with a hyphen in their name. This is most commonly encountered with bridge interfaces that are named `br-1234`.

#### archive_file

The `archive_file` resource now supports archives in the RAR 5.0 format as well as zip files compressed using xz, lzma, ppmd8 and bzip2 compression.

#### user

**macOS 10.14 / 10.15 support**

The `user` resource now supports the creation of users on macOS 10.14 and 10.15 systems. The updated resource now complies with macOS TCC policies by using a user with admin privileges to create and modify users. The following new properties have been added for macOS user creation:

- `admin` sets a user to be an admin.

- `admin_username` and `admin_password` define the admin user credentials required for toggling SecureToken for a user. The value of 'admin_username' must correspond to a system user that is part of the 'admin' with SecureToken enabled in order to toggle SecureToken.

- `secure_token` is a boolean property that sets the desired state for SecureToken. FileVault requires a SecureToken for full disk encryption.

- `secure_token_password` is the plaintext password required to enable or disable `secure_token` for a user. If no salt is specified we assume the 'password' property corresponds to a plaintext password and will attempt to use it in place of secure_token_password if it is not set.

**Password property is now sensitive**

The `password` property is now set to sensitive to prevent the password from being shown in debug or failure logs.

**gid property can now be a string**

The `gid` property now allows specifying the user's gid as a string. For example:

```ruby
user 'tim' do
  gid '123'
end
```

### Platform Support Updates

#### macOS 10.15 Support

Chef Infra Client is now validated against macOS 10.15 (Catalina) with packages now available at [downloads.chef.io](https://downloads.chef.io/) and via the [Omnitruck API](https://docs.chef.io/api_omnitruck/). Additionally, Chef Infra Client will no longer be validated against macOS 10.12.

#### AIX 7.2

Chef Infra Client is now validated against AIX 7.2 with packages now available at [downloads.chef.io](https://downloads.chef.io/) and via the [Omnitruck API](https://docs.chef.io/api_omnitruck/).

### Chef InSpec 4.16

Chef InSpec has been updated from 4.10.4 to 4.16.0 with the following changes:

- A new `postfix_conf` has been added for inspecting Postfix configuration files.
- A new `plugins` section has been added to the InSpec configuration file which can be used to pass secrets or other configurations into Chef InSpec plugins.
- The `service` resource now includes a new `startname` property for determining which user is starting the Windows services.
- The `groups` resource now properly gathers membership information on macOS hosts.

### Security Updates

#### Ruby

Ruby has been updated from 2.6.3 to 2.6.4 in order to resolve [CVE-2012-6708](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-6708) and [CVE-2015-9251](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9251).

#### openssl

openssl has been updated from 1.0.2s to 1.0.2t in order to resolve [CVE-2019-1563](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1563) and [CVE-2019-1547](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1547).

#### nokogiri

nokogiri has been updated from 1.10.2 to 1.10.4 in order to resolve [CVE-2019-5477](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5477)

## What's New in 15.2

### Updated Resources

#### dnf_package

The `dnf_package` resource has been updated to fully support RHEL 8.

#### kernel_module

The `kernel_module` now supports a `:disable` action. Thanks [@tomdoherty](https://github.com/tomdoherty).

#### rhsm_repo

The `rhsm_repo` resource has been updated to support passing a repo name of `*` in the `:disable` action. Thanks for reporting this issue [@erinn](https://github.com/erinn).

#### windows_task

The `windows_task` resource has been updated to allow the `day` property to accept an `Integer` value.

#### zypper_package

The `zypper_package` package has been updated to properly upgrade packages if necessary based on the version specified in the resource block. Thanks [@foobarbam](https://github.com/foobarbam) for this fix.

### Platform Support Updates

#### RHEL 8 Support Added

Chef Infra Client 15.2 now includes native packages for RHEL 8 with all builds now validated on RHEL 8 hosts.

#### SLES 11 EOL

Packages will no longer be built for SUSE Linux Enterprise Server (SLES) 11 as SLES 11 exited the 'General Support' phase on March 31, 2019. See Chef's [Platform End-of-Life Policy](https://docs.chef.io/platforms/#platform-end-of-life-policy) for more information on when Chef ends support for an OS release.

#### Ubuntu 14.04 EOL

Packages will no longer be built for Ubuntu 14.04 as Canonical ended maintenance updates on April 30, 2019. See Chef's [Platform End-of-Life Policy](https://docs.chef.io/platforms/#platform-end-of-life-policy) for more information on when Chef ends support for an OS release.

### Ohai 15.2

Ohai has been updated to 15.2 with the following changes:

- Improved detection of Openstack including proper detection of Windows nodes running on Openstack when fetching metadata. Thanks [@jjustice6](https://github.com/jjustice6).
- A new `other_versions` field has been added to the Packages plugin when the node is using RPM. This allows you to see all installed versions of packages, not just the latest version. Thanks [@jjustice6](https://github.com/jjustice6).
- The Linux Network plugin has been improved to not mark interfaces down if `stp_state` is marked as down. Thanks [@josephmilla](https://github.com/josephmilla).
- Arch running on ARM processors is now detected as the `arm` platform. Thanks [@BackSlasher](https://github.com/BackSlasher).

### Chef InSpec 4.10.4

Chef InSpec has been updated from 4.6.4 to 4.10.4 with the following changes:

- Fix handling multiple triggers in the `windows_task` resource
- Fix exceptions when resources are used with incompatible transports
- Un-deprecate the `be_running` matcher on the `service` resource
- Add resource `sys_info.manufacturer` and `sys_info.model`
- Add `ip6tables` resource

### Security Updates

#### bzip2

bzip2 has been updated from 1.0.6 to 1.0.8 to resolve [CVE-2016-3189](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3189) and [CVE-2019-12900](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-12900).

## What's New in 15.1

### New Resources

#### chocolatey_feature

The `chocolatey_feature` resource allows you to enable and disable Chocolatey features. See the [chocolatey_feature documentation](https://docs.chef.io/resources/chocolatey_feature/) for full usage information. Thanks [@gep13](https://github.com/gep13) for this new resource.

### Updated Resources

#### chocolatey_source

The `chocolatey_source` resource has been updated with new `enable` and `disable` actions, as well as `admin_only` and `allow_self_service` properties. Thanks [@gep13](https://github.com/gep13) for this enhancement.

#### launchd

The `launchd` resource has been updated with a new `launch_events` property, which allows you to specify higher-level event types to be used as launch-on-demand event sources. Thanks [@chilcote](https://github.com/chilcote) for this enhancement.

#### yum_package

The `yum_package` resource's helper for interacting with the yum subsystem has been updated to always close out the rpmdb lock, even during failures. This may prevent the rpmdb becoming locked in some rare conditions. Thanks for reporting this issue, [@lytao](https://github.com/lytao).

#### template

The `template` resource now provides additional information on failures, which is especially useful in ChefSpec tests. Thanks [@brodock](https://github.com/brodock) for this enhancement.

### Target Mode Improvements

Our experimental Target Mode received a large number of updates in Chef Infra Client 15.1. Target Mode now reuses the connection to the remote system, which greatly speeds up the remote Chef Infra run. There is also now support for Target Mode in the `systemd_unit`, `log`, `ruby_block`, and `breakpoint` resources. Keep in mind that when using `ruby_block` with Target Mode that the Ruby code in the block will execute locally as there is not necessarily a Ruby runtime on the remote host.

### Ohai 15.1

Ohai has been updated to 15.1 with the following changes:

- The `Shard` plugin properly uses the machine's `machinename`, `serial`, and `uuid` attributes to generate the shard value. The plugin also no longer throws an exception on macOS hosts. Thanks [@michel-slm](https://github.com/michel-slm) for these fixes.
- The `Virtualbox` plugin has been enhanced to gather information on running guests, storage, and networks when VirtualBox is installed on a node. Thanks [@freakinhippie](https://github.com/freakinhippie) for this new capability.
- Ohai no longer fails to gather interface information on Solaris in some rare conditions. Thanks [@devoptimist](https://github.com/devoptimist) for this fix.

### Chef InSpec 4.6.4

Chef InSpec has been updated from 4.3.2 to 4.6.4 with the following changes:

- InSpec `Attributes` have now been renamed to `Inputs` to avoid confusion with Chef Infra attributes.
- A new InSpec plugin type of `Input` has been added for defining new input types. See the [InSpec Plugins documentation](https://github.com/inspec/inspec/blob/master/docs/dev/plugins.md#implementing-input-plugins) for more information on writing these plugins.
- InSpec no longer prints errors to the stdout when passing `--format json`.
- When fetching profiles from GitHub, the URL can now include periods.
- The performance of InSpec startup has been improved.

## What's New in 15.0.300

This release includes critical bugfixes for the 15.0 release:
- Fix `knife bootstrap` over SSH when `requiretty` is configured on the host.
- Added the `--chef-license` CLI flag to `chef-apply` and `chef-solo` commands.

## What's New in 15.0.298

This release includes critical bugfixes for the 15.0 release:

- Allow accepting the license on non-interactive Windows sessions
- Resolve license acceptance failures on Windows 2012 R2
- Improve some `knife` and `chef-client` help text
- Properly handle session_timeout default value in `knife bootstrap`
- Avoid failures due to Train::Transports::SSHFailed class not being loaded in `knife bootstrap`
- Resolve failures using the ca_trust_file option with `knife bootstrap`

## What's New in 15.0.293

### Chef Client is now Chef Infra Client

Chef Client has a new name, but don't worry, it's the same Chef Client you've grown used to. You'll notice new branding throughout the application, help, and documentation but the command line name of `chef-client` remains the same.

### Chef EULA

Chef Infra Client requires an EULA to be accepted by users before it can run. Users can accept the EULA in a variety of ways:

- `chef-client --chef-license accept`
- `chef-client --chef-license accept-no-persist`
- `CHEF_LICENSE="accept" chef-client`
- `CHEF_LICENSE="accept-no-persist" chef-client`

Finally, if users run `chef-client` without any of these options, they will receive an interactive prompt asking for license acceptance. If the license is accepted, a marker file will be written to the filesystem unless `accept-no-persist` is specified. Once this marker file is persisted, users no longer need to set any of these flags.

See our [Frequently Asked Questions document](https://www.chef.io/bmc-faq/) for more information on the EULA and license acceptance.

### New Features / Functionality

#### Target Mode Prototype

Chef Infra Client 15 adds a prototype for a new method of executing resources called Target Mode. Target Mode allows a Chef Infra Client run to manage a remote system over SSH or another protocol supported by the Train library. This support includes platforms that we currently support like Ubuntu Linux, but also allows for configuring other architectures and platforms, such as switches that do not have native builds of Chef Infra Client. Target Mode maintains a separate node object for each target and allows you to manage that node using existing patterns that you currently use.

As of this release, only the `execute` resource and guards are supported, but modifying existing resources or writing new resources to support Target Mode is relatively easy. Using Target Mode is as easy as running `chef-client --target hostname`. The authentication credentials should be stored in your local `~/.chef/credentials` file with the hostname of the target node as the profile name. Each key/value pair is passed to Train for authentication.

#### Data Collection Ground-Up Refactor

Chef Infra Client's Data Collection subsystem is used to report node changes during client runs to Chef Automate or other reporting systems. For Chef Infra Client 15, we performed a ground-up rewrite of this subsystem, which greatly improves the data reported to Chef Automate and ensures data is delivered even in the toughest of failure conditions.

#### copy_properties_from in Custom Resources

A new `copy_properties_from` method for custom resources allows you copy properties from your custom resource into other resources you are calling, so you can avoid unnecessarily repeating code.

To inherit all the properties of another resource:

```ruby
resource_name :my_resource

property :mode, String, default: '777'
property :owner, String, default: 'app_user'
property :group, String, default: 'admins'

directory '/etc/myapp' do
  copy_properties_from new_resource
  recursive true
end
```

To selectively inherit certain properties from a resource:

```ruby
resource_name :my_resource

property :mode, String, default: '777'
property :owner, String, default: 'app_user'
property :group, String, default: 'admins'

directory '/etc/myapp' do
  copy_properties_from(new_resource, :owner, :group, :mode)
  mode '755'
  recursive true
end
```

#### ed25519 SSH key support

Our underlying SSH implementation has been updated to support the new ed25519 SSH key format. This means you will be able to use `knife bootstrap` and `knife ssh` on hosts that only support this new key format.

#### Allow Using --delete-entire-chef-repo in Chef Local Mode

Chef Solo's `--delete-entire-chef-repo` option has been extended to work in Local Mode as well. Be warned that this flag does exactly what it states, and when used incorrectly, can result in loss of work.

### New Resources

#### archive_file resource

Use the `archive_file` resource to decompress multiple archive formats without the need for compression tools on the host.

See the [archive_file](https://docs.chef.io/resources/archive_file/) documentation for more information.

#### windows_uac resource

Use the `windows_uac` resource to configure UAC settings on Windows hosts.

See the [windows_uac](https://docs.chef.io/resources/windows_uac) documentation for more information.

#### windows_dfs_folder resource

Use the `windows_dfs_folder` resource to create and delete Windows DFS folders.

See the [windows_dfs_folder](https://docs.chef.io/resources/windows_dfs_folder) documentation for more information.

#### windows_dfs_namespace resources

Use the `windows_dfs_namespace` resource to create and delete Windows DFS namespaces.

See the [windows_dfs_namespace](https://docs.chef.io/resources/windows_dfs_namespace) documentation for more information.

#### windows_dfs_server resources

Use the `windows_dfs_server` resource to configure Windows DFS server settings.

See the [windows_dfs_server](https://docs.chef.io/resources/windows_dfs_server) documentation for more information.

#### windows_dns_record resource

Use the `windows_dns_record` resource to create or delete DNS records.

See the [windows_dns_record](https://docs.chef.io/resources/windows_dns_record) documentation for more information.

#### windows_dns_zone resource

Use the `windows_dns_zone` resource to create or delete DNS zones.

See the [windows_dns_zone](https://docs.chef.io/resources/windows_dns_zone) documentation for more information.

#### snap_package resource

Use the `snap_package` resource to install snap packages on Ubuntu hosts.

See the [snap_package](https://docs.chef.io/resources/snap_package) documentation for more information.

### Resource Improvements

#### windows_task

The `windows_task` resource now supports the Start When Available option with a new `start_when_available` property.

#### locale

The `locale` resource now allows setting all possible LC_* environmental variables.

#### directory

The `directory` resource now property supports passing `deny_rights :write` on Windows nodes.

#### windows_service

The `windows_service` resource has been improved to prevent accidentally reverting a service back to default settings in a subsequent definition.

This example will no longer result in the MyApp service reverting to default RunAsUser:
```ruby
windows_service 'MyApp' do
  run_as_user 'MyAppsUser'
  run_as_password 'MyAppsUserPassword'
  startup_type :automatic
  delayed_start true
  action [:configure, :start]
end

...

windows_service 'MyApp' do
  startup_type :automatic
  action [:configure, :start]
end
```

#### Ruby 2.6.3

Chef now ships with Ruby 2.6.3. This new version of Ruby improves performance and includes many new features to make more advanced Chef usage easier. See <https://www.rubyguides.com/2018/11/ruby-2-6-new-features/> for a list of some of the new functionality.

### Ohai Improvements

#### Improved Linux Platform / Platform Family Detection

`Platform` and `platform_family` detection on Linux has been rewritten to utilize the latest config files on modern Linux distributions before falling back to slower and fragile legacy detection methods. Ohai will now begin by parsing the contents of `/etc/os-release` for OS information if available. This feature improves the reliability of detection on modern distros and allows detection of new distros as they are released.

With this change, we now detect `sles_sap` as a member of the `suse` `platform_family`. Additionally, this change corrects our detection of the `platform_version` on Cisco Nexus switches where previously the build number was incorrectly appended to the version string.

#### Improved Virtualization Detection

Hypervisor detection on multiple platforms has been updated to use DMI data and a single set of hypervisors. This greatly improves the detection of hypervisors on Windows, BSD and Solaris platforms. It also means that as new hypervisor detection is added in the future, we will automatically support the majority of platforms.

#### Fix Windows 2016 FQDN Detection

Ohai 14 incorrectly detected a Windows 2016 node's `fqdn` as the node's `hostname`. Ohai 15 now correctly reports the FQDN value.

#### Improved Memory Usage

Ohai now uses less memory due to internal optimization of how we track plugin information.

#### FIPS Detection Improvements

The FIPS plugin now uses the built-in FIPS detection in Ruby for improved detection.

### New Deprecations

#### knife cookbook site deprecated in favor of knife supermarket

The `knife cookbook site` command has been deprecated in favor of the `knife supermarket` command. `knife cookbook site` will now produce a warning message. In Chef Infra Client 16, we will remove the `knife cookbook site` command entirely.

#### locale LC_ALL property

The `LC_ALL` property in the `locale` resource has been deprecated as the usage of this environmental variable is not recommended by distribution maintainers.

### Breaking Changes

#### Knife Bootstrap

Knife bootstrap has been entirely rewritten. Native support for Windows bootstrapping is now a part of the main `knife bootstrap` command. This marks the deprecation of the `knife-windows` plugin's `bootstrap` behavior. This change also addresses [CVE-2015-8559](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8559): *The `knife bootstrap` command in chef leaks the validator.pem private RSA key to /var/log/messages*.

**Important**: `knife bootstrap` can bootstrap all supported versions of Chef Infra Client. Older versions may continue to work as far back as 12.20.

In order to accommodate a combined bootstrap that supports both SSH and WinRM, some CLI flags have been added, removed, or changed. Using the changed options will result in deprecation warnings, but `knife bootstrap` will accept those options unless otherwise noted. Using removed options will cause the command to fail.

**New Flags**

| Flag | Description |
|-----:|:------------|
| --max-wait SECONDS | Maximum time to wait for initial connection to be established. |
| --winrm-basic-auth-only | Perform only Basic Authentication to the target WinRM node. |
| --connection-protocol PROTOCOL| Connection protocol to use. Valid values are 'winrm' and 'ssh'. Default is 'ssh'. |
| --connection-user | User to authenticate as, regardless of protocol. |
| --connection-password| Password to authenticate as, regardless of protocol. |
| --connection-port | Port to connect to, regardless of protocol. |
| --ssh-verify-host-key VALUE | Verify host key. Default is 'always'. Valid values are 'accept', 'accept\_new', 'accept\_new\_or\_local\_tunnel', and 'never'. |

**Changed Flags**

| Flag | New Option | Notes |
|-----:|:-----------|:------|
| --[no-]host-key-verify |--ssh-verify-host-key VALUE | See above for valid values. |
| --forward-agent | --ssh-forward-agent| |
| --session-timeout MINUTES | --session-timeout SECONDS|New for ssh, existing for winrm. The unit has changed from MINUTES to SECONDS for consistency with other timeouts. |
| --ssh-password | --connection-password | |
| --ssh-port | --connection-port | `knife[:ssh_port]` config setting remains available.
| --ssh-user | --connection-user | `knife[:ssh_user]` config setting remains available.
| --ssl-peer-fingerprint | --winrm-ssl-peer-fingerprint | |
| --prerelease |--channel CHANNEL | This now allows you to specify the channel that Chef Infra Client gets installed from. Valid values are _stable_, _current_, and _unstable_. 'current' has the same effect as using the old --prerelease. |
| --winrm-authentication-protocol=PROTO | --winrm-auth-method=AUTH-METHOD | Valid values: _plaintext_, _kerberos_, _ssl_, _negotiate_ |
| --winrm-password| --connection-password | |
| --winrm-port| --connection-port | `knife[:winrm_port]` config setting remains available.|
| --winrm-ssl-verify-mode MODE | --winrm-no-verify-cert | Mode is not accepted. When flag is present, SSL cert will not be verified. Same as original mode of 'verify\_none'. [1] |
| --winrm-transport TRANSPORT | --winrm-ssl | Use this flag if the target host is accepts WinRM connections over SSL. [1] |
| --winrm-user | --connection-user | `knife[:winrm_user]` config setting remains available.|
| --winrm-session-timeout | --session-timeout | Now available for bootstrapping over SSH as well |

[1] These flags do not have an automatic mapping of old flag -> new flag. The new flag must be used.

**Removed Flags**

| Flag | Notes |
|-----:|:------|
|--kerberos-keytab-file| This option existed but was not implemented. |
|--winrm-codepage| This was used under `knife-windows` because bootstrapping was performed over a `cmd` shell. It is now invoked from `powershell`, so this option is no longer used. |
|--winrm-shell| This option was ignored for bootstrap. |
|--install-as-service| Installing Chef Client as a service is not supported. |

**Usage Changes**

Instead of specifying protocol with `-o`, it is also possible to prefix the target hostname with the protocol in URL format. For example:

```
knife bootstrap example.com -o ssh
knife bootstrap ssh://example.com
knife bootstrap example.com -o winrm
knife bootstrap winrm://example.com
```

#### Chef Infra Client packages remove /opt/chef before installation

Upon upgrading Chef Infra Client packages, the `/opt/chef` directory is removed. This ensures any `chef_gem` installed gem versions and other modifications to `/opt/chef` will removed to prevent upgrade issues. Due to technical details with rpm script execution order, the implementation involves a a pre-installation script that wipes `/opt/chef` before every install, and is done consistently this way on every package manager.

Users who are properly managing customizations to `/opt/chef` through Chef recipes would not be affected, because their customizations will still be installed by the new package.

You will see a warning that the `/opt/chef` directory will be removed during the package installation process.

#### powershell_script now allows overriding the default flags

We now append `powershell_script` user flags to the default flags rather than the other way around, which made user flags override the defaults. This is the correct behavior, but it may cause scripts to execute differently than in previous Chef Client releases.

#### Package provider allow_downgrade is now true by default

We reversed the default behavior to `allow_downgrade true` for our package providers. To override this setting to prevent downgrades, use the `allow_downgrade false` flag. This behavior change will mostly affect users of the rpm and zypper package providers.

In this example, the code below should now read as asserting that the package `foo` must be version `1.2.3` after that resource is run.:

```
package "foo" do
  version "1.2.3"
end
```

The code below is now what is necessary to specify that `foo` must be version `1.2.3` or higher. Note that the yum provider supports syntax like `package "foo > 1.2.3"`, which should be used and is preferred over using allow_downgrade.

```
package "foo" do
  allow_downgrade false
  version "1.2.3"
end
```

#### Node Attributes deep merge nil values

Writing a `nil` to a precedence level in the node object now acts like any other value and can be used to override values back to `nil`.

For example:

```
chef (15.0.53)> node.default["foo"] = "bar"
 => "bar"
chef (15.0.53)> node.override["foo"] = nil
 => nil
chef (15.0.53)> node["foo"]
 => nil
```

In prior versions of `chef-client`, the `nil` set in the override level would be completely ignored and the value of `node["foo"]` would have been "bar".

#### http_disable_auth_on_redirect now enabled

The Chef config ``http_disable_auth_on_redirect`` has been changed from `false` to `true`. In Chef Infra Client 16, this config option will be removed altogether and Chef Infra Client will always disable auth on redirect.

#### knife cookbook test removal

The `knife cookbook test` command has been removed. This command would often report non-functional cookbooks as functional, and has been superseded by functionality in other testing tools such as `cookstyle`, `foodcritic`, and `chefspec`.

#### ohai resource's ohai_name property removal

The `ohai` resource contained a non-functional `ohai_name` property, which has been removed.

#### knife status --hide-healthy flag removal

The `knife status --hide-healthy` flag has been removed. Users should run `knife status --hide-by-mins MINS` instead.

#### Cookbook shadowing in Chef Solo Legacy Mode Removed

Previously, if a user provided multiple cookbook paths to Chef Solo that contained cookbooks with the same name, Chef Solo would combine these into a single cookbook. This merging of two cookbooks often caused unexpected outcomes and has been removed.

#### Removal of unused route resource properties

The `route` resource contained multiple unused properties that have been removed. If you previously set `networking`, `networking_ipv6`, `hostname`, `domainname`, or `domain`, they would be ignored. In Chef Infra Client 15, setting these properties will throw an error.

#### FreeBSD pkg provider removal

Support for the FreeBSD `pkg` package system in the `freebsd_package` resource has been removed. FreeBSD 10 replaced the `pkg` system with `pkg-ng` system, so this removal only impacts users of EOL FreeBSD releases.

#### require_recipe removal

The legacy `require_recipe` method in recipes has been removed. This method was replaced with `include_recipe` in Chef Client 10, and a FoodCritic rule has been warning to update cookbooks for multiple years.

#### Legacy shell_out methods removed

In Chef Client 14, many of the more obscure `shell_out` methods used in LWRPs and custom resources were combined into the standard `shell_out` and `shell_out!` methods. The legacy methods were infrequently used and Chef Client 14/Foodcritic both contained deprecation warnings for these methods. The following methods will now throw an error: `shell_out_compact`, `shell_out_compact!`, `shell_out_compact_timeout`, `shell_out_compact_timeout!`, `shell_out_with_systems_locale`, and `shell_out_with_systems_locale!`.

#### knife bootstrap --identity_file removal

The `knife bootstrap --identity_file` flag has been removed. This flag was deprecated in Chef Client 12, and users should now use the `--ssh-identity-file` flag instead.

### knife user support for Chef Infra Server < 12 removed

The `knife user` command no longer supports the open source Chef Infra Server version prior to 12.

#### attributes in metadata.rb

Chef Infra Client no longer processes attributes in the `metadata.rb` file. Attributes could be defined in the `metadata.rb` file as a form of documentation, which would be shown when running `knife cookbook show COOKBOOK_NAME`. Often, these attribute definitions would become out of sync with the attributes in the actual attributes files. Chef Infra Client 15 will no longer show these attributes when running `knife cookbook show COOKBOOK_NAME` and will instead throw a warning message upon upload. Foodcritic has warned against the use of attributes in the `metadata.rb` file since April 2017.

#### Node attributes array bugfix

Chef Infra Client 15 includes a bugfix for incorrect node attribute behavior involving a rare usage of arrays, which may impact users who depend on the incorrect behavior.

Previously, you could set an attribute like this:

```
node.default["foo"] = []
node.default["foo"] << { "bar" => "baz }
```

This would result in a Hash, instead of a VividMash, inserted into the AttrArray, so that:

```
node.default["foo"][0]["bar"] # gives the correct result
node.default["foo"][0][:bar]  # does not work due to the sub-Hash not
                              # converting keys
```

The new behavior uses a Mash so that the attributes will work as expected.

#### Ohai's system_profile plugin for macOS removed

We removed the `system_profile` plugin because it incorrectly returned data on modern macOS systems. If you relied on this plugin, you'll want to update recipes to use `node['hardware']` instead, which correctly returns the same data, but in a more easily consumed format. Removing this plugin speeds up Ohai and Chef Infra Client by ~3 seconds, and dramatically reduces the size of the node object on the Chef Infra Server.

#### Ohai's Ohai::Util::Win32::GroupHelper class has been removed

We removed the `Ohai::Util::Win32::GroupHelper` helper class from Ohai. This class was intended for use internally in several Windows plugins, but it was never marked private in the codebase. If any of your Ohai plugins rely on this helper class, you will need to update your plugins for Ohai 15.

#### Audit Mode

Chef Client's Audit mode was introduced in 2015 as a beta that needed to be enabled via `client.rb`. Its functionality has been superseded by Chef InSpec and has been removed.

#### Ohai system_profiler plugin removal

The `system_profiler` plugin, which ran on macOS systems, has been removed. This plugin took longer to run than all other plugins on macOS combined, and no longer produced usable information on modern macOS releases. If you're looking for similar information, it can now be found in the `hardware` plugin.

#### Ohai::Util::Win32::GroupHelper helper removal

The deprecated `Ohai::Util::Win32::GroupHelper` helper has been removed from Ohai. Any custom Ohai plugins using this helper will need to be updated.

#### Ohai::System.refresh_plugins method removal

The `refresh_plugins` method in the `Ohai::System` class has been removed as it has been unused for multiple major Ohai releases. If you are programmatically using Ohai in your own Ruby application, you will need to update your code to use the `load_plugins` method instead.

#### Ohai Microsoft VirtualPC / VirtualServer detection removal

The `Virtualization` plugin will no longer detect systems running on the circa ~2005 VirtualPC or VirtualServer hypervisors. These hypervisors were long ago deprecated by Microsoft and support can no longer be tested.

## What's New in 14.15

### Updated Resources

#### ifconfig

The `ifconfig` resource has been updated to properly support interfaces with a hyphen in their name. This is most commonly encountered with bridge interfaces that are named `br-1234`. Additionally, the `ifconfig` resource now supports the latest ifconfig binaries found in OS releases such as Debian 10.

#### windows_task

The `windows_task` resource now supports the Start When Available option with a new `start_when_available` property. Issues that prevented the resource from being idempotent on Windows 2016 and 2019 hosts have also been resolved.

### Platform Support

#### New Platforms

Chef Infra Client is now tested against the following platforms with packages available on [downloads.chef.io](https://downloads.chef.io):

- Ubuntu 20.04
- Ubuntu 18.04 aarch64
- Debian 10

#### Retired Platforms

- Chef Infra Clients packages are no longer produced for Windows 2008 R2 as this release reached its end of life on Jan 14th, 2020.
- Chef Infra Client packages are no longer produced for RHEL 6 on the s390x platform.

### Security Updates

#### OpenSSL

OpenSSL has been updated to 1.0.2u to resolve [CVE-2019-1551](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1551)

#### Ruby

Ruby has been updated from 2.5.7 to 2.5.8 to resolve the following CVEs:

- [CVE-2020-16255](https://www.ruby-lang.org/en/news/2020/03/19/json-dos-cve-2020-10663/): Unsafe Object Creation Vulnerability in JSON (Additional fix)
- [CVE-2020-10933](https://www.ruby-lang.org/en/news/2020/03/31/heap-exposure-in-socket-cve-2020-10933/): Heap exposure vulnerability in the socket library

## What's New in 14.14.29

### Bug Fixes

 - Fixed an error with the `service` and `systemd_unit` resources which would try to re-enable services with an indirect status.
 - The `systemd_unit` resource now logs at the info level.
 - Fixed knife config when it returned a `TypeError: no implicit conversion of nil into String` error.

### Security Updates

#### libxslt

libxslt has been updated to 1.1.34 to resolve [CVE-2019-13118](https://nvd.nist.gov/vuln/detail/CVE-2019-13118).

## What's New in 14.14.25

### Bug Fixes

- Resolved a regression introduced in Chef Infra Client 14.14.14 that broke installation of gems in some scenarios
- Fixed Habitat packaging of `chef-client` artifacts
- Fixed crash in knife when displaying a missing profile error message
- Fixed knife subcommand --help not working as intended for some commands
- Fixed knife ssh interactive mode exit error
- Fixed for `:day` option not accepting integer value in the `windows_task` resource
- Fixed for `user` resource not handling a GID if it is specified as a string
- Fixed the `ifconfig` resource to support interfaces with a `-` in the name

## What's New in 14.14.14

### Platform Updates

#### Newly Supported Platforms

The following platforms are now packaged and tested for Chef Infra Client:

- Red Hat 8
- FreeBSD 12
- macOS 10.15
- Windows 2019
- AIX 7.2

#### Deprecated Platforms

The following platforms have reached EOL status and are no longer packaged or tested for Chef Infra Client:

- FreeBSD 10
- macOS 10.12
- SUSE Linux Enterprise Server (SLES) 11
- Ubuntu 14.04

See Chef's [Platform End-of-Life Policy](/platforms/#platform-end-of-life-policy) for more information on when Chef ends support for an OS release.

### Updated Resources

#### dnf_package

The `dnf_package` resource has been updated to fully support RHEL 8.

#### zypper_package

The `zypper_package` resource has been updated to properly update packages when using the `:upgrade` action.

#### remote_file

The `remote_file` resource now properly shows download progress when the `show_progress` property is set to true.

### Improvements

### Custom Resource Unified Mode

Chef Infra Client 14.14 introduces an exciting new way to easily write custom resources that mix built-in Chef Infra resources with Ruby code. Previously, custom resources would use Chef Infra's standard compile and converge phases, which meant that Ruby would be evaluated first and then the resources would be converged. This often results in confusing and undesirable behavior when you are trying to mix resources with Ruby logic. Many custom resource authors would attempt to get around this by forcing resources to run at compile time so that all the code in their resource would execute during the compile phase.

An example of forcing a resource to run at compile time:

```ruby
resource_name 'foo' do
  action :nothing
end.run_action(:some_action)
```

With unified mode, you opt in to a single phase per resource where all Ruby and Chef Infra resources are executed at once. This makes it far easier to determine how your code will be evaluated and run. Additionally, you no longer need to force any resources to run at compile time, as all code is run in the compile phase. To enable this new mode just add `unified_mode true` to your resources like this:

```ruby
property :Some_property, String

unified_mode true

action :create do
  # some code
end
```

#### New Options for installing Ruby Gems From metadata.rb

Chef Infra Client allows gems to be specified in the cookbook metadata.rb, which can be problematic in some environments. When a cookbook is running in an airgapped environment, Chef Infra Client attempts to connect to rubygems.org even if the gem is already on the system. There are now two additional configuration options that can be set in your `client.rb` config:
    - `gem_installer_bundler_options`: This allows setting additional bundler options for the install such as  --local to install from local cache. Example: ["--local", "--clean"].
    - `skip_gem_metadata_installation`: If set to true skip gem metadata installation if all gems are already installed.

#### SLES / openSUSE 15 detection

Ohai now properly detects SLES and openSUSE 15.x. Thanks for this fix [@balasankarc](https://gitlab.com/balasankarc).

#### Performance Improvements

We have improved the performance of Chef Infra Client by resolving bundler errors in our packaging.

#### Bootstrapping Chef Infra Client 15 will no fail

Knife now fails with a descriptive error message when attempting to bootstrap nodes with Chef Infra Client 15. You will need to bootstrap these nodes using Knife from Chef Infra Client 15.x. We recommend performing this bootstrap from Chef Workstation, which includes the Knife CLI in addition to other useful tools for managing your infrastructure with Chef Infra.

### Security Updates

#### Ruby

Ruby has been updated from 2.5.5 to 2.5.7 in order to resolve the following CVEs:

- [CVE-2012-6708](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-6708)
- [CVE-2015-9251](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9251).
- [CVE-2019-16201](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-15845).
- [CVE-2019-15845](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9251).
- [CVE-2019-16254](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16254).
- [CVE-2019-16255](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16255).

#### openssl

openssl has been updated from 1.0.2s to 1.0.2t in order to resolve [CVE-2019-1563](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1563) and [CVE-2019-1547](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1547).

#### nokogiri

nokogiri has been updated from 1.10.2 to 1.10.4 in order to resolve [CVE-2019-5477](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5477).

## What's New in 14.13

### Updated Resources

#### directory

The `directory` has been updated to properly set the `deny_rights` permission on Windows. Thanks [@merlinjim](https://github.com/merlinjim) for reporting this issue.

#### service

The `service` resource is now idempotent on SLES 11 systems. Thanks [@gsingla294](https://github.com/gsingla294) for reporting this issue.

#### cron

The `cron` resource has been updated to advise users to use the specify properties rather than passing values in as part of the `environment` property. This avoids a situation where a user could pass the differing values in both locations and receive unexpected results.

#### link

The `link` resource includes improved logging upon failure to help you debug what has failed. Thanks [@jaymzh](https://github.com/jaymzh) for this improvement.

#### template

The `template` resource now includes additional information when templating failures, which is particularly useful in ChefSpec. Thanks [@brodock](https://github.com/brodock) for this improvement.

### delete_resource Fix

The `delete_resource` helper now works properly when the resource you are attempting to delete has multiple providers. Thanks [@artem-sidorenko](https://github.com/artem-sidorenko) for this fix.

### Helpers Help Everywhere

Various helpers have been moved into Chef Infra Client's `universal` class, which makes them available anywhere in your cookbook, not just recipes. If you've ever been confused why something like `search`, `powershell_out`, or `data_bag_item` didn't work somewhere in your code, that should be resolved now.

### Deprecations

The `CHEF-25` deprecation for resource collisions between cookbooks and resources in Chef Infra Client has been removed. Instead you will see a log warning that a collision has occurred, which advises you to update your run_list or cookbooks.

### Updated Components

- openssl 1.0.2r -> 1.0.2s (bugfix only release)
- cacerts 2019-01-23 -> 2019-05-15

## What's New in 14.12.9

### License Acceptance Placeholder Flag

In preparation for Chef Infra Client 15.0 we've added a placeholder `--chef-license` flag to the chef-client command. This allows you to use the new `--chef-license` flag on both Chef Infra Client 14.12.9+ and 15+ notes without producing errors on Chef Infra Client 14.

### Important Bug Fixes

- Blacklisting and whitelisting default and override level attributes is once again possible.
- You may now encrypt a previously unencrypted data bag.
- Resolved a regression introduced in Chef Infra Client 14.12.3 that resulted in errors when managing Windows services

## What's New in 14.12.3

### Updated Resources

#### windows_service

The windows_service resource no longer resets credentials on a service when using the :start action without the :configure action. Thanks [@jasonwbarnett](https://github.com/jasonwbarnett) for fixing this.

#### windows_certificate

The windows_certificate resource now imports nested certificates while importing P7B certs.

### Updated Components

- nokogiri 1.10.1 -> 1.10.2
- ruby 2.5.3 -> 2.5.5
- InSpec 3.7.1 -> 3.9.0
- The unused windows-api gem is no longer bundled with Chef on Windows hosts

## What's New in 14.11

### Updated Resources

#### chocolatey_package

The chocolatey_package resource now uses the provided options to fetch information on available packages, which allows installation packages from private sources. Thanks [@astoltz](https://github.com/astoltz) for reporting this issue.

#### openssl_dhparam

The openssl_dhparam resource now supports updating the dhparam file's mode on subsequent chef-client runs. Thanks [@anewb](https://github.com/anewb) for the initial work on this fix.

#### mount

The mount resource now properly adds a blank line between entries in fstab to prevent mount failures on AIX.

#### windows_certificate

The windows_certificate resource now supports importing Base64 encoded CER certificates and nested P7B certificates. Additionally, private keys in PFX certificates are now imported along with the certificate.

#### windows_share

The windows_share resource has improved logic to compare the desired share path vs. the current path, which prevents the resource from incorrectly converging during each Chef run. Thanks [@Xorima](https://github.com/xorima) for this fix.

#### windows_task

The windows_task resource now properly clears out arguments that are no longer present when updating a task. Thanks [@nmcspadden](https://github.com/nmcspadden) for reporting this.

### InSpec 3.7.1

InSpec has been updated from 3.4.1 to 3.7.1. This new release contains improvements to the plugin system, a new config file system, and improvements to multiple resources. Additionally, profile attributes have also been renamed to inputs to prevent confusion with Chef attributes, which weren't actually related in any way.

### Updated Components

- bundler 1.16.1 -> 1.17.3
- libxml2 2.9.7 -> 2.9.9
- ca-certs updated to 2019-01-22 for new roots

### Security Updates

#### OpenSSL

OpenSSL has been updated to 1.0.2r in order to resolve [CVE-2019-1559](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1559)

#### RubyGems

RubyGems has been updated to 2.7.9 in order to resolve the following CVEs:

- [CVE-2019-8320](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8320): Delete directory using symlink when decompressing tar
- [CVE-2019-8321](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8321): Escape sequence injection vulnerability in verbose
- [CVE-2019-8322](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8322): Escape sequence injection vulnerability in gem owner
- [CVE-2019-8323](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8323): Escape sequence injection vulnerability in API response handling
- [CVE-2019-8324](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8324): Installing a malicious gem may lead to arbitrary code execution
- [CVE-2019-8325](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8325): Escape sequence injection vulnerability in errors

## What's New in 14.10

### Updated Resources

#### windows_certificate

The windows_certificate resource is now fully idempotent and properly imports private keys. Thanks [@Xorima](https://github.com/Xorima) for reporting these issues.

#### apt_repository

The apt_repository resource no longer creates .gpg directory in the user's home directory owned by root when installing repository keys. Thanks [@omry](http://github.com/omry) for reporting this issue.

#### git

The git resource no longer displays the URL of the repository if the `sensitive` property is set.

### InSpec 3.4.1

InSpec has been updated from 3.2.6 to 3.4.1. This new release adds new `aws_billing_report` / `aws_billing_reports` resources, resolves multiple bugs, and includes tons of under the hood improvements.

### New Deprecations

#### knife cookbook site

Since Chef 13, `knife cookbook site` has actually called the `knife supermarket` command under the hood. In Chef 16 (April 2020), we will remove the `knife cookbook site` command in favor of `knife supermarket`.

#### Audit Mode

Chef's Audit mode was introduced in 2015 as a beta that needed to be enabled via client.rb. Its functionality has been superseded by InSpec and we will be removing this beta feature in Chef Infra Client 15 (April 2019).

#### Cookbook Shadowing

Cookbook shadowing was deprecated in 0.10 and will be removed in Chef Infra Client 15 (April 2019). Cookbook shadowing allowed combining cookbooks within a mono-repo, so long as the cookbooks in question had the same name and were present in both the cookbooks directory and the site-cookbooks directory.

## What's New in 14.9

### Updated Resources

#### group

On Windows hosts, the group resource now supports setting the comment field via a new `comment` property.

#### homebrew_cask

Two issues, which caused homebrew_cask to converge on each Chef run, have been resolved. Thanks [@jeroenj](https://github.com/jeroenj) for this fix. Additionally, the resource will no longer fail if the `cask_name` property is specified.

#### homebrew_tap

The homebrew_tap resource no longer fails if the `tap_name` property is specified.

#### openssl_x509_request

The openssl_x509_request resource now properly writes out the CSR file if the `path` property is specified. Thank you [@cpjones](https://github.com/cpjones) for reporting this issue.

#### powershell_package_source

powershell_package_source now suppresses warnings, which prevented properly loading the resource state, and resolves idempotency issues when both the `name` and `source_name` properties were specified. Thanks [@Happycoil](https://github.com/Happycoil) for this fix.

#### sysctl

The sysctl resource now allows slashes in the key or block name. This allows keys such as `net/ipv4/conf/ens256.401/rp_filter` to be used with this resource.

#### windows_ad_join

Errors joining the domain are now properly suppressed from the console and logs if the `sensitive` property is set to true. Thanks [@Happycoil](https://github.com/Happycoil) for this improvement.

#### windows_certificate

The delete action now longer fails if a certificate does not exist on the system. Additionally, certificates with special characters in their passwords will no longer fail. Thank you for reporting this [@chadmccune](https://github.com/chadmccune).

#### windows_printer

The windows_printer resource no longer fails when creating or deleting a printer if the `device_id` property is specified.

#### windows_task

Non-system users can now run tasks without a password being specified.

### Minimal Ohai Improvements

The ohai `init_package` plugin is now included as part of the `minimal_ohai` plugins set, which allows resources such as timezone to continue to function if Chef is running with the minimal number of ohai plugins.

### Ruby 2.6 Support

Chef 14.9 now supports Ruby 2.6.

### InSpec 3.2.6

InSpec has been updated from 3.0.64 to 3.2.6 with improved resources for auditing. See the [InSpec changelog](https://github.com/inspec/inspec/blob/master/CHANGELOG.md#v326-2018-12-20) for additional details on this new version.

### powershell_exec Runtimes Bundled

The necessary VC++ runtimes for the powershell_exec helper are now bundled with Chef to prevent failures on hosts that lacked the runtimes.

## What's New in 14.8

### Updated Resources

#### apt_package

The apt_package resource now supports using the `allow_downgrade` property to enable downgrading of packages on a node in order to meet a specified version. Thank you [@whiteley](https://github.com/whiteley) for requesting this enhancement.

#### apt_repository

An issue was resolved in the apt_repository resource that caused the resource to fail when importing GPG keys on newer Debian releases. Thank you [@EugenMayer](https://github.com/EugenMayer) for this fix.

#### dnf_package / yum_package

Initial support has been added for Red Hat Enterprise Linux 8. Thank you [@pixdrift](https://github.com/pixdrift) for this fix.

#### gem_package

gem_package now supports installing gems into Ruby 2.6 or later installations.

#### windows_ad_join

windows_ad_join now uses the UPN format for usernames, which prevents some failures authenticating to the domain.

#### windows_certificate

An issue was resolved in the :acl_add action of the windows_certificate resource, which caused the resource to fail. Thank you [@shoekstra](https://github.com/shoekstra) for reporting this issue.

#### windows_feature

The windows_feature resource now allows for the installation of DISM features that have been fully removed from a system. Thank you [@zanecodes](https://github.com/zanecodes) for requesting this enhancement.

#### windows_share

Multiple issues were resolved in windows_share, which caused the resource to either fail or update the share state on every Chef Client run. Thank you [@chadmccune](https://github.com/chadmccune) for reporting several of these issues and [@derekgroh](https://github.com/derekgroh) for one of the fixes.

#### windows_task

A regression was resolved that prevented ChefSpec from testing the windows_task resource in Chef Client 14.7. Thank you [@jjustice6](https://github.com/jjustice6) for reporting this issue.

### Ohai 14.8

#### Improved Virtualization Detection

**Hyper-V Hypervisor Detection**

Detection of Linux guests running on Hyper-V has been improved. In addition, Linux guests on Hyper-V hypervisors will also now detect their hypervisor's hostname. Thank you [@safematix](https://github.com/safematix) for contributing this enhancement.

Example `node['virtualization']` data:

```json
{
  "systems": {
    "hyperv": "guest"
  },
  "system": "hyperv",
  "role": "guest",
  "hypervisor_host": "hyper_v.example.com"
}
```

**LXC / LXD Detection**

On Linux systems running lxc or lxd containers, the lxc/lxd virtualization system will now properly populate the `node['virtualization']['systems']` attribute.

**BSD Hypervisor Detection**

BSD-based systems can now detect guests running on KVM and Amazon's hypervisor without the need for the dmidecode package.

#### New Platform Support

- Ohai now properly detects the openSUSE 15.X platform. Thank you [@megamorf](https://github.com/megamorf) for reporting this issue.
- SUSE Linux Enterprise Desktop now identified as platform_family 'suse'
- XCP-NG is now identified as platform 'xcp' and platform_family 'rhel'. Thank you [@heyjodom](http://github.com/heyjodom) for submitting this enhancement.
- Mangeia Linux is now identified as platform 'mangeia' and platform_family 'mandriva'
- Antergos Linux now identified as platform_family 'arch'
- Manjaro Linux now identified as platform_family 'arch'

### Security Updates

#### OpenSSL

OpenSSL has been updated to 1.0.2q in order to resolve:

- Microarchitecture timing vulnerability in ECC scalar multiplication [CVE-2018-5407](https://nvd.nist.gov/vuln/detail/CVE-2018-5407)
- Timing vulnerability in DSA signature generation ([CVE-2018-0734](https://nvd.nist.gov/vuln/detail/CVE-2018-0734))

## What's New in 14.7

### New Resources

#### windows_firewall_rule

Use the `windows_firewall_rule` resource create or delete Windows Firewall rules.

See the [windows_firewall_rule](https://docs.chef.io/resources/windows_firewall_rule) documentation for more information.

Thank you [Schuberg Philis](https://schubergphilis.com/) for transferring us the [windows_firewall cookbook](https://supermarket.chef.io/cookbooks/windows_firewall) and to [@Happycoil](https://github.com/Happycoil) for porting it to chef-client with a significant refactoring.

#### windows_share

Use the `windows_share` resource create or delete Windows file shares.

See the [windows_share](https://docs.chef.io/resources/windows_share) documentation for more information.

#### windows_certificate

Use the `windows_certificate` resource add, remove, or verify certificates in the system or user certificate stores.

See the [windows_certificate](https://docs.chef.io/resources/windows_certificate) documentation for more information.

### Updated Resources

#### dmg_package

The dmg_package resource has been refactored to improve idempotency and properly support accepting a DMG's EULA with the `accept_eula` property.

#### kernel_module

Kernel_module now only runs the `initramfs` update once per Chef run to greatly speed up chef-client runs when multiple kernel_module resources are used. Thank you [@tomdoherty](https://github.com/tomdoherty) for this improvement.

#### mount

The `supports` property once again allows passing supports data as an array. This matches the behavior present in Chef 12.

#### timezone

macOS support has been added to the timezone resource.

#### windows_task

A regression in Chef 14.6's windows_task resource which resulted in tasks being created with the "Run only when user is logged on" option being set when created with a specific user other than SYSTEM, has been resolved.

## What's New in 14.6

### Smaller Package and Install Size

Both Chef packages and on disk installations have been greatly reduced in size by trimming unnecessary installation files. This has reduced our package size on macOS/Linux by ~50% and Windows by ~12%. With this change Chef 14 is now smaller than a legacy Chef 10 package.

### New Resources

#### timezone

Chef now includes the `timezone` resource from [@dragonsmith](http://github.com/dragonsmith)'s `timezone_lwrp` cookbook. This resource supports setting a Linux node's timezone. Thank you [@dragonsmith](http://github.com/dragonsmith) for allowing us to include this out of the box in Chef.

Example:

```ruby
timezone 'UTC'
```

### Updated Resources

#### windows_task

The `windows_task` resource has been updated to support localized system users and groups on non-English nodes. Thanks [@jugatsu](http://github.com/jugatsu) for making this possible.

#### user

The `user` resource now includes a new `full_name` property for Windows hosts, which allows specifying a user's full name.

Example:

```ruby
user 'jdoe' do
  full_name 'John Doe'
end
```

#### zypper_package

The `zypper_package` resource now includes a new `global_options` property. This property can be used to specify one or more options for the zypper command line that are global in context.

Example:

```ruby
package 'sssd' do
   global_options '-D /tmp/repos.d/'
end
```

### InSpec 3.0

Inspec has been updated to version 3.0 with addition resources, exception handling, and a new plugin system. See <https://blog.chef.io/2018/10/16/announcing-inspec-3-0/> for details.

### macOS Mojave (10.14)

Chef is now tested against macOS Mojave, and packages are now available at downloads.chef.io.

### Important Bugfixes

- Multiple bugfixes in Chef Vault have been resolved by updating chef-vault to 3.4.2
- Invalid yum package names now gracefully fail
- `windows_ad_join` now properly executes. Thank you [@cpjones01](https://github.com/cpjones01) for reporting this.
- `rhsm_errata_level` now properly executes. Thank you [@freakinhippie](https://github.com/freakinhippie) for this fix.
- `registry_key` now properly writes out the correct value when `sensitive` is specified. Thank you [@josh-barker](https://github.com/josh-barker) for this fix.
- `locale` now properly executes on RHEL 6 and Amazon Linux 201X.

### Ohai 14.6

#### Filesystem Plugin on AIX and Solaris

AIX and Solaris now ship with a filesystem2 plugin that updates the filesystem data to match that of Linux, macOS, and BSD hosts. This new data structure makes accessing filesystem data in recipes easier and especially improves the layout and depth of data on ZFS filesystems. In Chef Infra Client 15 (April 2019) we will begin writing this same format of data to the existing `node['filesystem']` namespace. In Chef 16 (April 2020) we will remove the `node['filesystem2']` namespace, completing the transition to the new format. Thank you [@jaymzh](https://github.com/jaymzh) for continuing the updates to our filesystem plugins with this change.

#### macOS Improvements

The system_profile plugin has been improved to skip over unnecessary data, which reduces macOS node sizes on the Chef Server. Additionally the CPU plugin has been updated to limit what sysctl values it polls, which prevents hanging on some system configurations.

#### SLES 15 Detection

SLES 15 is now correctly detected as the platform "suse" instead of "sles". This matches the behavior of SLES 11 and 12 hosts.

### New Deprecations

#### system_profile Ohai plugin removal

The system_profile plugin will be removed from Chef/Ohai 15 in April 2019. This plugin does not correctly return data on modern Mac systems. Additionally the same data is provided by the hardware plugin, which has a format that is simpler to consume. Removing this plugin will reduce Ohai return by ~3 seconds and greatly reduce the size of the node object on the Chef server.

### Security Updates

#### Ruby 2.5.3

Ruby has been updated to from 2.5.1 to 2.5.3 to resolve multiple CVEs and bugs:

- [CVE-2018-16396](https://www.ruby-lang.org/en/news/2018/10/17/not-propagated-taint-flag-in-some-formats-of-pack-cve-2018-16396/)
- [CVE-2018-16395](https://www.ruby-lang.org/en/news/2018/10/17/openssl-x509-name-equality-check-does-not-work-correctly-cve-2018-16395/)

## What's New in 14.5.33

This release resolves a regression that caused the ``windows_ad_join`` resource to fail to run. It also makes the following additional fixes:

  - The ``ohai`` resource's unused ``ohai_name`` property has been deprecated. This will be removed in Chef Infra Client 15.0.
  - Error messages in the ``windows_feature`` resources have been improved.
  - The ``windows_service`` resource will no longer log potentially sensitive information if the ``sensitive`` property is used.

Thanks to @cpjones01, @kitforbes, and @dgreeninger for their help with this release.

## What's New in 14.5.27

### New Resources

We've added new resources to Chef 14.5. Cookbooks using these resources will continue to take precedent until the Chef Infra Client 15.0 release

#### windows_workgroup

Use the `windows_workgroup` resource to join or change a Windows host workgroup.

See the [windows_workgroup](https://docs.chef.io/resources/windows_workgroup) documentation for more information.

Thanks [@derekgroh](https://github.com/derekgroh) for contributing this new resource.

#### locale

Use the `locale` resource to set the system's locale.

See the [locale](https://docs.chef.io/resources/locale) documentation for more information.

Thanks [@vincentaubert](https://github.com/vincentaubert) for contributing this new resource.

### Updated Resources

#### windows_ad_join

`windows_ad_join` now includes a `new_hostname` property for setting the hostname for the node upon joining the domain.

Thanks [@derekgroh](https://github.com/derekgroh) for contributing this new property.

### InSpec 2.2.102

InSpec has been updated from 2.2.70 to 2.2.102. This new version includes the following improvements:

  - Support for using ERB templating within the .yml files
  - HTTP basic auth support for fetching dependent profiles
  - A new global attributes concept
  - Better error handling with Automate reporting
  - Vendor command now vendors profiles when using path://

### Ohai 14.5

#### Windows Improvements

Detection for the `root_group` attribute on Windows has been simplified and improved to properly support non-English systems. With this change, we've also deprecated the `Ohai::Util::Win32::GroupHelper` helper, which is no longer necessary. Thanks to [@jugatsu](https://github.com/jugatsu) for putting this together.

We've also added a new `encryption_status` attribute to volumes on Windows. Thanks to [@kmf](https://github.com/kmf) for suggesting this new feature.

#### Configuration Improvements

The timeout period for communicating with OpenStack metadata servers can now be configured with the `openstack_metadata_timeout` config option. Thanks to [@sawanoboly](https://github.com/sawanoboly) for this improvement.

Ohai now properly handles relative paths to config files when running on the command line. This means commands like `ohai -c ../client.rb` will now properly use your config values.

### Security updates

#### Rubyzip

The rubyzip gem has been updated to 1.2.2 to resolve [CVE-2018-1000544](https://www.cvedetails.com/cve/CVE-2018-1000544/)

## What's New in 14.4

### Knife configuration profile management commands

Several new commands have been added under `knife config` to help manage multiple
profiles in your `credentials` file.

`knife config get-profile` displays the active profile.

`knife config use-profile PROFILE` sets the workstation-level default
profile. You can still override this setting with the `--profile` command line
option or the `$CHEF_PROFILE` environment variable.

`knife config list-profiles` displays all your available profiles along with
summary information on each.

```bash
$ knife config get-profile
staging
$ knife config use-profile prod
Set default profile to prod
$ knife config list-profiles
 Profile  Client  Key               Server
-----------------------------------------------------------------------------
 staging  myuser  ~/.chef/user.pem  https://example.com/organizations/staging
*prod     myuser  ~/.chef/user.pem  https://example.com/organizations/prod
```

Thank you [@coderanger](https://github.com/coderanger) for this contribution.

### New Resources

The following new previous resources were added to Chef 14.4. Cookbooks with the same resources will continue to take precedent until the Chef Infra Client 15.0 release

#### cron_d

Use the [cron_d](https://docs.chef.io/resources/cron_d) resource to manage cron definitions in /etc/cron.d. This is similar to the `cron` resource, but it does not use the monolithic `/etc/crontab`. file.

#### cron_access

Use the [cron_access](https://docs.chef.io/resources/cron_access) resource to manage the `/etc/cron.allow` and `/etc/cron.deny` files. This resource previously shipped in the `cron` community cookbook and has fully backwards compatibility with the previous `cron_manage` definition in that cookbook.

#### openssl_x509_certificate

Use the [openssl_x509_certificate](https://docs.chef.io/resources/openssl_x509_certificate) resource to generate signed or self-signed, PEM-formatted x509 certificates. If no existing key is specified, the resource automatically generates a passwordless key with the certificate. If a CA private key and certificate are provided, the certificate will be signed with them. This resource previously shipped in the `openssl` cookbook as `openssl_x509` and is fully backwards compatible with the legacy resource name.

Thank you [@juju482](https://github.com/juju482) for updating this resource!

#### openssl_x509_request

Use the [openssl_x509_request](https://docs.chef.io/resources/openssl_x509_request) resource to generate PEM-formatted x509 certificates requests. If no existing key is specified, the resource automatically generates a passwordless key with the certificate.

Thank you [@juju482](https://github.com/juju482) for contributing this resource.

#### openssl_x509_crl

Use the [openssl_x509_crl](https://docs.chef.io/resources/openssl_x509_crl)l resource to generate PEM-formatted x509 certificate revocation list (CRL) files.

Thank you [@juju482](https://github.com/juju482) for contributing this resource.

#### openssl_ec_private_key

Use the [openssl_ec_private_key](https://docs.chef.io/resources/openssl_ec_private_key) resource to generate ec private key files. If a valid ec key file can be opened at the specified location, no new file will be created.

Thank you [@juju482](https://github.com/juju482) for contributing this resource.

#### openssl_ec_public_key

Use the [openssl_ec_public_key](https://docs.chef.io/resources/openssl_ec_public_key) resource to generate ec public key files given a private key.

Thank you [@juju482](https://github.com/juju482) for contributing this resource.

### Resource improvements

#### windows_package

The windows_package resource now supports setting the `sensitive` property to avoid showing errors if a package install fails.

#### sysctl

The sysctl resource will now update the on-disk `sysctl.d` file even if the current sysctl value matches the desired value.

#### windows_task

The windows_task resource now supports setting the task priority of the scheduled task with a new `priority` property. Additionally windows_task now supports managing the behavior of task execution when a system is on battery using new `disallow_start_if_on_batteries` and `stop_if_going_on_batteries` properties.

#### ifconfig

The ifconfig resource now supports setting the interface's VLAN via a new `vlan` property on RHEL `platform_family` and setting the interface's gateway via a new `gateway` property on RHEL/Debian `platform_family`.

Thank you [@tomdoherty](https://github.com/tomdoherty) for this contribution.

#### route

The route resource now supports additional RHEL platform_family systems as well as Amazon Linux.

#### systemd_unit

The [systemd_unit](https://docs.chef.io/resources/systemd_unit) resource now supports specifying options multiple times in the content hash. Instead of setting the value to a string you can now set it to an array of strings.

Thank you [@dbresson](https://github.com/dbresson) for this contribution.

### Security Updates

#### OpenSSL

OpenSSL updated to 1.0.2p to resolve:

- Client DoS due to large DH parameter ([CVE-2018-0732](https://nvd.nist.gov/vuln/detail/CVE-2018-0732))
- Cache timing vulnerability in RSA Key Generation ([CVE-2018-0737](https://nvd.nist.gov/vuln/detail/CVE-2018-0737))

## What's New in 14.3

### New Preview Resources Concept

This release of Chef introduces the concept of Preview Resources. Preview resources behave the same as a standard resource built into Chef, except Chef will load a resource with the same name from a cookbook instead of the built-in preview resource.

What does this mean for you? It means we can introduce new resources in Chef without breaking existing behavior in your infrastructure. For instance if you have a cookbook with a resource named `manage_everything` and a future version of Chef introduced a preview resource named `manage_everything` you will continue to receive the resource from your cookbook. That way outside of a major release your won't experience a potentially breaking behavior change from the newly included resource.

Then when we perform our yearly major release we'll remove the preview designation from all resources, and the built in resources will take precedence over resources with the same names in cookbooks.

### New Resources

#### chocolatey_config

Use the chocolatey_config resource to add or remove Chocolatey configuration keys."

**Actions**

- `set` - Sets a Chocolatey config value.
- `unset` - Unsets a Chocolatey config value.

**Properties**

- `config_key` - The name of the config. We'll use the resource's name if this isn't provided.
- `value` - The value to set.

#### chocolatey_source

Use the chocolatey_source resource to add or remove Chocolatey sources.

**Actions**

- `add` - Adds a Chocolatey source.
- `remove` - Removes a Chocolatey source.

**Properties**

- `source_name` - The name of the source to add. We'll use the resource's name if this isn't provided.
- `source` - The source URL.
- `bypass_proxy` - Whether or not to bypass the system's proxy settings to access the source.
- `priority` - The priority level of the source.

#### powershell_package_source

Use the `powershell_package_source` resource to register a PowerShell package repository.

#### Actions

- `register` - Registers and updates the PowerShell package source.
- `unregister` - Unregisters the PowerShell package source.

**Properties**

- `source_name` - The name of the package source.
- `url` - The url to the package source.
- `trusted` - Whether or not to trust packages from this source.
- `provider_name` - The package management provider for the source. It supports the following providers: 'Programs', 'msi', 'NuGet', 'msu', 'PowerShellGet', 'psl' and 'chocolatey'.
- `publish_location` - The url where modules will be published to for this source. Only valid if the provider is 'PowerShellGet'.
- `script_source_location` - The url where scripts are located for this source. Only valid if the provider is 'PowerShellGet'.
- `script_publish_location` - The location where scripts will be published to for this source. Only valid if the provider is 'PowerShellGet'.

#### kernel_module

Use the kernel_module resource to manage kernel modules on Linux systems. This resource can load, unload, blacklist, install, and uninstall modules.

**Actions**

- `install` - Load kernel module, and ensure it loads on reboot.
- `uninstall` - Unload a kernel module and remove module config, so it doesn't load on reboot.
- `blacklist` - Blacklist a kernel module.
- `load` - Load a kernel module.
- `unload` - Unload kernel module

**Properties**

- `modname` - The name of the kernel module.
- `load_dir` - The directory to load modules from.
- `unload_dir` - The modprobe.d directory.

#### ssh_known_hosts_entry

Use the ssh_known_hosts_entry resource to add an entry for the specified host in /etc/ssh/ssh_known_hosts or a user's known hosts file if specified.

**Actions**

- `create` - Create an entry in the ssh_known_hosts file.
- `flush` - Immediately flush the entries to the config file. Without this the actual writing of the file is delayed in the Chef run so all entries can be accumulated before writing the file out.

**Properties**

- `host` - The host to add to the known hosts file.
- `key` - An optional key for the host. If not provided this will be automatically determined.
- `key_type` - The type of key to store.
- `port` - The server port that the ssh-keyscan command will use to gather the public key.
- `timeout` - The timeout in seconds for ssh-keyscan.
- `mode` - The file mode for the ssh_known_hosts file.
- `owner`- The file owner for the ssh_known_hosts file.
- `group` - The file group for the ssh_known_hosts file.
- `hash_entries` - Hash the hostname and addresses in the ssh_known_hosts file for privacy.
- `file_location` - The location of the ssh known hosts file. Change this to set a known host file for a particular user.

### New `knife config get` command

The `knife config get` command has been added to help with debugging configuration issues with `knife` and other tools that use the `knife.rb` file.

With no arguments, it will display all options you've set:

```bash
$ knife config get
Loading from configuration file /Users/.../.chef/knife.rb
chef_server_url: https://...
client_key:      /Users/.../.chef/user.pem
config_file:     /Users/.../.chef/knife.rb
log_level:       warn
log_location:    STDERR
node_name:       ...
validation_key:
```

You can also pass specific keys to only display those `knife config get node_name client_key`, or use `--all` to display everything (including options that are using the default value).

### Simplification of `shell_out` APIs

The following helper methods have been deprecated in favor of the single shell_out helper:

- `shell_out_with_systems_locale`
- `shell_out_with_timeout`
- `shell_out_compact`
- `shell_out_compact_timeout`
- `shell_out_with_systems_locale!`
- `shell_out_with_timeout!`
- `shell_out_compact!`
- `shell_out_compact_timeout!`

The functionality of `shell_out_with_systems_locale` has been implemented using the `default_env: false` option that removes the PATH and locale mangling that has been the default behavior of `shell_out`.

The functionality of `shell_out_compact` has been folded into `shell_out`. The `shell_out` API when called with varargs has its arguments flatted, compacted and coerced to strings. This style of calling is encouraged over using strings and building up commands using `join(" ")` since it avoids shell interpolation and edge conditions in the construction of spaces between arguments. The varargs form is still not supported on Windows.

The functionality of `shell_out*timeout` has also been folded into `shell_out`. Users writing Custom Resources should be explicit for Chef-14: `shell_out!("whatever", timeout: new_resource.timeout)` which will become automatic in Chef-15.

### Silencing deprecation warnings

While deprecation warnings have been great for the Chef community to ensure cookbooks are kept up-to-date and to prepare for major version upgrades, sometimes you just can't fix a deprecation right now. This is often compounded by the recommendation to enable `treat_deprecation_warnings_as_errors` mode in your Test Kitchen integration tests, which doesn't understand the difference between deprecations from community cookbooks and those from your own code.

Two new options are provided for silencing deprecation warnings: `silence_deprecation_warnings` and inline `chef:silence_deprecation` comments.

The `silence_deprecation_warnings` configuration value can be set in your `client.rb` or `solo.rb` config file, either to `true` to silence all deprecation warnings or to an array of deprecations to silence. You can specify which to silence either by the deprecation key name (e.g. `"internal_api"`), the numeric deprecation ID (e.g. `25` or `"CHEF-25"`), or by specifying the filename and line number where the deprecation is being raised from (e.g. `"default.rb:67"`).

An example of setting the `silence_deprecation_warnings` option in your `client.rb` or `solo.rb`:

```ruby
silence_deprecation_warnings %w{deploy_resource chef-23 recipes/install.rb:22}
```

or in your `kitchen.yml`:

```yaml
provisioner:
  name: chef_solo
  solo_rb:
    treat_deprecation_warnings_as_errors: true
    silence_deprecation_warnings:
    - deploy_resource
    - chef-23
    - recipes/install.rb:22
```

You can also silence deprecations using a comment on the line that is raising the warning:

```ruby
erl_call 'something' do # chef:silence_deprecation
```

We advise caution in the use of this feature, as excessive or prolonged silencing can lead to difficulty upgrading when the next major release of Chef comes out.

### Misc Windows improvements

- A new `skip_publisher_check` property has been added to the `powershell_package` resource
- `windows_feature_powershell` now supports Windows 2008 R2
- The `mount` resource now supports the `mount_point` property on Windows
- `windows_feature_dism` no longer errors when specifying the source
- Resolved idempotency issues in the `windows_task` resource and prevented setting up a task with bad credentials
- `windows_service` no longer throws Ruby deprecation warnings

### Newly Introduced Deprecations

#### CHEF-26: Deprecation of old shell_out APIs

As noted above, this release of Chef unifies our shell_out helpers into just shell_out and shell_out!. Previous helpers are now deprecated and will be removed in Chef Infra Client 15.

See [CHEF-26 Deprecation Page](https://docs.chef.io/deprecations_shell_out) for details.

#### Legacy FreeBSD pkg provider

Chef Infra Client 15 will remove support for the legacy FreeBSD pkg format. We will continue to support the pkgng format introduced in FreeBSD 10.

## What's New in 14.2

### `ssh-agent` support for user keys

You can now use `ssh-agent` to hold your user key when using knife. This allows storing your user key in an encrypted form as well as using `ssh -A` agent forwarding for running knife commands from remote devices.

You can enable this by adding `ssh_agent_signing true` to your `knife.rb` or `ssh_agent_signing = true` in your `credentials` file.

To encrypt your existing user key, you can use OpenSSL:

```
( openssl rsa -in user.pem -pubout && openssl rsa -in user.pem -aes256 ) > user_enc.pem
chmod 600 user_enc.pem
```

This will prompt you for a passphrase for to use to encrypt the key. You can then load the key into your `ssh-agent` by running `ssh-add user_enc.pem`. Make sure you add the `ssh_agent_signing` to your configuration, and update your `client_key` to point at the new, encrypted key (and once you've verified things are working, remember to delete your unencrypted key file).

### default_env Property in Execute Resource

The shell_out helper has been extended with a new option `default_env` to allow disabling Chef from modifying PATH and LOCALE environmental variables as it shells out. This new option defaults to true (modify the env), preserving the previous behavior of the helper.

The execute resource has also been updated with a new property `default_env` that allows utilizing this the ENV sanity functionality in shell_out. The new property defaults to false, but it can be set to true in order to ensure a sane PATH and LOCALE when shelling out. If you find that binaries cannot be found when using the execute resource, `default_env` set to true may resolve those issues.

### Small Size on Disk

Chef now bundles the inspec-core and train-core gems, which omit many cloud dependencies not needed within the Chef client. This change reduces the install size of a typical system by ~22% and the number of files within that installation by ~20% compared to Chef 14.1\. Enjoy the extra disk space.

### Virtualization detection on AWS

Ohai now detects the virtualization hypervisor `amazonec2` when running on Amazon's new C5/M5 instances.

## What's New in 14.1.12

This release resolves a number of regressions in 14.1.1:

- `git` resource: don't use `--prune-tags` as it's really new.
- `rhsm_repo` resource: now works
- `apt_repository` resource: use the `repo_name` property to name files
- `windows_task` resource: properly handle commands with arguments
- `windows_task` resource: handle creating tasks as the SYSTEM user
- `remote_directory` resource: restore the default for the `overwrite` property

### Ohai 14.1.3

- Properly detect FIPS environments
- `shard` plugin: work in FIPS compliant environments
- `filesystem` plugin: Handle BSD platforms

## What's New in 14.1.1

### Platform Additions

Enable Ubuntu-18.04 and Debian-9 tested chef-client packages.

## What's New in 14.1

### Windows Task

The `windows_task` resource has been entirely rewritten. This resolves a large number of bugs, including being able to correctly set the start time of tasks, proper creation and deletion of tasks, and improves Chef's validation of tasks. The rewrite will also solve the idempotency problems that users have reported.

### build_essential

The `build_essential` resource no longer requires a name, similar to the `apt_update` resource.

### Ignore Failure

The `ignore_failure` property takes a new argument, `:quiet`, to suppress the error output when the resource does in fact fail.

### This release of Chef Client 14 resolves a number of regressions in 14.0

- On Windows, the installer now correctly re-extracts files during repair mode
- Fix a number of issues relating to use with Red Hat Satellite
- Git fetch now prunes remotes before running
- Fix locking and unlocking packages with apt and zypper
- Ensure we don't request every remote file when running with lazy loading enabled
- The sysctl resource correctly handles missing keys when used with `ignore_error`
- --recipe-url apparently never worked on Windows. Now it does.

### Security Updates

#### ffi Gem

- CVE-2018-1000201: DLL loading issue which can be hijacked on Windows OS

## Ohai Release Notes 14.1

### Configurable DMI Whitelist

The whitelist of DMI IDs is now user configurable using the `additional_dmi_ids` configuration setting, which takes an Array.

### Shard plugin

The Shard plugin has been returned to a default plugin rather than an optional one. To ensure we work in FIPS environments, the plugin will use SHA256 rather than MD5 in those environments.

### SCSI plugin

A new plugin to enumerate SCSI devices has been added. This plugin is optional.

## What's New in 14.0.202

This release of Chef 14 resolves several regressions in the Chef 14.0 release.

- Resources contained in cookbooks would be used instead of built-in Chef client resources causing older resources to run
- Resources failed due to a missing `property_is_set?` and `resources` methods
- `yum_package` changed the order of `disablerepo` and `enablerepo` options
- Depsolving large numbers of cookbooks with chef zero/local took a very long time

## What's New in 14.0

### New Resources

Chef 14 includes a large number of resources ported from community cookbooks. These resources have been tested, improved, and had their functionality expanded. With these new resources in the Chef Client itself, the need for external cookbook dependencies and dependency management has been greatly reduced.

#### build_essential

Use the build_essential resource to install packages required for compiling C software from source. This resource was ported from the `build-essential` community cookbook.

`Note`: This resource no longer configures msys2 on Windows systems.

#### chef_handler

Use the chef_handler resource to install or uninstall Chef reporting/exception handlers. This resource was ported from the `chef_handler` community cookbook.

#### dmg_package

Use the dmg_package resource to install a dmg 'package'. The resource will retrieve the dmg file from a remote URL, mount it using hdiutil, copy the application (.app directory) to the specified destination (/Applications), and detach the image using hdiutil. The dmg file will be stored in the Chef::Config[:file_cache_path]. This resource was ported from the `dmg` community cookbook.

#### homebrew_cask

Use the homebrew_cask resource to install binaries distributed via the Homebrew package manager. This resource was ported from the `homebrew` community cookbook.

#### homebrew_tap

Use the homebrew_tap resource to add additional formula repositories to the Homebrew package manager. This resource was ported from the `homebrew` community cookbook.

#### hostname

Use the hostname resource to set the system's hostname, configure hostname and hosts config file, and re-run the Ohai hostname plugin so the hostname will be available in subsequent cookbooks. This resource was ported from the `chef_hostname` community cookbook.

#### macos_userdefaults

Use the macos_userdefaults resource to manage the macOS user defaults system. The properties of this resource are passed to the defaults command, and the parameters follow the convention of that command. See the defaults(1) man page for details on how the tool works. This resource was ported from the `mac_os_x` community cookbook.

#### ohai_hint

Use the ohai_hint resource to pass hint data to Ohai to aid in configuration detection. This resource was ported from the `ohai` community cookbook.

#### openssl_dhparam

Use the openssl_dhparam resource to generate dhparam.pem files. If a valid dhparam.pem file is found at the specified location, no new file will be created. If a file is found at the specified location but it is not a valid dhparam file, it will be overwritten. This resource was ported from the `openssl` community cookbook.

#### openssl_rsa_private_key

Use the openssl_rsa_private_key resource to generate RSA private key files. If a valid RSA key file can be opened at the specified location, no new file will be created. If the RSA key file cannot be opened, either because it does not exist or because the password to the RSA key file does not match the password in the recipe, it will be overwritten. This resource was ported from the `openssl` community cookbook.

#### openssl_rsa_public_key

Use the openssl_rsa_public_key resource to generate RSA public key files given a RSA private key. This resource was ported from the `openssl` community cookbook.

#### rhsm_errata

Use the rhsm_errata resource to install packages associated with a given Red Hat Subscription Manager Errata ID. This is helpful if packages to mitigate a single vulnerability must be installed on your hosts. This resource was ported from the `redhat_subscription_manager` community cookbook.

#### rhsm_errata_level

Use the rhsm_errata_level resource to install all packages of a specified errata level from the Red Hat Subscription Manager. For example, you can ensure that all packages associated with errata marked at a 'Critical' security level are installed. This resource was ported from the `redhat_subscription_manager` community cookbook.

#### rhsm_register

Use the rhsm_register resource to register a node with the Red Hat Subscription Manager or a local Red Hat Satellite server. This resource was ported from the `redhat_subscription_manager` community cookbook.

#### rhsm_repo

Use the rhsm_repo resource to enable or disable Red Hat Subscription Manager repositories that are made available via attached subscriptions. This resource was ported from the `redhat_subscription_manager` community cookbook.

#### rhsm_subscription

Use the rhsm_subscription resource to add or remove Red Hat Subscription Manager subscriptions for your host. This can be used when a host's activation_key does not attach all necessary subscriptions to your host. This resource was ported from the `redhat_subscription_manager` community cookbook.

#### sudo

Use the sudo resource to add or remove individual sudo entries using `sudoers.d` files. Sudo version 1.7.2 or newer is required to use the sudo resource, as it relies on the `#includedir` directive introduced in version 1.7.2\. This resource does not enforce installation of the required sudo version. Supported releases of Ubuntu, Debian, SuSE, and RHEL (6+) all support this feature. This resource was ported from the `sudo` community cookbook.

#### swap_file

Use the swap_file resource to create or delete swap files on Linux systems, and optionally to manage the swappiness configuration for a host. This resource was ported from the `swap` community cookbook.

#### sysctl

Use the sysctl resource to set or remove kernel parameters using the sysctl command line tool and configuration files in the system's `sysctl.d` directory. Configuration files managed by this resource are named 99-chef-KEYNAME.conf. If an existing value was already set for the value it will be backed up to the node and restored if the :remove action is used later. This resource was ported from the `sysctl` community cookbook.

`Note`: This resource no longer backs up existing key values to the node when changing values as we have done in the sysctl cookbook previously. The resource has also been renamed from `sysctl_param` to `sysctl` with backwards compatibility for the previous name.

#### windows_ad_join

Use the windows_ad_join resource to join a Windows Active Directory domain and reboot the node. This resource is based on the `win_ad_client` resource in the `win_ad` community cookbook, but is not backwards compatible with that resource.

#### windows_auto_run

Use the windows_auto_run resource to set applications to run at logon. This resource was ported from the `windows` community cookbook.

#### windows_feature

Use the windows_feature resource to add, remove or delete Windows features and roles. This resource calls the `windows_feature_dism` or `windows_feature_powershell` resources depending on the specified installation method and defaults to dism, which is available on both Workstation and Server editions of Windows. This resource was ported from the `windows` community cookbook.

`Note`: These resources received significant refactoring in the 4.0 version of the windows cookbook (March 2018). windows_feature resources now fail if the installation of invalid features is requested and support for installation via server `servermanagercmd.exe` has been removed. If you are using a windows cookbook version less than 4.0 you may need to update cookbooks for Chef 14.

#### windows_font

Use the windows_font resource to install or remove font files on Windows. By default, the font is sourced from the cookbook using the resource, but a URI source can be specified as well. This resource was ported from the `windows` community cookbook.

#### windows_printer

Use the windows_printer resource to setup Windows printers. Note that this doesn't currently install a printer driver. You must already have the driver installed on the system. This resource was ported from the `windows` community cookbook.

#### windows_printer_port

Use the windows_printer_port resource to create and delete TCP/IPv4 printer ports on Windows. This resource was ported from the `windows` community cookbook.

#### windows_shortcut

Use the windows_shortcut resource to create shortcut files on Windows. This resource was ported from the `windows` community cookbook.

#### windows_workgroup

Use the windows_workgroup resource to join a Windows Workgroup and reboot the node. This resource is based on the `windows_ad_join` resource.

### Custom Resource Improvements

We've expanded the DSL for custom resources with new functionality to better document your resources and help users with errors and upgrades. Many resources in Chef itself are now using this new functionality, and you'll see more updated to take advantage of this it in the future.

#### Deprecations in Cookbook Resources

Chef 14 provides new primitives that allow you to deprecate resources or properties with the same functionality used for deprecations in Chef Client resources. This allows you make breaking changes to enterprise or community cookbooks with friendly notifications to downstream cookbook consumers directly in the Chef run.

Deprecate the foo_bar resource in a cookbook:

```ruby
deprecated "The foo_bar resource has been deprecated and will be removed in the next major release of this cookbook scheduled for 12/25/2018!"

property :thing, String, name_property: true

action :create do
 # you'd probably have some actual chef code here
end
```

Deprecate the thing2 property in a resource

```ruby
property :thing2, String, deprecated: 'The thing2 property has been deprecated and will be removed in the next major release of this cookbook scheduled for 12/25/2018!'
```

Rename a property with a deprecation warning for users of the old property name

```ruby
deprecated_property_alias 'thing2', 'the_second_thing', 'The thing2 property was renamed the_second_thing in the 2.0 release of this cookbook. Please update your cookbooks to use the new property name.'
```

#### Platform Deprecations

chef-client no longer is built or tested on OS X 10.10 in accordance with Chef's EOL policy.

#### validation_message

Validation messages allow you give the user a friendly error message when any validation on a property fails.

Provide a friendly message when a regex fails:

```ruby
property :repo_name, String, regex: [/^[^\/]+$/], validation_message: "The repo_name property cannot contain a forward slash '/'",
```

#### Resource Documentation

You can now include documentation that describes how a resource is to be used. Expect this data to be consumed by Chef and other tooling in future releases.

A resource which includes description and introduced values in the resource, actions, and properties:

```ruby
description 'The apparmor_policy resource is used to add or remove policy files from a cookbook file'
introduced '14.1'

property :source_cookbook, String,
         description: 'The cookbook to source the policy file from'
property :source_filename, String,
         description: 'The name of the source file if it differs from the apparmor.d file being created'

action :add do
  description 'Adds an apparmor policy'

  # you'd probably have some actual chef code here
end
```

### Improved Resources

Many existing resources now include new actions and properties that expand their functionality.

#### apt_package

`apt_package` includes a new `overwrite_config_files` property. Setting this new property to true is equivalent to passing `-o Dpkg::Options::="--force-confnew"` to apt, and allows you to install packages that prompt the user to overwrite config files. Thanks @ccope for this new property.

#### env

The `env` resource has been renamed to `windows_env` as it only supports the Windows platform. Existing cookbooks using `env` will continue to function, but should be updated to use the new name.

#### ifconfig

`ifconfig` includes a new `family` property for setting the network family on Debian systems. Thanks @martinisoft for this new property.

#### registry_key

The `sensitive` property can now be used in `registry_key` to suppress the output of the key's data from logs and error messages. Thanks @shoekstra for implementing this.

#### powershell_package

`powershell_package` includes a new `source` property to allow specifying the source of the package. Thanks @Happycoil for this new property.

#### systemd_unit

`systemd_unit` includes the following new actions:

- `preset` - Restore the preset enable/disable configuration for a unit
- `revert` - Revert to a vendor's version of a unit file
- `reenable` - Reenable a unit file

Thanks @nathwill for these new actions.

#### windows_service

`windows_service` now includes actions for fully managing services on Windows, in addition to the previous actions for starting/stopping/enabling services.

- `create` - Create a new service
- `delete` - Delete an existing service
- `configure` - Reconfigure an existing service

Thanks @jasonwbarnett for these new actions

#### route

`route` includes a new `comment` property.

Thanks Thomas Doherty for adding this new property.

### Expanded Configuration Detection

Ohai has been expanded to collect more information than ever. This should make writing cross-platform and cross cloud cookbooks simpler.

#### Windows Kernel information

The kernel plugin now reports the following information on Windows:

- `node['kernel']['product_type']` - Workstation vs. Server editions of Windows
- `node['kernel']['system_type']` - What kind of hardware are we installed on (Desktop, Mobile, Workstation, Enterprise Server, etc.)
- `node['kernel']['server_core']` - Are we on Windows Server Core edition?

#### Cloud Detection

Ohai now detects the Scaleway cloud and provides additional configuration information for systems running on Azure.

#### Virtualization / Container Detection

In addition to detecting if a system is a Docker host, we now provide a large amount of Docker configuration information available at `node['docker']`. This includes the release of Docker, installed plugins, network config, and the number of running containers.

Ohai also now properly detects LXD containers and macOS guests running on VirtualBox / VMware. This data is available in `node['virtualization']['systems']`.

#### Optional Ohai Plugins

Ohai now includes the ability to mark plugins as optional, which skips those plugins by default. This allows us to ship additional plugins, which some users may find useful, but not all users want that data collected in the node object on a Chef server. The change introduces two new configuration options; `run_all_plugins` which runs everything including optional plugins, and `optional_plugins` which allows you to run plugins marked as optional.

By default we will now be marking the `lspci`, `sessions` `shard` and `passwd` plugins as optional. Passwd has been particularly problematic for nodes attached to LDAP or AD where it attempts to write the entire directory's contents to the node. If you previously disabled this plugin via Ohai config, you no longer need to. Hurray!

### Other Changes

#### Ruby 2.5

Ruby has been updated to version 2.5 bringing a 10% performance improvement and improved functionality.

#### InSpec 2.0

InSpec has been updated to the 2.0 release. InSpec 2.0 brings compliance automation to the cloud, with new resource types specifically built for AWS and Azure clouds. Along with these changes are major speed improvements and quality of life updates. Please visit <https://docs.chef.io/inspec/> for more information.

#### Policyfile Hoisting

Many users of Policyfiles rely on "hoisting" to provide group specific attributes. This approach was formalized in the poise-hoist extension, and is now included in Chef 14.

To hoist an attribute, the user provides a default attribute structure in their Policyfile similar to:

```ruby
default['staging']['myapp']['title'] = "My Staging App" default['production']['myapp']['title'] = "My App"
```

and then accesses the node attribute in their cookbook as:

```ruby
node['myapp']['title']
```

The correct attribute is then provided based on the policy_group of the node, so with a policy_group of staging the attribute would contain "My Staging App".

#### yum_package rewrite

yum_package received a ground up rewrite that greatly improves both the performance and functionality while also resolving a dozen existing issues. It introduces a new caching method that runs for the duration of the chef-client process. This caching method speeds up each package install and takes 1/2 the memory of the previous `yum-dump.py` process.

yum_package should now take any argument that `yum install` does and operate the same way, including version constraints "foo < 1.2.3" and globs "foo-1.2*" along with arches "foo.i386" and in combinations

Package with a version constraint:

```ruby
yum_package "foo < 1.2.3"
```

Installing a package via what it provides:

```ruby
yum_package "perl(Git)"
```

#### powershell_exec Mixin

Since our supported Windows platforms can all run .NET Framework 4.0 and PowerShell 4.0 we have taken time to add a new helper that will allow for faster and safer interactions with the system PowerShell. You will be able to use the powershell_exec mixin in most places where you would have previously used powershell_out. For comparison, a basic benchmark test to return the $PSVersionTable 100 times completed 7.3X faster compared to the powershell_out method. The majority of the time difference is because of less time spent in invocation. So we believe it has big future potential where multiple calls to PowerShell are required inside (for example) a custom resource. Many core Chef resources will be updated to use this new mixin in future releases.

#### Logging Improvements

Chef now includes a new log level of `:trace` in addition to the existing `:info`, `:warn`, and `:debug` levels. With the introduction of `trace` level logging we've moved a large amount of logging that is more useful for Chef developers from `debug` to `trace`. This makes it easier for Chef Cookbook developers to use `debug` level to get useful information.

### Security Updates

#### OpenSSL

OpenSSL has been updated to 1.0.2o to resolve [CVE-2018-0739](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-0739)

#### Ruby

Ruby has been updated to 2.5.1 to resolve the following vulnerabilities:

- [CVE-2017-17742](https://www.ruby-lang.org/en/news/2018/03/28/http-response-splitting-in-webrick-cve-2017-17742/)
- [CVE-2018-6914](https://www.ruby-lang.org/en/news/2018/03/28/unintentional-file-and-directory-creation-with-directory-traversal-cve-2018-6914/)
- [CVE-2018-8777](https://www.ruby-lang.org/en/news/2018/03/28/large-request-dos-in-webrick-cve-2018-8777/)
- [CVE-2018-8778](https://www.ruby-lang.org/en/news/2018/03/28/buffer-under-read-unpack-cve-2018-8778/)
- [CVE-2018-8779](https://www.ruby-lang.org/en/news/2018/03/28/poisoned-nul-byte-unixsocket-cve-2018-8779/)
- [CVE-2018-8780](https://www.ruby-lang.org/en/news/2018/03/28/poisoned-nul-byte-dir-cve-2018-8780/)
- [Multiple vulnerabilities in rubygems](https://www.ruby-lang.org/en/news/2018/02/17/multiple-vulnerabilities-in-rubygems/)

### Breaking Changes

This release completes the deprecation process for many of the deprecations that were warnings throughout the Chef 12 and Chef 13 releases.

#### erl_call Resource

The erl_call resource was deprecated in Chef 13.7 and has been removed.

#### deploy Resource

The deploy resource was deprecated in Chef 13.6 and been removed. If you still require this resource, it is available in the new `deploy_resource` cookbook at <https://supermarket.chef.io/cookbooks/deploy_resource>

#### Windows 2003 Support

Support for Windows 2003 has been removed from both Chef and Ohai, improving the performance of Chef on Windows hosts.

#### knife deprecations

- `knife bootstrap` options `--distro` and `--template_file` flags were deprecated in Chef 12 and have now been removed.
- `knife help` functionality that read legacy Chef manpages has been removed as the manpages had not been updated and were often quite wrong. Running knife help will now simply show the help menu.
- `knife index rebuild` has been removed as reindexing Chef Server was only necessary on releases prior to Chef Server 11.
- The `knife ssh --identity-file` flag was deprecated and has been removed. Users should use the `--ssh_identity_file` flag instead.
- `knife ssh csshx` was deprecated in Chef 10 and has been removed. Users should use `knife ssh cssh` instead.

#### Chef Solo `-r` flag

The Chef Solo `-r` flag has been removed as it was deprecated and replaced with the `--recipe-url` flag in Chef 12.

#### node.set and node.set_unless attribute levels removal

`node.set` and `node.set_unless` were deprecated in Chef 12 and have been removed in Chef 14\. To replicate this same functionality users should use `node.normal` and `node.normal_unless`, although we highly recommend reading our [attribute documentation](https://docs.chef.io/attributes) to make sure `normal` is in fact the your desired attribute level.

#### chocolatey_package :uninstall Action

The chocolatey_package resource in the chocolatey cookbook supported an `:uninstall` action. When this resource was moved into the Chef Client we allowed this action with a deprecation warning. This action is now removed.

#### Property names not using new_resource.NAME

Previously if a user wrote a custom resource with a property named `foo` they could reference it throughout the resource using the name `foo`. This caused multiple edge cases where the property name could conflict with resources or methods in Chef. Properties now must be referenced as `new_resource.foo`. This was already the case when writing LWRPs.

#### epic_fail

The original name for the `ignore_failure` property in resource was `epic_fail`. The legacy name has been removed.

#### Legacy Mixins

Several legacy mixins mostly used in older HWRPs have been removed. Usage of these mixins has resulted in deprecation warnings for several years and they are rarely used in cookbooks available on the Supermarket.

- Chef::Mixin::LanguageIncludeAttribute
- Chef::Mixin::RecipeDefinitionDSLCore
- Chef::Mixin::LanguageIncludeRecipe
- Chef::Mixin::Language
- Chef::DSL::Recipe::FullDSL

#### cloud_v2 and filesystem2 Ohai Plugins

In Chef 13 the `cloud_v2` plugin replaced data at `node['cloud']` and `filesystem2` replaced data at `node['filesystem']`. For compatibility with cookbooks that were previously using the "v2" data we continued to write data to both locations (ie: both node['filesystem'] and node['filesystem2']). We now no longer write data to the "v2" locations which greatly reduces the amount of data we need to store on the Chef server.

#### Ipscopes Ohai Plugin Removed

The ipscopes plugin has been removed as it duplicated data already present in the network plugins and required the user to install an additional gem into the Chef installation.

#### Ohai libvirt attributes moved

The libvirt Ohai plugin now writes data to `node['libvirt']` instead of writing to various locations in `node['virtualization']`. This plugin required installing an additional gem into the Chef installation and thus was infrequently used.

#### Ohai Plugin V6 Support Removed

In 2014 we introduced Ohai v7 with a greatly improved plugin format. With Chef 14 we no longer support loading of the legacy "v6" plugin format.

#### Newly-disabled Ohai Plugins

As mentioned above we now support an `optional` flag for Ohai plugins and have marked the `sessions`, `lspci`, and `passwd` plugins as optional, which disables them by default. If you need one of these plugins you can include them using `optional_plugins`.

optional_plugins in the client.rb file:

```ruby
optional_plugins [ "lspci", "passwd" ]
```

## What's New in 13.12.14

### Bugfixes

- The mount provider now properly adds blank lines between fstab entries on AIX
- Ohai now reports itself as Ohai well communicating with GCE metadata endpoints
- Property deprecations in custom resources no longer result in an error. Thanks for reporting this [martinisoft](https://github.com/martinisoft)
- mixlib-archive has been updated to prevent corruption of archives on Windows systems

### Updated Components

- libxml2 2.9.7 -> 2.9.9
- ca-certs updated to 2019-01-22 for new roots
- nokogiri 1.8.5 -> 1.10.1

### Security Updates

#### OpenSSL

OpenSSL has been updated to 1.0.2r in order to resolve [CVE-2019-1559](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1559) and [CVE-2018-5407](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5407)

#### RubyGems

RubyGems has been updated to 2.7.9 in order to resolve the following CVEs:

- [CVE-2019-8320](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8320): Delete directory using symlink when decompressing tar
- [CVE-2019-8321](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8321): Escape sequence injection vulnerability in verbose
- [CVE-2019-8322](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8322): Escape sequence injection vulnerability in gem owner
- [CVE-2019-8323](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8323): Escape sequence injection vulnerability in API response handling
- [CVE-2019-8324](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8324): Installing a malicious gem may lead to arbitrary code execution
- [CVE-2019-8325](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8325): Escape sequence injection vulnerability in errors

## What's New in 13.12.3

### Smaller Package and Install Size

We trimmed unnecessary installation files, greatly reducing the sizes of both Chef packages and on disk installations. MacOS/Linux/FreeBSD packages are ~50% smaller and Windows are ~12% smaller. Chef 13 is now smaller than a legacy Chef 10 package.

### macOS Mojave (10.14)

Chef is now tested against macOS Mojave and packages are now available at downloads.chef.io.

### SUSE Linux Enterprise Server 15

- Ohai now properly detects SLES 15
- The Chef package will no longer remove symlinks to chef-client and ohai when upgrading on SLES 15

### Updated Chef-Vault

Updating chef-vault to 3.4.2 resolved multiple bugs.

### Faster Windows Installations

Improved Windows installation speed by skipping unnecessary steps when Windows Installer 5.0 or later is available.

### Ohai Release Notes 13.12

#### macOS Improvements

- sysctl commands have been modified to gather only the bare minimum required data, which prevents sysctl hanging in some scenarios
- Extra data has been removed from the system_profile plugin, reducing the amount of data stored on the chef-server for each node

### New Deprecations

#### system_profile Ohai plugin removal

The system_profile plugin will be removed from Chef/Ohai 15 in April, 2019. This plugin incorrectly returns data on modern Mac systems. Further, the hardware plugin returns the same data in a more readily consumable format. Removing this plugin reduces the speed of the Ohai return by ~3 seconds and also greatly reduces the node object size on the Chef server

#### ohai_name property in ohai resource

The ``ohai`` resource's unused ``ohai_name`` property has been deprecated. This will be removed in Chef Infra Client 15.0.

### Security Updates

#### Ruby 2.4.5

Ruby has been updated to from 2.4.4 to 2.4.5 to resolve multiple CVEs as well as bugs:

- [CVE-2018-16396](https://www.ruby-lang.org/en/news/2018/10/17/not-propagated-taint-flag-in-some-formats-of-pack-cve-2018-16396/)
- [CVE-2018-16395](https://www.ruby-lang.org/en/news/2018/10/17/openssl-x509-name-equality-check-does-not-work-correctly-cve-2018-16395/)

## What's New in 13.11

### Sensitive Properties on Windows

- `windows_service` no longer logs potentially sensitive information when a service is setup
- `windows_package` now respects the `sensitive` property to avoid logging sensitive data in the event of a package installation failure

### Other Fixes

- `remote_directory` now properly loads files in the root of a cookbook's `files` directory
- `osx_profile` now uses the full path the profiles CLI tool to avoid running other binaries of the same name in a users path
- `package` resources that don't support the `allow_downgrade` property will no longer fail
- `knife bootstrap windows` error messages have been improved

### Security Updates

#### OpenSSL

- OpenSSL has been updated to 1.0.2p to resolve [CVE-2018-0732](https://nvd.nist.gov/vuln/detail/CVE-2018-0732) and [CVE-2018-0737](https://nvd.nist.gov/vuln/detail/CVE-2018-0737)

#### Rubyzip

- Updated Rubyzip to 1.2.2 to resolve [CVE-2018-1000544](https://nvd.nist.gov/vuln/detail/CVE-2018-1000544)

## What's New in 13.10

### Bugfixes

- Resolves a duplicate logging getting created when redirecting stdout
- Using --recipe-url with a local file on Windows no longer fails
- Service resource no longer throws Ruby deprecation warnings on Windows

### Ohai 13.10 Improvements

- Correctly identify the platform_version on the final release of Amazon Linux 2.0
- Detect nodes with the DMI data of "OpenStack Compute" as being OpenStack nodes

### Security Updates

#### ffi Gem

- CVE-2018-1000201: DLL loading issue which can be hijacked on Windows OS

## What's New in 13.9.4

### Platform Updates

As Debian 7 is now end of life we will no longer produce Debian 7 chef-client packages.

### Ifconfig on Ubuntu 18.04

Incompatibilities with Ubuntu 18.04 in the ifconfig resource have been resolved.

### Ohai Updated to 13.9.2

#### Virtualization detection on AWS

Ohai now detects the virtualization hypervisor `amazonec2` when running on Amazon's new C5/M5 instances.

#### Configurable DMI Whitelist

The whitelist of DMI IDs is now user configurable using the `additional_dmi_ids` configuration setting, which takes an Array.

#### Filesystem2 on BSD

The Filesystem2 functionality has been backported to BSD systems to provide a consistent filesystem format.

### Security Updates

#### Ruby updated to 2.4.4

- [CVE-2017-17742](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17742/): HTTP response splitting in WEBrick
- [CVE-2018-6914](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6914/): Unintentional file and directory creation with directory traversal in tempfile and tmpdir
- [CVE-2018-8777](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-8777/): DoS by large request in WEBrick
- [CVE-2018-8778](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-8778/): Buffer under-read in String#unpack
- [CVE-2018-8779](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-8779/): Unintentional socket creation by poisoned NUL byte in UNIXServer and UNIXSocket
- [CVE-2018-8780](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-8780/): Unintentional directory traversal by poisoned NUL byte in Dir
- Multiple vulnerabilities in RubyGems

#### Nokogiri updated to 1.8.2

- Behavior in libxml2 has been reverted which caused CVE-2018-8048 (loofah gem), CVE-2018-3740 (sanitize gem), and CVE-2018-3741 (rails-html-sanitizer gem).

#### OpenSSL updated to 1.0.2o

- CVE-2018-0739: Constructed ASN.1 types with a recursive definition could exceed the stack.

## What's New in 13.9.1

## Platform Additions

Enable Ubuntu-18.04 and Debian-9 tested chef-client packages.

## What's New in 13.9.0

- On Windows, the installer now correctly re-extracts files during repair mode
- The mount resource will now not create duplicate entries when the device type differs
- Ensure we don't request every remote file when running with lazy loading enabled
- Don't crash when getting the access rights for Windows system accounts

### Custom Resource Improvements

We've expanded the DSL for custom resources with new functionality to better document your resources and help users with errors and upgrades. Many resources in Chef itself are now using this new functionality, and you'll see more updated to take advantage of this it in the future.

### Deprecations in Cookbook Resources

Chef 13 provides new primitives that allow you to deprecate resources or properties with the same functionality used for deprecations in Chef Client resources. This allows you make breaking changes to enterprise or community cookbooks with friendly notifications to downstream cookbook consumers directly in the Chef run.

Deprecate the foo_bar resource in a cookbook:

```ruby
deprecated "The foo_bar resource has been deprecated and will be removed in the next major release of this cookbook scheduled for 12/25/2018!"

property :thing, String, name_property: true

action :create do
 # you'd probably have some actual chef code here
end
```

Deprecate the thing2 property in a resource

```ruby
property :thing2, String, deprecated: 'The thing2 property has been deprecated and will be removed in the next major release of this cookbook scheduled for 12/25/2018!'
```

Rename a property with a deprecation warning for users of the old property name

```ruby
deprecated_property_alias 'thing2', 'the_second_thing', 'The thing2 property was renamed the_second_thing in the 2.0 release of this cookbook. Please update your cookbooks to use the new property name.'
```

### validation_message

Validation messages allow you give the user a friendly error message when any validation on a property fails.

Provide a friendly message when a regex fails:

```ruby
property :repo_name, String, regex: [/^[^\/]+$/], validation_message: "The repo_name property cannot contain a forward slash '/'",
```

### Resource Documentation

You can now include documentation that describes how a resource is to be used. Expect this data to be consumed by Chef and other tooling in future releases.

A resource which includes description and introduced values in the resource, actions, and properties:

```ruby
description 'The apparmor_policy resource is used to add or remove policy files from a cookbook file'
 introduced '14.1'

 property :source_cookbook, String,
         description: 'The cookbook to source the policy file from'
 property :source_filename, String,
         description: 'The name of the source file if it differs from the apparmor.d file being created'

 action :add do
   description 'Adds an apparmor policy'

   # you'd probably have some actual chef code here
 end
```

### Ohai Improvements

- Fix uptime parsing on AIX
- Fix Softlayer cloud detection
- Use the current Azure metadata endpoint
- Correctly detect macOS guests on VMware and VirtualBox
- Please see the [Ohai Changelog](https://github.com/chef/ohai/blob/master/CHANGELOG.md) for the complete list of changes.

## What's New in 13.8.5

This is a small bug fix release to resolve two issues we found in the
13.8 release:

- chef-client run failures due to a failure in a newer version of the FFI gem on RHEL 6.x and 7.x
- knife failures when running `knife cookbook site install` to install a deprecated cookbook that has no replacement

## What's New in 13.8.3

This is a small bug fix release that updates Ohai to properly detect and
poll SoftLayer metadata now that SoftLayer no longer supports TLS
1.0/1.1. This update is only necessary if you're running on Softlayer.

## What's New in 13.8.0

### Revert attributes changes from 13.7

Per <https://discourse.chef.io/t/regression-in-chef-client-13-7-16/12518/1> , there was a regression in how arrays and hashes were handled in 13.7\. In 13.8, we've reverted to the same code as 13.6.

### Continuing work on `windows_task`

13.8 has better validation for the `idle_time` property, when using the `on_idle` frequency.

### Security Updates

- Updated libxml2 to 2.9.7; fixes: [CVE-2017-15412](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-15412)

## What's New in 13.7.16

### The `windows_task` Resource should be better behaved

We've spent a considerable amount of time testing and fixing the `windows_task` resource to ensure that it is properly idempotent and correct in more situations.

### Credentials handling

Previously, the `knife` CLI used `knife.rb` or `config.rb` to handle credentials. This didn't do a great job when interacting with multiple Chef servers, leading to the need for tools like `knife_block`. We've added support for a credentials file that can contain configuration for many Chef servers (or organizations), and we've made it easy to indicate which account you mean to use.

### New deprecations

#### `erl_call` Resource

We introduced `erl_call` to help us to manage CouchDB servers back in the olden times of Chef. Since then, we've noticed that no-one uses it, and so `erl_call` will be removed in Chef 14. Foodcritic rule [FC105(http://www.foodcritic.io/#FC105) has been introduced to detect usage of erl_call.

#### epic_fail

The original name for the ignore_failure property in resources was epic_fail. Our documentation hasn't referred to epic_fail for years and out of the 3500 cookbooks on the Supermarket only one uses epic_fail. In Chef 14 we will remove the epic_fail property entirely. Foodcritic rule [FC107](http://www.foodcritic.io/#FC107) has been introduced to detect usage of epic_fail.

#### Legacy Mixins

In Chef 14 several legacy mixins will be removed. Usage of these mixins has resulted in deprecation warnings for several years. They were traditionally used in some HWRPs, but are rarely found in code available on the Supermarket. Foodcritic rules [FC097](http://www.foodcritic.io/#FC097), [FC098](http://www.foodcritic.io/#FC098), [FC099](http://www.foodcritic.io/#FC099), [FC100](http://www.foodcritic.io/#FC100), and [FC102](http://www.foodcritic.io/#FC102) have been introduced to detect these mixins:

- `Chef::Mixin::LanguageIncludeAttribute`
- `Chef::Mixin::RecipeDefinitionDSLCore`
- `Chef::Mixin::LanguageIncludeRecipe`
- `Chef::Mixin::Language`
- `Chef::DSL::Recipe::FullDSL`

### :uninstall action in chocolatey_package

The chocolatey cookbook's chocolatey_package resource originally contained an :uninstall action. When chocolatey_package was moved into core Chef we made :uninstall an alias for :remove. In Chef 14 :uninstall will no longer be a valid action. Foodcritic rule [FC103](http://www.foodcritic.io/#FC103) has been introduced to detect the usage of the :uninstall action.

## Bugfixes

- Resolved a bug where knife commands that prompted on Windows would never display the prompt
- Fixed hiding of sensitive resources when converge_if_changed was used
- Fixed scenarios where services would fail to start on Solaris

### Security Updates

- OpenSSL has been upgraded to 1.0.2n to resolve [CVE-2017-3738](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-3738), [CVE-2017-3737](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-3737), [CVE-2017-3736](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-3736), and [CVE-2017-3735](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-3735).
- Ruby has been upgraded to 2.4.3 to resolve [CVE-2017-17405](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17405)

### Ohai 13.7

#### Network Tunnel Information

The Network plugin on Linux hosts now gathers additional information on tunnels

#### LsPci Plugin

The new LsPci plugin provides a `node[:pci]` hash with information about the PCI bus based on `lspci`. Only runs on Linux.

#### EC2 C5 Detection

The EC2 plugin has been updated to properly detect the new AWS hypervisor used in the C5 instance types

#### mdadm

The mdadm plugin has been updated to properly handle arrays with more than 10 disks and to properly handle journal and spare drives in the disk counts

## What's New in 13.6.4

### Bugfixes

- Resolved a regression in 13.6.0 that prevented upgrading packages on Debian/Ubuntu when the package name contained a tilde.

### Security Updates

- OpenSSL has been upgraded to 1.0.2m to resolve [CVE-2017-3735](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-3735) and [CVE-2017-3736](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-3736)
- RubyGems has been upgraded to 2.6.14 to resolve [CVE-2017-0903](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0903)

## What's New in 13.6.0

### `deploy` Resource Is Deprecated

The `deploy` resource (and its alter ego `deploy_revision`) have been deprecated, to be removed in Chef 14. This is being done because this resource is considered overcomplicated and error-prone in the modern Chef ecosystem. A compatibility cookbook will be available to help users migrate during the Chef 14 release cycle. See [the deprecation documentation](https://docs.chef.io/deprecations_deploy_resource) for more information.

### zypper_package supports package downgrades

`zypper_package` now supports downgrading installed packages with the `allow_downgrade` property.

### InSpec updated to 1.42.3

### Reserve certain Data Bag names

It's no longer possible to create data bags named `node`, `role`, `client`, or `environment`. Existing data bags will continue to work as before.

### Properly use yum on RHEL 7

If both dnf and yum were installed, in some circumstances the yum provider might choose to run dnf, which is not what we intended it to do. It now properly runs yum, all the time.

### Ohai 13.6

#### Critical Plugins

Users can now specify a list of plugins which are `critical`. Critical plugins will cause Ohai to fail if they do not run successfully (and thus cause a Chef run using Ohai to fail). The syntax for this is:

```ruby
ohai.critical_plugins << :Filesystem
```

#### Filesystem now has a `allow_partial_data` configuration option

The Filesystem plugin now has a `allow_partial_data` configuration option. If set, the filesystem will return whatever data it can even if some commands it ran failed.

#### Rackspace detection on Windows

Windows nodes running on Rackspace will now properly detect themselves as running on Rackspace without a hint file.

#### Package data on Amazon Linux

The Packages plugin now supports gathering packages data on Amazon Linux

#### Deprecation updates

In Ohai 13 we replaced the filesystem and cloud plugins with the filesystem2 and cloud_v2 plugins. To maintain compatibility with users of the previous V2 plugins we write data to both locations. We had originally planned to continue writing data to both locations until Chef Infra Client 15. Instead due to the large amount of duplicate node data this introduces we are updating OHAI-11 and OHAI-12 deprecations to remove node['cloud_v2'] and node['filesystem2'] with the release of Chef 14 in April 2018.

## What's New in 13.5

- **The mount resource's password property is now marked as **sensitive** Passwords passed to mount won't show up in logs.
- **The windows_task resource now correctly handles start_day** Previously, the resource would accept any date that was formatted correctly in the local locale, unlike the Windows cookbook and Windows itself. We now support only the MM/DD/YYYY format, in keeping with the Windows cookbook.
-   **InSpec updated to 1.39.1**

### Ohai 13.5

### Correctly detect IPv6 routes ending in ::

Previously we would ignore routes that ended `::`, and now we properly detect them.

### Plugin run time is now measured

Debug logs will show the length of time each plugin takes to run, making debugging of long ohai runs easier.

## What's New in 13.4.24

### Security

This release includes Ruby 2.4.2 to fix the following CVEs:

- [CVE-2017-0898](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0898)
- [CVE-2017-10784](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-10784)
- [CVE-2017-14033](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14033)
- [CVE-2017-14064](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14064)

## What's New in 13.4.19

### Security release of RubyGems

Chef Client 13.4 includes RubyGems 2.6.13 to fix the following CVEs:

- [CVE-2017-0899](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0899)
- [CVE-2017-0900](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0900)
- [CVE-2017-0901](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0901)
- [CVE-2017-0902](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0902)

### Ifconfig provider on Red Hat now supports additional properties

It is now possible to set `ETHTOOL_OPTS`, `BONDING_OPTS`, `MASTER` and `SLAVE` properties on interfaces on Red Hat compatible systems. See <https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Deployment_Guide/s1-networkscripts-interfaces.html> for further information

#### Properties

- `ethtool_opts`<br>
  **Ruby types:** String<br>
  **Platforms:*- Fedora, RHEL, Amazon Linux A string containing arguments to ethtool. The string will be wrapped in double quotes, so ensure that any needed quotes in the property are surrounded by single quotes

- `bonding_opts`<br>
  **Ruby types:** String<br>
  **Platforms:*- Fedora, RHEL, Amazon Linux A string containing configuration parameters for the bonding device.

- `master`<br>
  **Ruby types:** String<br>
  **Platforms:*- Fedora, RHEL, Amazon Linux The channel bonding interface that this interface is linked to.

- `slave`<br>
  **Ruby types:** String<br>
  **Platforms:*- Fedora, RHEL, Amazon Linux Whether the interface is controlled by the channel bonding interface defined by `master`, above.

### Chef Vault is now included

Chef Client 13.4 now includes the `chef-vault` gem, making it easier for users of chef-vault to use their encrypted items.

### Windows `remote_file` resource with alternate credentials

The `remote_file` resource now supports the use of credentials on Windows when accessing a remote UNC path on Windows such as `\\myserver\myshare\mydirectory\myfile.txt`. This allows access to the file at that path location even if the Chef client process identity does not have permission to access the file. The new properties `remote_user`, `remote_domain`, and `remote_password` may be used to specify credentials with access to the remote file so that it may be read.

**Note**: This feature is mainly used for accessing files between two nodes in different domains and having different user accounts. In case the two nodes are in same domain, `remote_file` resource does not need `remote_user` and `remote_password` specified because the user has the same access on both systems through the domain.

#### Properties

The following properties are new for the `remote_file` resource:

- `remote_user`<br>
  **Ruby types:** String<br>
  _Windows only:_ The user name of a user with access to the remote file specified by the `source` property. Default value: `nil`. The user name may optionally be specified with a domain, i.e. `domain\user` or `user@my.dns.domain.com` via Universal Principal Name (UPN) format. It can also be specified without a domain simply as `user` if the domain is instead specified using the `remote_domain` attribute. Note that this property is ignored if `source` is not a UNC path. If this property is specified, the `remote_password` property **must*- be specified.

- `remote_password`<br>
  **Ruby types*- String<br>
  _Windows only:_ The password of the user specified by the `remote_user` property. Default value: `nil`. This property is mandatory if `remote_user` is specified and may only be specified if `remote_user` is specified. The `sensitive` property for this resource will automatically be set to `true` if `remote_password` is specified.

- `remote_domain`<br>
  **Ruby types*- String<br>
  _Windows only:_ The domain of the user user specified by the `remote_user` property. Default value: `nil`. If not specified, the user and password properties specified by the `remote_user` and `remote_password` properties will be used to authenticate that user against the domain in which the system hosting the UNC path specified via `source` is joined, or if that system is not joined to a domain it will authenticate the user as a local account on that system. An alternative way to specify the domain is to leave this property unspecified and specify the domain as part of the `remote_user` property.

#### Examples

Accessing file from a (different) domain account

```ruby
remote_file "E://domain_test.txt"  do
  source  "\\\\myserver\\myshare\\mydirectory\\myfile.txt"
  remote_domain "domain"
  remote_user "username"
  remote_password "password"
end
```

OR

```ruby
remote_file "E://domain_test.txt"  do
  source  "\\\\myserver\\myshare\\mydirectory\\myfile.txt"
  remote_user "domain\\username"
  remote_password "password"
end
```

Accessing file using a local account on the remote machine

```ruby
remote_file "E://domain_test.txt"  do
  source  "\\\\myserver\\myshare\\mydirectory\\myfile.txt"
  remote_domain "."
  remote_user "username"
  remote_password "password"
end
```

OR

```ruby
remote_file "E://domain_test.txt"  do
  source  "\\\\myserver\\myshare\\mydirectory\\myfile.txt"
  remote_user ".\\username"
  remote_password "password"
end
```

### windows_path resource

`windows_path` resource has been moved to core chef from windows cookbook. Use the `windows_path` resource to manage the path environment variable on Microsoft Windows.

#### Actions

- `:add` - Add an item to the system path
- `:remove` - Remove an item from the system path

#### Properties

- `path` - Name attribute. The name of the value to add to the system path

#### Examples

Add Sysinternals to the system path

```ruby
windows_path 'C:\Sysinternals' do
  action :add
end
```

Remove 7-Zip from the system path

```ruby
windows_path 'C:\7-Zip' do
  action :remove
end
```

### Ohai 13.4

#### Windows EC2 Detection

Detection of nodes running in EC2 has been greatly improved and should now detect nodes 100% of the time including nodes that have been migrated to EC2 or were built with custom AMIs.

#### Azure Metadata Endpoint Detection

Ohai now polls the new Azure metadata endpoint, giving us additional configuration details on nodes running in Azure

Sample data now available under azure:

```javascript
{
  "metadata": {
    "compute": {
      "location": "westus",
      "name": "timtest",
      "offer": "UbuntuServer",
      "osType": "Linux",
      "platformFaultDomain": "0",
      "platformUpdateDomain": "0",
      "publisher": "Canonical",
      "sku": "17.04",
      "version": "17.04.201706191",
      "vmId": "8d523242-71cf-4dff-94c3-1bf660878743",
      "vmSize": "Standard_DS1_v2"
    },
    "network": {
      "interfaces": {
        "000D3A33AF03": {
          "mac": "000D3A33AF03",
          "public_ipv6": [

          ],
          "public_ipv4": [
            "52.160.95.99",
            "23.99.10.211"
          ],
          "local_ipv6": [

          ],
          "local_ipv4": [
            "10.0.1.5",
            "10.0.1.4",
            "10.0.1.7"
          ]
        }
      },
      "public_ipv4": [
        "52.160.95.99",
        "23.99.10.211"
      ],
      "local_ipv4": [
        "10.0.1.5",
        "10.0.1.4",
        "10.0.1.7"
      ],
      "public_ipv6": [

      ],
      "local_ipv6": [

      ]
    }
  }
}
```

#### Package Plugin Supports Arch Linux

The Packages plugin has been updated to include package information on Arch Linux systems.

## What's New in 13.3

### Unprivileged Symlink Creation on Windows

Chef can now create symlinks without privilege escalation, which allows for the creation of symlinks on Windows 10 Creator Update.

### nokogiri Gem

The nokogiri gem is once again bundled with the omnibus install of Chef

### zypper_package Options

It is now possible to pass additional options to the zypper in the zypper_package resource. This can be used to pass any zypper CLI option

#### Example:

```ruby
zypper_package 'foo' do
  options '--user-provided'
end
    ```

### windows_task Improvements

The `windows_task` resource now properly allows updating the configuration of a scheduled task when using the `:create` action. Additionally the previous `:change` action from the windows cookbook has been aliased to `:create` to provide backwards compatibility.

### apt_preference Resource

The apt_preference resource has been ported from the apt cookbook. This resource allows for the creation of APT preference files controlling which packages take priority during installation.

Further information regarding apt-pinning is available via <https://wiki.debian.org/AptPreferences> and <https://manpages.debian.org/stretch/apt/apt_preferences.5.en.html>

#### Actions

- `:add`: creates a preferences file under /etc/apt/preferences.d
- `:remove`: Removes the file, therefore unpin the package

#### Properties

- `package_name`: name attribute. The name of the package
- `glob`: Pin by glob() expression or regexp surrounded by /.
- `pin`: The package version/repository to pin
- `pin_priority`: The pinning priority aka "the highest package version wins"

#### Examples

Pin libmysqlclient16 to version 5.1.49-3:

```ruby
apt_preference 'libmysqlclient16' do
  pin          'version 5.1.49-3'
  pin_priority '700'
end
```

Unpin libmysqlclient16:

```ruby
apt_preference 'libmysqlclient16' do
  action :remove
end
```

Pin all packages from dotdeb.org:

```ruby
apt_preference 'dotdeb' do
  glob         '*'
  pin          'origin packages.dotdeb.org'
  pin_priority '700'
end
```

### zypper_repository Resource

The zypper_repository resource allows for the creation of Zypper package repositories on SUSE Enterprise Linux and openSUSE systems. This resource maintains full compatibility with the resource in the existing [zypper](https://supermarket.chef.io/cookbooks/zypper) cookbooks

#### Actions

- `:add` - adds a repo
- `:delete` - removes a repo

#### Properties

- `repo_name` - repository name if different from the resource name (name property)
- `type` - the repository type. default: 'NONE'
- `description` - the description of the repo that will be shown in `zypper repos`
- `baseurl` - the base url of the repo
- `path` - the relative path from the `baseurl`
- `mirrorlist` - the url to the mirrorlist to use
- `gpgcheck` - should we gpg check the repo (true/false). default: true
- `gpgkey` - location of repo key to import
- `priority` - priority of the repo. default: 99
- `autorefresh` - should the repository be automatically refreshed (true/false). default: true
- `keeppackages` - should packages be saved (true/false). default: false
- `refresh_cache` - should package cache be refreshed (true/false). default: true
- `enabled` - should this repository be enabled (true/false). default: true
- `mode` - the file mode of the repository file. default: "0644"

#### Examples

Add the Apache repository for openSUSE Leap 42.2

```ruby
zypper_repository 'apache' do
  baseurl 'http://download.opensuse.org/repositories/Apache'
  path '/openSUSE_Leap_42.2'
  type 'rpm-md'
  priority '100'
end
```

### Ohai 13.3

#### Additional Platform Support

Ohai now properly detects the [F5 Big-IP](https://www.f5.com/) platform and platform_version.

- platform: bigip
- platform_family: rhel

## What's New in 13.2

### Properly send policyfile data

When sending events back to the Chef Server, we now correctly expand the run_list for nodes that use Policyfiles. This allows Automate to correctly report the node.

### Reconfigure between runs when daemonized

When Chef performs a reconfigure, it re-reads the configuration files. It also re-opens its log files, which facilitates log file rotation.

Chef normally will reconfigure when sent a HUP signal. As of this release if you send a HUP signal while it is converging, the reconfigure happens at the end of the run. This is avoids potential Ruby issues when the configuration file contains additional Ruby code that is executed. While the daemon is sleeping between runs, sending a SIGHUP will still cause an immediate reconfigure.

Additionally, Chef now always performs a reconfigure after every run when daemonized.

### New deprecations

### Explicit property methods

<https://docs.chef.io/deprecations_namespace_collisions>

In Chef 14, custom resources will no longer assume property methods are being called on `new_resource`, and instead require the resource author to be explicit.

### Ohai 13.2

Ohai 13.2 has been a fantastic release in terms of community involvement with new plugins, platform support, and critical bug fixes coming from community members. A huge thank you to msgarbossa, albertomurillo, jaymzh, and davide125 for their work.

#### New Features

##### Systemd Paths Plugin

A new plugin has been added to expose system and user paths from systemd-path (see <https://www.freedesktop.org/software/systemd/man/systemd-path.html> for details).

##### Linux Network, Filesystem, and Mdadm Plugin Resilience

The Network, Filesystem, and Mdadm plugins have been improved to greatly reduce failures to collect data. The Network plugin now better finds the binaries it requires for shelling out, filesystem plugin utilizes data from multiple sources, and mdadm handles arrays in bad states.

##### Zpool Plugin Platform Expansion

The Zpool plugin has been updated to support BSD and Linux in addition to Solaris.

##### RPM version parsing on AIX

The packages plugin now correctly parses RPM package name / version information on AIX systems.

##### Additional Platform Support

Ohai now properly detects the [Clear](https://clearlinux.org/) and [ClearOS](https://www.clearos.com/) Linux distributions.

**Clear Linux**

- platform: clearlinux
- platform_family: clearlinux

**ClearOS**

- platform: clearos
- platform_family: rhel

#### New Deprecations

##### Removal of IpScopes plugin. (OHAI-13)

<https://docs.chef.io/deprecations_ohai_ipscopes>

In Chef/Ohai 14 (April 2018) we will remove the IpScopes plugin. The data returned by this plugin is nearly identical to information already returned by individual network plugins and this plugin required the installation of an additional gem into the Chef installation. We believe that few users were installing the gem and users would be better served by the data returned from the network plugins.

# What's New in 13.1

## Socketless local mode by default

For security reasons we are switching Local Mode to use socketless connections by default. This prevents potential attacks where an unprivileged user or process connects to the internal Zero server for the converge and changes data.

If you use Chef Provisioning with Local Mode, you may need to pass `--listen` to `chef-client`.

## New Deprecations

### Removal of support for Ohai version 6 plugins (OHAI-10)

<https://docs.chef.io/deprecations_ohai_v6_plugins>

In Chef/Ohai 14 (April 2018) we will remove support for loading Ohai v6 plugins, which we deprecated in Ohai 7/Chef 11.12.

# What's New in 13.0

## Rubygems provider sources behavior changed.

The behavior of `gem_package` and `chef_gem` is now to always apply the `Chef::Config[:rubygems_url]` sources, which may be a String uri or an Array of Strings. If additional sources are put on the resource with the `source` property those are added to the configured `:rubygems_url` sources.

This should enable easier setup of rubygems mirrors particularly in "airgapped" environments through the use of the global config variable. It also means that an admin may force all rubygems.org traffic to an internal mirror, while still being able to consume external cookbooks which have resources which add other mirrors unchanged (in a non-airgapped environment).

In the case where a resource must force the use of only the specified source(s), then the `include_default_source` property has been added -* setting it to false will remove the `Chef::Config[:rubygems_url]` setting from the list of sources for that resource.

The behavior of the `clear_sources` property is now to only add `--clear-sources` and has no magic side effects on the source options.

## Ruby version upgraded to 2.4.1

We've upgraded to the latest stable release of the Ruby programming language. See the Ruby [2.4.0 Release Notes](https://www.ruby-lang.org/en/news/2016/12/25/ruby-2-4-0-released/) for an overview of what's new in the language.

## Resource can now declare a default name

The core `apt_update` resource can now be declared without any name argument, no need for `apt_update "this string doesn't matter but why do i have to type it?"`.

This can be used by any other resource by just overriding the name property and supplying a default:

```ruby
  property :name, String, default: ""
```

Notifications to resources with empty strings as their name is also supported via either the bare resource name (`apt_update` -- matches what the user types in the DSL) or with empty brackets (`apt_update[]` -- matches the resource notification pattern).

## The knife ssh command applies the same fuzzifier as knife search node

A bare name to knife search node will search for the name in `tags`, `roles`, `fqdn`, `addresses`, `policy_name` or `policy_group` fields and will match when given partial strings (available since Chef 11). The `knife ssh` search term has been similarly extended so that the search API matches in both cases. The node search fuzzifier has also been extracted out to a `fuzz` option to Chef::Search::Query for re-use elsewhere.

## Cookbook root aliases

Rather than `attributes/default.rb`, cookbooks can now use `attributes.rb` in the root of the cookbook. Similarly for a single default recipe, cookbooks can use `recipe.rb` in the root of the cookbook.

## knife ssh can now connect to gateways with ssh key authentication

The new `gateway_identity_file` option allows the operator to specify the key to access ssh gateways with.

## Windows Task resource added

The `windows_task` resource has been ported from the windows cookbook, and many bugs have been fixed.

## Solaris SMF services can now been started recursively

It is now possible to load Solaris services recursively, by ensuring the new `options` property of the `service` resource contains `-r`.

## It's now possible to blacklist node attributes

This is the inverse of the pre-existing whitelisting functionality.

## The guard interpreter for `powershell_script` is PowerShell, again

When writing `not_if` or `only_if` statements, by default we now run those statements using powershell, rather than forcing the user to set `guard_interpreter` each time.

## Zypper GPG checks by default

Zypper now defaults to performing gpg checks of packages.

## The InSpec gem is now shipped by default

The `inspec` and `train` gems are shipped by default in the chef omnibus package, making it easier for users in airgapped environments to use InSpec.

## Properly support managing Sys-V services on Debian systemd hosts

Chef now properly supports managing sys-v services on hosts running systemd. Previously Chef would incorrectly attempt to fallback to Upstart even if upstart was not installed.

## Backwards Compatibility Breaks

### Resource Cloning has been removed

When Chef compiles resources, it will no longer attempt to merge the properties of previously compiled resources with the same name and type in to the new resource. See [the deprecation page](https://docs.chef.io/deprecations_resource_cloning) for further information.

### It is an error to specify both `default` and `name_property` on a property

Chef 12 made this work by picking the first option it found, but it was always an error and has now been disallowed.

### The path property of the execute resource has been removed

It was never implemented in the provider, so it was always a no-op to use it, the remediation is to simply delete it.

### Using the command property on any script resource (including bash, etc) is now a hard error

This was always a usage mistake. The command property was used internally by the script resource and was not intended to be exposed to users. Users should use the code property instead (or use the command property on an execute resource to execute a single command).

### Omitting the code property on any script resource (including bash, etc) is now a hard error

It is possible that this was being used as a no-op resource, but the log resource is a better choice for that until we get a null resource added. Omitting the code property or mixing up the code property with the command property are also common usage mistakes that we need to catch and error on.

### The chef_gem resource defaults to not run at compile time

The `compile_time true` flag may still be used to force compile time.

### The Chef::Config[:chef_gem_compile_time] config option has been removed

In order to for community cookbooks to behave consistently across all users this optional flag has been removed.

### The `supports[:manage_home]` and `supports[:non_unique]` API has been removed from all user providers

The remediation is to set the manage_home and non_unique properties directly.

### Using relative paths in the `creates` property of an execute resource with specifying a `cwd` is now a hard error

Without a declared cwd the relative path was (most likely?) relative to wherever chef-client happened to be invoked which is not deterministic or easy to intuit behavior.

### Chef::PolicyBuilder::ExpandNodeObject#load_node has been removed

This change is most likely to only affect internals of tooling like chefspec if it affects anything at all.

### PolicyFile fallback to create non-policyfile nodes on Chef Server < 12.3 has been removed

PolicyFile users on Chef-13 should be using Chef Server 12.3 or higher.

### Cookbooks with self dependencies are no longer allowed

The remediation is removing the self-dependency `depends` line in the metadata.

### Removed `supports` API from Chef::Resource

Retained only for the service resource (where it makes some sense) and for the mount resource.

### Removed retrying of non-StandardError exceptions for Chef::Resource

Exceptions not descending from StandardError (e.g. LoadError, SecurityError, SystemExit) will no longer trigger a retry if they are raised during the execution of a resources with a non-zero retries setting.

### Removed deprecated `method_missing` access from the Chef::Node object

Previously, the syntax `node.foo.bar` could be used to mean `node["foo"]["bar"]`, but this API had sharp edges where methods collided with the core ruby Object class (e.g. `node.class`) and where it collided with our own ability to extend the `Chef::Node` API. This method access has been deprecated for some time, and has been removed in Chef-13.

### Changed `declare_resource` API

Dropped the `create_if_missing` parameter that was immediately supplanted by the `edit_resource` API (most likely nobody ever used this) and converted the `created_at` parameter from an optional positional parameter to a named parameter. These changes are unlikely to affect any cookbook code.

### Node deep-duping fixes

The `node.to_hash`/`node.to_h` and `node.dup` APIs have been fixed so that they correctly deep-dup the node data structure including every string value. This results in a mutable copy of the immutable merged node structure. This is correct behavior, but is now more expensive and may break some poor code (which would have been buggy and difficult to follow code with odd side effects before).

For example:

```
node.default["foo"] = "fizz"
n = node.to_hash   # or node.dup
n["foo"] << "buzz"
```

before this would have mutated the original string in-place so that `node["foo"]` and `node.default["foo"]` would have changed to "fizzbuzz" while now they remain "fizz" and only the mutable `n["foo"]` copy is changed to "fizzbuzz".

### Freezing immutable merged attributes

Since Chef 11 merged node attributes have been intended to be immutable but the merged strings have not been frozen. In Chef 13, in the process of merging the node attributes strings and other simple objects are dup'd and frozen. In order to get a mutable copy, you can now correctly use the `node.dup` or `node.to_hash` methods, or you should mutate the object correctly through its precedence level like `node.default["some_string"] << "appending_this"`.

### The Chef::REST API has been removed

It has been fully replaced with `Chef::ServerAPI` in chef-client code.

### Properties overriding methods now raise an error

Defining a property that overrides methods defined on the base ruby `Object` or on `Chef::Resource` itself can cause large amounts of confusion. A simple example is `property :hash` which overrides the Object#hash method which will confuse ruby when the Custom Resource is placed into the Chef::ResourceCollection which uses a Hash internally which expects to call Object#hash to get a unique id for the object. Attempting to create `property :action` would also override the Chef::Resource#action method which is unlikely to end well for the user. Overriding inherited properties is still supported.

### `chef-shell` now supports solo and legacy solo modes

Running `chef-shell -s` or `chef-shell --solo` will give you an experience consistent with `chef-solo`. `chef-shell --solo-legacy-mode` will give you an experience consistent with `chef-solo --legacy-mode`.

### Chef::Platform.set and related methods have been removed

The deprecated code has been removed. All providers and resources should now be using Chef >= 12.0 `provides` syntax.

### Remove `sort` option for the Search API

This option has been unimplemented on the server side for years, so any use of it has been pointless.

### Remove Chef::ShellOut

This was deprecated and replaced a long time ago with mixlib-shellout and the shell_out mixin.

### Remove `method_missing` from the Recipe DSL

The core of chef hasn't used this to implement the Recipe DSL since 12.5.1 and its unlikely that any external code depended upon it.

### Simplify Recipe DSL wiring

Support for actions with spaces and hyphens in the action name has been dropped. Resources and property names with spaces and hyphens most likely never worked in Chef-12. UTF-8 characters have always been supported and still are.

### `easy_install` resource has been removed

The Python `easy_install` package installer has been deprecated for many years, so we have removed support for it. No specific replacement for `pip` is being included with Chef at this time, but a `pip`-based `python_package` resource is available in the [`poise-python`](https://github.com/poise/poise-python) cookbooks.

### Removal of run_command and popen4 APIs

All the APIs in chef/mixlib/command have been removed. They were deprecated by mixlib-shellout and the shell_out mixin API.

### Iconv has been removed from the ruby libraries and chef omnibus build

The ruby Iconv library was replaced by the Encoding library in ruby 1.9.x and since the deprecation of ruby 1.8.7 there has been no need for the Iconv library but we have carried it forwards as a dependency since removing it might break some chef code out there which used this library. It has now been removed from the ruby build. This also removes LGPLv3 code from the omnibus build and reduces build headaches from porting iconv to every platform we ship chef-client on.

This will also affect nokogiri, but that gem natively supports UTF-8, UTF-16LE/BE, ISO-8851-1(Latin-1), ASCII and "HTML" encodings. Users who really need to write something like Shift-JIS inside of XML will need to either maintain their own nokogiri installs or will need to convert to using UTF-8.

### Deprecated cookbook metadata has been removed

The `recommends`, `suggests`, `conflicts`, `replaces` and `grouping` metadata fields are no longer supported, and have been removed, since they were never used. Chef will ignore them in existing `metadata.rb` files, but we recommend that you remove them. This was proposed in RFC 85.

### All unignored cookbook files will now be uploaded.

We now treat every file under a cookbook directory as belonging to a cookbook, unless that file is ignored with a `chefignore` file. This is a change from the previous behavior where only files in certain directories, such as `recipes` or `templates`, were treated as special. This change allows chef to support new classes of files, such as Ohai plugins or Inspec tests, without having to make changes to the cookbook format to support them.

### DSL-based custom resources and providers no longer get module constants

Up until now, creating a `mycook/resources/thing.rb` would create a `Chef::Resources::MycookThing` name to access the resource class object. This const is no longer created for resources and providers. You can access resource classes through the resolver API like:

```ruby
Chef::Resource.resource_for_node(:mycook_thing, node)
```

Accessing a provider class is a bit more complex, as you need a resource against which to run a resolution like so:

```ruby
Chef::ProviderResolver.new(node, find_resource!("mycook_thing[name]"), :nothing).resolve
```

### Default values for resource properties are frozen

A resource declaring something like:

```ruby
property :x, default: {}
```

will now see the default value set to be immutable. This prevents cases of modifying the default in one resource affecting others. If you want a per-resource mutable default value, define it inside a `lazy{}` helper like:

```ruby
property :x, default: lazy { {} }
```

### Resources which later modify their name during creation will have their name changed on the ResourceCollection and notifications

```ruby
some_resource "name_one" do
  name "name_two"
end
```

The fix for sending notifications to multipackage resources involved changing the API which inserts resources into the resource collection slightly so that it no longer directly takes the string which is typed into the DSL but reads the (possibly coerced) name off of the resource after it is built. The end result is that the above resource will be named `some_resource[name_two]` instead of `some_resource[name_one]`. Note that setting the name (_not_ the `name_property`, but actually renaming the resource) is very uncommon. The fix is to simply name the resource correctly in the first place (`some_resource "name_two" do ...`)

### `use_inline_resources` is always enabled

The `use_inline_resources` provider mode is always enabled when using the `action :name do ... end` syntax. You can remove the `use_inline_resources` line.

### `knife cookbook site vendor` has been removed

Please use `knife cookbook site install` instead.

### `knife cookbook create` has been removed

Please use `chef generate cookbook` from the ChefDK instead.

### Verify commands no longer support "%{file}"

Chef has always recommended `%{path}`, and `%{file}` has now been removed.

### The `partial_search` recipe method has been removed

The `partial_search` method has been fully replaced by the `filter_result` argument to `search`, and has now been removed.

### The logger and formatter settings are more predictable

The default now is the formatter. There is no more automatic switching to the logger when logging or when output is sent to a pipe. The logger needs to be specifically requested with `--force-logger` or it will not show up.

The `--force-formatter` option does still exist, although it will probably be deprecated in the future.

If your logfiles switch to the formatter, you need to include `--force-logger` for your daemonized runs.

Redirecting output to a file with `chef-client > /tmp/chef.out` now captures the same output as invoking it directly on the command line with no redirection.

### Path Sanity disabled by default and modified

The chef client itself no long modifies its `ENV['PATH']` variable directly. When using the `shell_out` API now, in addition to setting up LANG/LANGUAGE/LC_ALL variables that API will also inject certain system paths and the ruby bindir and gemdirs into the PATH (or Path on Windows). The `shell_out_with_systems_locale` API still does not mangle any environment variables. During the Chef-13 lifecycle changes will be made to prep Chef-14 to switch so that `shell_out` by default behaves like `shell_out_with_systems_locale`. A new flag will get introduced to call `shell_out(..., internal: [true|false])` to either get the forced locale and path settings ("internal") or not. When that is introduced in Chef 13.x the default will be `true` (backwards-compat with 13.0) and that default will change in 14.0 to 'false'.

The PATH changes have also been tweaked so that the ruby bindir and gemdir PATHS are prepended instead of appended to the PATH. Some system directories are still appended.

Some examples of changes:

- `which ruby` in 12.x will return any system ruby and fall back to the embedded ruby if using omnibus
- `which ruby` in 13.x will return any system ruby and will not find the embedded ruby if using omnibus
- `shell_out_with_systems_locale("which ruby")` behaves the same as `which ruby` above
- `shell_out("which ruby")` in 12.x will return any system ruby and fall back to the embedded ruby if using omnibus
- `shell_out("which ruby")` in 13.x will always return the omnibus ruby first (but will find the system ruby if not using omnibus)

The PATH in `shell_out` can also be overridden:

- `shell_out("which ruby", env: { "PATH" => nil })` - behaves like shell_out_with_systems_locale()
- `shell_out("which ruby", env: { "PATH" => [...include PATH string here...] })` - set it arbitrarily however you need

Since most providers which launch custom user commands use `shell_out_with_systems_locale` (service, execute, script, etc) the behavior will be that those commands that used to be having embedded omnibus paths injected into them no longer will. Generally this will fix more problems than it solves, but may causes issues for some use cases.

### Default guard clauses (`not_if`/`only_if`) do not change the PATH or other env vars

The implementation switched to `shell_out_with_systems_locale` to match `execute` resource, etc.

### Chef Client will now exit using the RFC062 defined exit codes

Chef Client will only exit with exit codes defined in RFC 062. This allows other tooling to respond to how a Chef run completes. Attempting to exit Chef Client with an unsupported exit code (either via `Chef::Application.fatal!` or `Chef::Application.exit!`) will result in an exit code of 1 (GENERIC_FAILURE) and a warning in the event log.

When Chef Client is running as a forked process on unix systems, the standardized exit codes are used by the child process. To actually have Chef Client return the standard exit code, `client_fork false` will need to be set in Chef Client's configuration file.

# What's New in 12.22:

## Security Updates

### Ruby

Ruby has been updated to 2.3.6 to resolve CVE-2017-17405

### LibXML2

Libxml2 has been updated to 2.9.7 to resolve CVE-2017-15412

## Ohai 8.26.1

### EC2 detection on C5/M5

Ohai now provides EC2 metadata configuration information on the new C5/M5 instance types running on Amazon's new hypervisor.

### LsPci Plugin

The new LsPci plugin provides a node[:pci] hash with information about the PCI bus based on lspci. Only runs on Linux.

### Docker Detection

The virtualization plugin has been updated to properly detect when running on Docker CE

# What's New in 12.21:

## Security Fixes

This release of Chef Client contains Ruby 2.3.5, fixing 4 CVEs:

  - CVE-2017-0898
  - CVE-2017-10784
  - CVE-2017-14033
  - CVE-2017-14064

It also contains a new version of Rubygems, fixing 4 CVEs:

  - CVE-2017-0899
  - CVE-2017-0900
  - CVE-2017-0901
  - CVE-2017-0902

This release also contains a new version of zlib, fixing 4
CVEs:

 -  [CVE-2016-9840](https://www.cvedetails.com/cve/CVE-2016-9840/)
 -  [CVE-2016-9841](https://www.cvedetails.com/cve/CVE-2016-9841/)
 -  [CVE-2016-9842](https://www.cvedetails.com/cve/CVE-2016-9842/)
 -  [CVE-2016-9843](https://www.cvedetails.com/cve/CVE-2016-9843/)

## On Debian prefer Systemd to Upstart

On Debian systems, packages that support systemd will often ship both an
old style init script and a systemd unit file. When this happened, Chef
would incorrectly choose Upstart rather than Systemd as the service
provider. Chef will now prefer systemd where available.

## Handle the supports pseudo-property more gracefully

Chef 13 removed the `supports` property from core resources. However,
many cookbooks also have a property named support, and Chef 12 was
incorrectly giving a deprecation notice in that case, preventing users
from properly testing their cookbooks for upgrades.

## Don't crash if downgrading from Chef 13 to 12

On systems where Chef 13 had been run, Chef 12 would crash as the
on-disk cookbook format has changed. Chef 12 now correctly ignores the
unexpected files.

## Provide better system information when Chef crashes

When Chef crashes, the output now includes details about the platform
and version of Chef that was running, so that a bug report has more
detail from the off.

# What's New in 12.19:

## Highlighted enhancements for this release:

- Systemd unit files are now verified before being installed.
- Added support for windows alternate user identity in execute resources.
- Added ed25519 key support for for ssh connections.

### Windows alternate user identity execute support

The `execute` resource and similar resources such as `script`, `batch`, and `powershell_script` now support the specification of credentials on Windows so that the resulting process is created with the security identity that corresponds to those credentials.

**Note**: When Chef is running as a service, this feature requires that the user that Chef runs as has 'SeAssignPrimaryTokenPrivilege' (aka 'SE_ASSIGNPRIMARYTOKEN_NAME') user right. By default only LocalSystem and NetworkService have this right when running as a service. This is necessary even if the user is an Administrator.

This right can be added and checked in a recipe using this example:

```ruby
# Add 'SeAssignPrimaryTokenPrivilege' for the user
Chef::ReservedNames::Win32::Security.add_account_right('<user>', 'SeAssignPrimaryTokenPrivilege')

# Check if the user has 'SeAssignPrimaryTokenPrivilege' rights
Chef::ReservedNames::Win32::Security.get_account_right('<user>').include?('SeAssignPrimaryTokenPrivilege')
```

#### Properties

The following properties are new or updated for the `execute`, `script`, `batch`, and `powershell_script` resources and any resources derived from them:

- `user`<br>
  **Ruby types:** String<br>
  The user name of the user identity with which to launch the new process. Default value: `nil`. The user name may optionally be specified with a domain, i.e. `domain\user` or `user@my.dns.domain.com` via Universal Principal Name (UPN) format. It can also be specified without a domain simply as `user` if the domain is instead specified using the `domain` attribute. On Windows only, if this property is specified, the `password` property **must*- be specified.

- `password`<br>
  **Ruby types*- String<br>
  _Windows only:_ The password of the user specified by the `user` property. Default value: `nil`. This property is mandatory if `user` is specified on Windows and may only be specified if `user` is specified. The `sensitive` property for this resource will automatically be set to `true` if `password` is specified.

- `domain`<br>
  **Ruby types*- String<br>
  _Windows only:_ The domain of the user user specified by the `user` property. Default value: `nil`. If not specified, the user name and password specified by the `user` and `password` properties will be used to resolve that user against the domain in which the system running Chef client is joined, or if that system is not joined to a domain it will resolve the user as a local account on that system. An alternative way to specify the domain is to leave this property unspecified and specify the domain as part of the `user` property.

#### Usage

The following examples explain how alternate user identity properties can be used in the execute resources:

```ruby
powershell_script 'create powershell-test file' do
  code <<-EOH
  $stream = [System.IO.StreamWriter] "#{Chef::Config[:file_cache_path]}/powershell-test.txt"
  $stream.WriteLine("In #{Chef::Config[:file_cache_path]}...word.")
  $stream.close()
  EOH
  user 'username'
  password 'password'
end

execute 'mkdir test_dir' do
  cwd Chef::Config[:file_cache_path]
  domain "domain-name"
  user "user"
  password "password"
end

script 'create test_dir' do
  interpreter "bash"
  code  "mkdir test_dir"
  cwd Chef::Config[:file_cache_path]
  user "domain-name\\username"
  password "password"
end

batch 'create test_dir' do
  code "mkdir test_dir"
  cwd Chef::Config[:file_cache_path]
  user "username@domain-name"
  password "password"
end
```

## Highlighted bug fixes for this release:

- Ensure that the Windows Administrator group can access the chef-solo nodes directory
- When loading a cookbook in Chef Solo, use `metadata.json` in preference to `metadata.rb`

## Deprecation Notice

- As of version 12.19, chef client will no longer be build or tested on the Cisco NX-OS and IOS XR platforms.

# Ohai Release Notes 8.23:

## Cumulus Linux Platform

Cumulus Linux will now be detected as platform `cumulus` instead of `debian` and the `platform_version` will be properly set to the Cumulus Linux release.

## Virtualization Detection

Windows / Linux / BSD guests running on the Veertu hypervisors will now be detected

Windows guests running on Xen and Hyper-V hypervisors will now be detected

## New Sysconf Plugin

A new plugin parses the output of the sysconf command to provide information on the underlying system.

## AWS Account ID

The EC2 plugin now fetches the AWS Account ID in addition to previous instance metadata

## GCC Detection

GCC detection has been improved to collect additional information, and to not prompt for the installation of Xcode on macOS systems

## New deprecations introduced in this release:

### Ohai::Config removed

- **Deprecation ID**: OHAI-1
- **Remediation Docs**: <https://docs.chef.io/deprecations_ohai_legacy_config>
- **Expected Removal**: Ohai 13 (April 2017)

### sigar gem based plugins removed

- **Deprecation ID**: OHAI-2
- **Remediation Docs**: <https://docs.chef.io/deprecations_ohai_sigar_plugins>
- **Expected Removal**: Ohai 13 (April 2017)

### run_command and popen4 helper methods removed

- **Deprecation ID**: OHAI-3
- **Remediation Docs**: <https://docs.chef.io/deprecations_ohai_run_command_helpers>
- **Expected Removal**: Ohai 13 (April 2017)

### libvirt plugin attributes moved

- **Deprecation ID**: OHAI-4
- **Remediation Docs**: <https://docs.chef.io/deprecations_ohai_libvirt_plugin>
- **Expected Removal**: Ohai 13 (April 2017)

### Windows CPU plugin attribute changes

- **Deprecation ID**: OHAI-5
- **Remediation Docs**: <https://docs.chef.io/deprecations_ohai_windows_cpu>
- **Expected Removal**: Ohai 13 (April 2017)

### DigitalOcean plugin attribute changes

- **Deprecation ID**: OHAI-6
- **Remediation Docs**: <https://docs.chef.io/deprecations_ohai_digitalocean/>
- **Expected Removal**: Ohai 13 (April 2017)
