# applocker
[![License](https://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![Puppet Forge](https://img.shields.io/puppetforge/v/autostructure/applocker.svg)](https://forge.puppetlabs.com/autostructure/applocker)
[![Puppet Forge](https://img.shields.io/puppetforge/f/autostructure/applocker.svg)](https://forge.puppetlabs.com/autostructure/applocker)
[![Build Status](https://travis-ci.org/autostructure/applocker.svg?branch=master)](https://travis-ci.org/autostructure/applocker)

[Microsoft's AppLocker Overview]: https://docs.microsoft.com/en-us/windows/security/threat-protection/applocker/applocker-overview
[GitHub AppLocker Project]: https://github.com/autostructure/applocker

Manage Windows&reg; AppLocker rules using this module. It contains a custom type provider that uses `powershell.exe` commands to create, modify, or delete AppLocker rules. Simply include this module in your `Puppetfile` and utilize the `applocker_rule` resource to help manage Windows&reg; application security policies. For more information about AppLocker, please see [Microsoft's AppLocker Overview]. Examine the codebase on GitHub at the [GitHub AppLocker Project].

#### Table of Contents

1. [Module Description](#module-description)
2. [Setup - The basics of getting started with applocker](#setup)
    * [Setup Requirements](#setup-requirements)
    * [Setup Required Resources](#setup-required-resources)
      - [Edit Puppetfile](#edit-puppetfile)
      - [PowerShell Rule](#powershell-rule)
      - [Default Rules](#default-rules)
      - [AppIDSvc Service](#appidsvc-service)
3. [Usage - Configuration options and additional functionality](#usage)
    * [CLI Usage](#cli-usage)
    * [Usage Examples](#usage-examples)
4. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
    * [Resource Types](#resource-types)
    * [Parameters](#parameters)
    * [Properties](#properties)
    * [Security Identifiers (SID)](#security-identifiers-sid)
5. [Limitations - OS compatibility, etc.](#limitations)
6. [Disclaimer](#disclaimer)
7. [Copyrights](#copyrights)
8. [Development - Guide for contributing to the module](#development)
9. [Release Notes/Contributors/Etc.](#release-notescontributorsetc)

## Module Description

Create, modify, or delete AppLocker rules using the `applocker_rule` resource.

The module enforces the AppLocker rules using a Puppet type provider that makes calls to the Windows-native `powershell.exe` executable.  Therefore, `powershell.exe` must be able to run to enforce AppLocker rules.  If an AppLocker rule is created that restricts access to `powershell.exe`, then this module will be useless.  The [Resources Required for Setup](#resources-required-for-setup) section below contains an example of an AppLocker rule that can be used that enables the Administrator to run `powershell.exe`.  A sample rule also exists in the `applocker_startup.pp` file, found in examples directory.

The module has been tested in Windows&reg; Server 2016 and 2012R2 environments running Puppet Enterprise 2017.3.

## Setup

### Setup Requirements

Follow these steps:

1. Add the module reference to your "Puppetfile"
1. Create an AppLocker PowerShell rule
1. Create AppLocker "Default Rules"
1. Use the `applocker_rule` resource to create your custom AppLocker rules
1. Startup the Application Identity Service (AppIDSvc)
1. `pluginsync` must be enabled

>Note: `pluginsync` is necessary to download the `powershell.rb` provider file to the agent.  It is enabled by default, so no action should be required.

### Setup Required Resources

#### Edit Puppetfile

Modify the Puppet Master's `Puppetfile` by adding the following line:

```puppet
mod 'autostructure-applocker', '1.0.0'
```

#### PowerShell Rule

Please note that this AppLocker custom provider will fail without access to `powershell.exe`.  AppLocker may restrict access to `powershell.exe`.  The provider uses `powershell.exe` to enforce the resource and will fail after AppLocker is started (i.e. when the AppIDSvc is started) unless an AppLocker 'Allow' rule is created for `powershell.exe`.

Add the following resource definition below to allow Administrators to run `powershell.exe`:
```puppet
# Must enable access to powershell.exe since it is used by the applocker_rule provider to enforce rules.

applocker_rule { '(Puppet Rule) Allow Puppet to run powershell.exe (the applocker_rule provider).':
  ensure            => 'present',
  action            => 'Allow',
  conditions        => [
  {
    'path' => '%SYSTEM32%\WindowsPowerShell\v1.0\powershell.exe'
  }],
  description       => 'Allow Administrator to execute %SYSTEM32%\WindowsPowerShell\v1.0\powershell.exe',
  mode              => 'NotConfigured',
  rule_type         => 'path',
  type              => 'Exe',
  user_or_group_sid => 'S-1-5-32-544',
}
```

The command above also appears in: `examples/enable_powershell.pp` and `examples/applocker_startup.pp`.

#### Default Rules

Next, it is advised that you create the AppLocker Default Rules along with any other rules you desire (or be locked out of the system when you start the AppIDSvc service).  Default rules give users some default application access.  **Be advised, if you start the Application Identity Service (AppIDSvc) with no AppLocker rules you will be denied access to all executables!**. During development, it may be convenient to omit the resource that starts the Application Identity Service until you are ready to test your rules.  

The default rules can be found here: `examples/applocker_default_rules.pp` or `examples/applocker_startup.pp`.  They have also been listed below.  The rule definitions below were created by running the `puppet resource applocker_rule` command after creating the default rules from within AppLocker...

```puppet
# Create AppLocker "Default Rules" before starting the AppIDSvc service.

applocker_rule { '(Default Rule) All Windows Installer files':
  ensure            => 'present',
  action            => 'Allow',
  conditions        => [
  {
    'path' => '*.*'
  }],
  description       => 'Allows members of the local Administrators group to run all Windows Installer files.',
  mode              => 'NotConfigured',
  rule_type         => 'path',
  type              => 'Msi',
  user_or_group_sid => 'S-1-5-32-544',
}

applocker_rule { '(Default Rule) All Windows Installer files in %systemdrive%\Windows\Installer':
  ensure            => 'present',
  action            => 'Allow',
  conditions        => [
  {
    'path' => '%WINDIR%\Installer\*'
  }],
  description       => 'Allows members of the Everyone group to run all Windows Installer files located in %systemdrive%\Windows\Installer.',
  mode              => 'NotConfigured',
  rule_type         => 'path',
  type              => 'Msi',
  user_or_group_sid => 'S-1-1-0',
}

applocker_rule { '(Default Rule) All digitally signed Windows Installer files':
  ensure            => 'present',
  action            => 'Allow',
  conditions        => [
  {
    'publisher'  => '*',
    'product'    => '*',
    'binaryname' => '*',
    'hi_version' => '*',
    'lo_version' => '0.0.0.0'
  }],
  description       => 'Allows members of the Everyone group to run digitally signed Windows Installer files.',
  mode              => 'NotConfigured',
  rule_type         => 'publisher',
  type              => 'Msi',
  user_or_group_sid => 'S-1-1-0',
}

applocker_rule { '(Default Rule) All files':
  ensure            => 'present',
  action            => 'Allow',
  conditions        => [
  {
    'path' => '*'
  }],
  description       => 'Allows members of the local Administrators group to run all applications.',
  mode              => 'NotConfigured',
  rule_type         => 'path',
  type              => 'Exe',
  user_or_group_sid => 'S-1-5-32-544',
}

applocker_rule { '(Default Rule) All files located in the Program Files folder':
  ensure            => 'present',
  action            => 'Allow',
  conditions        => [
  {
    'path' => '%PROGRAMFILES%\*'
  }],
  description       => 'Allows members of the Everyone group to run applications that are located in the Program Files folder.',
  mode              => 'NotConfigured',
  rule_type         => 'path',
  type              => 'Exe',
  user_or_group_sid => 'S-1-1-0',
}

applocker_rule { '(Default Rule) All files located in the Windows folder':
  ensure            => 'present',
  action            => 'Allow',
  conditions        => [
  {
    'path' => '%WINDIR%\*'
  }],
  description       => 'Allows members of the Everyone group to run applications that are located in the Windows folder.',
  mode              => 'NotConfigured',
  rule_type         => 'path',
  type              => 'Exe',
  user_or_group_sid => 'S-1-1-0',
}

applocker_rule { '(Default Rule) All scripts':
  ensure            => 'present',
  action            => 'Allow',
  conditions        => [
  {
    'path' => '*'
  }],
  description       => 'Allows members of the local Administrators group to run all scripts.',
  mode              => 'NotConfigured',
  rule_type         => 'path',
  type              => 'Script',
  user_or_group_sid => 'S-1-5-32-544',
}

applocker_rule { '(Default Rule) All scripts located in the Program Files folder':
  ensure            => 'present',
  action            => 'Allow',
  conditions        => [
  {
    'path' => '%PROGRAMFILES%\*'
  }],
  description       => 'Allows members of the Everyone group to run scripts that are located in the Program Files folder.',
  mode              => 'NotConfigured',
  rule_type         => 'path',
  type              => 'Script',
  user_or_group_sid => 'S-1-1-0',
}

applocker_rule { '(Default Rule) All scripts located in the Windows folder':
  ensure            => 'present',
  action            => 'Allow',
  conditions        => [
  {
    'path' => '%WINDIR%\*'
  }],
  description       => 'Allows members of the Everyone group to run scripts that are located in the Windows folder.',
  mode              => 'NotConfigured',
  rule_type         => 'path',
  type              => 'Script',
  user_or_group_sid => 'S-1-1-0',
}

applocker_rule { '(Default Rule) All signed packaged apps':
  ensure            => 'present',
  action            => 'Allow',
  conditions        => [
  {
    'publisher'  => '*',
    'product'    => '*',
    'binaryname' => '*',
    'hi_version' => '*',
    'lo_version' => '0.0.0.0'
  }],
  description       => 'Allows members of the Everyone group to run packaged apps that are signed.',
  mode              => 'NotConfigured',
  rule_type         => 'publisher',
  type              => 'Appx',
  user_or_group_sid => 'S-1-1-0',
}
```

#### AppIDSvc Service

After specifying your `applocker_rule` resources, start the Application Identity Service (AppIDSvc).  Once this service is started it enforces the AppLocker rules...

```puppet

service { 'application identity service':
  ensure => running,
  name   => 'AppIDSvc',
  enable => true,
}
```
This rule is also found in `examples/applocker_startup.pp`.

## Usage

### CLI Usage

List existing `applocker_rule` resources using:
```
puppet resource applocker_rule
```

### Usage Examples

Below are two examples of each rule type: a simple definition using the filepath parameter and a complex definition using the conditions hash.  Note the `rule_type` property in each example, which contains either a `path`, `hash`, or `publisher` value.

```
applocker_rule {'(Sample Rule) Rule #1: Simple Path Rule':
  ensure            => present,
  action            => 'Allow',
  filepath          => '%PROGRAMFILES%\Internet Explorer\iexplore.exe',
  rule_type         => 'path',
  type              => 'Exe',
  user_or_group_sid => 'S-1-5-32-546',
}

applocker_rule {'(Sample Rule) Rule #2: Complex Path Rule':
  ensure            => present,
  action            => 'Deny',
  conditions        => [ { 'path' => '%WINDIR%\*' } ],
  exceptions        => [ '%WINDIR%\Temp\*', '%WINDIR%\System32\*' ],
  description       => 'Sample rule specifying conditions and exceptions, no filepath param.',
  rule_type         => 'path',
  type              => 'Exe',
  user_or_group_sid => 'S-1-5-32-546',
}

applocker_rule {'(Sample Rule) Rule #3: Simple Hash Rule':
  ensure            => present,
  action            => 'Allow',
  filepath          => '%PROGRAMFILES%\Internet Explorer\iexplore.exe',
  rule_type         => 'hash',
  type              => 'Exe',
  user_or_group_sid => 'S-1-5-32-546',
}

applocker_rule {'(Sample Rule) Rule #4: Complex Hash Rule':
  ensure            => present,
  action            => 'Deny',
  conditions        => [
  {
    'hash' => '0x9C352E488066F6319673B8F4ACF1DA3242CF1A68D9637EC54EF95EC5FDD4FDBF',
    'file' => 'iexplore.exe',
    'type' => 'SHA256',
    'size' => '814768'
  }],
  rule_type         => 'hash',
  type              => 'Exe',
  user_or_group_sid => 'S-1-5-32-546',
}

applocker_rule {'(Sample Rule) Rule #5: Simple Publisher Rule':
  ensure            => present,
  action            => 'Allow',
  filepath          => '%PROGRAMFILES%\Internet Explorer\iexplore.exe',
  rule_type         => 'publisher',
  type              => 'Exe',
  user_or_group_sid => 'S-1-5-32-546',
}

applocker_rule {'(Sample Rule) Rule #6: Complex Publisher Rule':
  ensure            => present,
  action            => 'Deny',
  conditions        => [
  {
    'publisher'  => 'O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US',
    'product'    => 'INTERNET EXPLORER',
    'binaryname' => '*',
    'hi_version' => '*',
    'lo_version' => '11.0.0.0'
  }],
  rule_type         => 'publisher',
  type              => 'Exe',
  user_or_group_sid => 'S-1-5-32-546',
}
```
## Reference

Below are the `applocker_rule` resource parameters and properties:

### Resource Types

`applocker_rule`

At a minimum, please supply:
* title / name
* action
* rule_type
* type
* user_or_group_sid

And, **one** of the following:
* conditions property
* filepath parameter

### Parameters

* **name (parameter)** - The namevar.  You can either use this parameter or the title to set the rule's name.
* **filepath (parameter)** - Specify a complete path to a file.  The AppLocker interface allows you to choose a file to grab publisher and hash information.  It is a parameter, so it does not map to a property that can be retrieved from the AppLocker API.

### Properties

* **action** - The AppLocker action [Allow, Deny].
* **conditions** - The AppLocker rule conditions, an array of hashes specifying the rule conditions.  AppLocker only allows one rule condition (one file path, file hash, or publisher rule).  Different hashes are needed for each rule:

  Rule | Conditions Hash
  ---- | ---------------
  File Path Rule | `{ path => }`
  Hash Rule | `{ hash =>,  file => , type => , size => }`
  Publisher Rule | `{ publisher =>, product =>, binaryname =>, hi_version =>, lo_version => }`
* **description** - The AppLocker rule description.  Note: have not tested values like single, or double, quotes, nor any other special characters, so use them at your own risk.
* **exceptions** - The AppLocker rule exceptions, an array of file paths listing files not affected by the rule.  Currently this property only supports FilePathRule creation.  It will not set hash or publisher exceptions (TBD).
* **id** - The AppLocker rule identifier (GUID).  A GUID will be automatically be generated and assigned if this property is omitted.  Or, you can use this to explicitly set the identifier.
* **mode** - AppLocker EnforcementMode [Enabled, Disabled, NotConfigured, AuditOnly].  You shouldn't have to specify this property when creating rules.
* **rule_type** - Type of AppLocker rule [path, hash, publisher]
* **type** - Type of AppLocker collection [Appx, Dll, Exe, Msi, Script].
* **user_or_group_sid** - Windows&reg; user or group system identifier (SID).  Specifically supply a SID and not a username.  The username isn't stored in AppLocker, so the provider can't resolve the username value against AppLocker's data (a SID).  The username appears to work for rule creation, it just can't resolve the property after creation.  I have created a rule using a username, grabbed this SID from the puppet resource command, utimately replacing the username with the SID in the puppet manifest.  For more information, see [Security Identifiers (SID)](https://github.com/autostructure/applocker/blob/master/README.md#security-identifiers-sid) below.

#### Security Identifiers (SID)

A security identifier (SID) is a unique value of variable length that is used to identify a security principal or security group in Windows operating systems. Well-known SIDs are a group of SIDs that identify generic users or generic groups. Their values remain constant across all operating systems.

Some useful, well-known SIDs:

Security Identifier (SID) | [User/Group] | Description
------------------------- | ------------ | -----------
**S-1-0** | [Null Authority] | An identifier authority.
**S-1-0-0** | [Nobody] | No security principal.
**S-1-1-0** | [Everyone] | A group that includes all users, even anonymous users and guests. Membership is controlled by the operating system.  Note By default, the Everyone group no longer includes anonymous users on a computer that is running Windows&reg; XP Service Pack 2 (SP2).
**S-1-2-0** | [Local] | A group that includes all users who have logged on locally.
**S-1-2-1** | [Console Logon] | A group that includes users who are logged on to the physical console.  Note Added in Windows 7 and Windows&reg; Server 2008 R2
**S-1-5-7** | [Anonymous] | A group that includes all users that have logged on anonymously. Membership is controlled by the operating system.
**S-1-5-11** | [Authenticated Users] | A group that includes all users whose identities were authenticated when they logged on. Membership is controlled by the operating system.
**S-1-5-32-544** | [Administrators] | A built-in group. After the initial installation of the operating system, the only member of the group is the Administrator account. When a computer joins a domain, the Domain Admins group is added to the Administrators group. When a server becomes a domain controller, the Enterprise Admins group also is added to the Administrators group.
**S-1-5-32-545** | [Users] | A built-in group. After the initial installation of the operating system, the only member is the Authenticated Users group. When a computer joins a domain, the Domain Users group is added to the Users group on the computer.
**S-1-5-32-546** | [Guests] | A built-in group. By default, the only member is the Guest account. The Guests group allows occasional or one-time users to log on with limited privileges to a computer's built-in Guest account.
**S-1-5-32-547** | [Power Users] | A built-in group. By default, the group has no members. Power users can create local users and groups; modify and delete accounts that they have created; and remove users from the Power Users, Users, and Guests groups. Power users also can install programs; create, manage, and delete local printers; and create and delete file shares.
**S-1-5-80-0** | [All Services] | A group that includes all service processes that are configured on the system. Membership is controlled by the operating system.  Note Added in Windows&reg; Server 2008 R2.  SID S-1-5-80-0 = NT SERVICES\ALL SERVICES

Source: [Well-known security identifiers in Windows&reg; operating systems](https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems)

## Limitations

Only works on Windows-based operating systems.  The module has been tested on Windows&reg; Server 2012R2 and Windows&reg; Server 2016 platforms running Puppet Enterprise 2017.3.

Although the module supports creation, modification, and deletion of all three rule types (`FilePathRule`, `FileHashRule`, `FilePublisherRule`) it currently only allows you to create one type of exception.  The `exceptions` property only accepts an array of filepaths, which is used to create one or more `FilePathRule` exceptions.  The ability to create `FileHashRule` and `FilePublisherRule` related exceptions will be added in a future module release.

## Disclaimer

> This Work is provided "as is." Any express or implied warranties,
including but not limited to, the implied warranties of merchantability
and fitness for a particular purpose are disclaimed. In no event shall
the authors be liable for any direct, indirect,
incidental, special, exemplary or consequential damages (including, but
not limited to, procurement of substitute goods or services, loss of
use, data or profits, or business interruption) however caused and on
any theory of liability, whether in contract, strict liability, or tort
(including negligence or otherwise) arising in any way out of the use of
this Guidance, even if advised of the possibility of such damage.
>
> The User of this Work agrees to hold harmless and indemnify Autostructure,
its agents, parent company, and employees from every claim or liability
(whether in tort or in contract), including attorneys' fees,
court costs, and expenses, arising in direct consequence of Recipient's
use of the item, including, but not limited to, claims or liabilities
made for injury to or death of personnel of User or third parties,
damage to or destruction of property of User or third parties, and
infringement or other violations of intellectual property or technical
data rights.
>
> Nothing in this Work is intended to constitute an endorsement, explicit
or implied, by Autostructure of any particular manufacturer's
product or service.

## Copyrights

> All materials are copyright by their respective owners unless otherwise noted.
>
> Released under the [Apache License, Version 2](http://www.apache.org/licenses/LICENSE-2.0.html).

## Development

[GitHub AppLocker Project]

A GitHub pull request must be submitted to make changes to this module.

## Release Notes/Contributors/Etc.

Release v1.0.0 to Puppet Forge on May 3, 2018.
