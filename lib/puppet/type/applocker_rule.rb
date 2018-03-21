Puppet::Type.newtype(:applocker_rule) do
  @doc = 'Manage the Windows O/S AppLocker policies.  For more information see: https://docs.microsoft.com/en-us/windows/security/threat-protection/applocker/applocker-overview'

  ensurable

  newparam(:name) do
    desc 'applockerpolicy.rb::name (namevar).'
    isnamevar
  end

  newproperty(:action) do
    desc 'The AppLocker action [Allow, Deny].'
    newvalues(:Allow, :Deny)
  end

  newproperty(:conditions, array_matching: :all) do
    desc 'The AppLocker rule conditions, an array of hashes specifying the rule conditions.  Different hashes are needed for each rule: { path => }, { hash =>,  file => , type => , size => }, { publisher =>, product =>, binaryname =>, hi_version =>, lo_version => }'
  end

  newproperty(:description) do
    desc 'The AppLocker rule description.'
  end

  newproperty(:exceptions, array_matching: :all) do
    desc 'The AppLocker rule exceptions, an array of file paths listing files not affected by the rule.  Currently this property only supports FilePathRule creation.'
  end

  newparam(:filepath) do
    desc 'Specify a complete path to a file.  The AppLocker interface allows you to choose a file to grab publisher and hash information.  It is a parameter, so it does not map to a property that can be retrieved from the AppLocker API.'
  end

  newproperty(:id) do
    desc 'The AppLocker rule identifier (GUID).  A GUID will be automatically be generated and assigned if this property is omitted.'
  end

  newproperty(:mode) do
    desc 'Is the rule enforced? [Enabled, Disabled, NotConfigured, AuditOnly]'
    newvalues(:Enabled, :Disabled, :NotConfigured, :AuditOnly)
  end

  newproperty(:rule_type) do
    desc 'The type of AppLocker rule [path, hash, publisher].'
    defaultto :path
    newvalues(:path, :hash, :publisher)
  end

  newproperty(:type) do
    desc 'The type of AppLocker collection [Appx, Dll, Exe, Msi, Script].'
    newvalues(:Appx, :Dll, :Exe, :Msi, :Script)
  end

  newproperty(:user_or_group_sid) do
    desc 'The AppLocker user or group system identifier.  See: https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems'
  end

end
