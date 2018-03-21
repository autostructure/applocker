# Example class that denies access to removable media and removable storage devices.
#

class deny_removable_media {

  # Use the two AppLocker variables, %HOT% and %REMOVABLE% to demonstrate rules to lockout removable storage.
  #
  applocker_rule {'(Puppet Rule) Lock down removable storage device (for example, USB flash drive)':
    ensure            => present,
    action            => 'Deny',
    conditions        => [ { 'path' => '%HOT%\*' } ],
    description       => 'Lock down removable storage device (for example, USB flash drive)',
    mode              => 'NotConfigured',
    rule_type         => 'path',
    type              => 'Exe',
    user_or_group_sid => 'S-1-1-0',
  }

  applocker_rule {'(Puppet Rule) Lock down Removable media (for example, CD or DVD)':
    ensure            => present,
    action            => 'Deny',
    conditions        => [ { 'path' => '%REMOVABLE%\*' } ],
    description       => 'Lock down removable media (for example, CD or DVD)',
    mode              => 'NotConfigured',
    rule_type         => 'path',
    type              => 'Exe',
    user_or_group_sid => 'S-1-1-0',
  }
}
