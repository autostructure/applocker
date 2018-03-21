# Example class demonstrating all three rule types created two different ways.
#

class sample_rules {

  # Guest Group SID => S-1-5-32-546
  # 
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
}
