# Example class that enables the applocker_rule type provider to access powershell.exe
#

class enable_powershell {

  # Must enable access to powershell.exe since it is used by the applocker_rule type provider to enforce rules.
  #
  applocker_rule { '(Puppet Rule) Allow Puppet to run powershell.exe (used by the applocker_rule provider).':
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
}
