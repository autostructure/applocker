require 'rexml/document'
include REXML
Puppet::Type.type(:applocker_rule).provide(:powershell) do
  desc 'Use the Windows O/S powershell.exe tool to manage AppLocker policies.'
  # For the AppLockerPolicy to be enforced on a computer, the Application Identity service must be running (AppIDSvc).

  mk_resource_methods

  confine :kernel => :windows
  commands :ps => File.exist?("#{ENV['SYSTEMROOT']}\\system32\\windowspowershell\\v1.0\\powershell.exe") ? "#{ENV['SYSTEMROOT']}\\system32\\windowspowershell\\v1.0\\powershell.exe" : 'powershell.exe'

  def initialize(value = {})
    super(value)
    @property_flush = {}
  end

  def tempfile
    'c:\windows\temp\applockerpolicy.xml.tmp'
  end

  def get_guid
    ps("[system.guid]::NewGuid().ToString('D')").strip
  end

  def self.conditions2hasharray(node)
    xml2hasharray(node, true)
  end

  def self.exceptions2hasharray(node)
    xml2hasharray(node, false)
  end

  def self.exceptions2array(node)
    ret_array = []
    fpc = node.get_elements('.//Exceptions/FilePathCondition')
    no_filepathconditions = fpc.nil? || fpc.empty?
    fpc.each { |xml| ret_array << xml.attribute('Path').to_string.slice(/=['|"]*(.*)['|"]/,1) } unless no_filepathconditions
    ret_array
  end

  def self.xml2hasharray(node, is_condition)
    ret_array = []
    fc = nil
    hc = nil
    pc = nil
    if is_condition
      fc = node.get_elements('.//Conditions/FilePathCondition')
      hc = node.get_elements('.//Conditions/FileHashCondition/FileHash')
      pc = node.get_elements('.//Conditions/FilePublisherCondition')
    else
      fc = node.get_elements('.//Exceptions/FilePathCondition')
      hc = node.get_elements('.//Exceptions/FileHashCondition/FileHash')
      pc = node.get_elements('.//Exceptions/FilePublisherCondition')
    end
    no_filepathconditions = fc.nil? || fc.empty?
    no_filehashconditions = hc.nil? || hc.empty?
    no_filepublisherconditions = pc.nil? || pc.empty?
    # CAVEAT: you must you double quotes around key for the puppet provider to match the value in the manifest.
    #         symbols and single quotes caused puppet agent to think the property changed value (mistakenly).
    fc.each { |xml| ret_array << { "path" => xml.attribute('Path').to_string.slice(/=['|"]*(.*)['|"]/,1) } } unless no_filepathconditions
    hc.each { |xml|
      ret_array << { "hash" => xml.attribute('Data').to_string.slice(/=['|"]*(.*)['|"]/,1),
                     "file" => xml.attribute('SourceFileName').to_string.slice(/=['|"]*(.*)['|"]/,1),
                     "type" => xml.attribute('Type').to_string.slice(/=['|"]*(.*)['|"]/,1),
                     "size" => xml.attribute('SourceFileLength').to_string.slice(/=['|"]*(.*)['|"]/,1)
                   }
    } unless no_filehashconditions
    pc.each { |xml|
      ret_array << { "publisher"  => xml.attribute('PublisherName').to_string.slice(/=['|"]*(.*)['|"]/,1),
                     "product"    => xml.attribute('ProductName').to_string.slice(/=['|"]*(.*)['|"]/,1),
                     "binaryname" => xml.attribute('BinaryName').to_string.slice(/=['|"]*(.*)['|"]/,1),
                     "hi_version" => xml.elements[1].attribute('HighSection').to_string.slice(/=['|"]*(.*)['|"]/,1),
                     "lo_version" => xml.elements[1].attribute('LowSection').to_string.slice(/=['|"]*(.*)['|"]/,1)
                   }
    } unless no_filepublisherconditions
    ret_array
  end

  # Prefetching is necessary to use @property_hash inside any setter methods.
  # self.prefetch uses self.instances to gather an array of user instances
  # on the system, and then populates the @property_hash instance variable
  # with attribute data for the specific instance in question (i.e. it
  # gathers the 'is' values of the resource into the @property_hash instance
  # variable so you don't have to read from the system every time you need
  # to gather the 'is' values for a resource. The downside here is that
  # populating this instance variable for every resource on the system
  # takes time and front-loads your Puppet run.
  def self.prefetch(resources)
    Puppet.debug 'applocker_rule: powershell.rb: prefetch(resources)'
    # the resources object contains all resources in the catalog.
    # the instances method below returns an array of provider objects.
    instances.each do |provider_instance|
      if resource = resources[provider_instance.name]
        resource.provider = provider_instance
      end
    end
  end

  def self.instances
    Puppet.debug 'applocker_rule: powershell.rb: self.instances'
    provider_array = []
    xml_string = ps('Get-AppLockerPolicy -Effective -Xml')
    xml_doc = Document.new xml_string
    xml_doc.root.each_element('RuleCollection') do |rc|
      # REXML Attributes are returned with the attribute and its value, including delimiters.
      # e.g. <RuleCollection Type='Exe' ...> returns "Type='Exe'".
      # So, the value must be parsed using slice.
      rule_collection_type = rc.attribute('Type').to_string.slice(/=['|"]*(.*)['|"]/,1)
      rule_collection_mode = rc.attribute('EnforcementMode').to_string.slice(/=['|"]*(.*)['|"]/,1)
      # must loop through each type of rule tag, I couldn't find how to grab tag name from REXML :/
      rc.each_element('FilePathRule') do |fr|
        rule = {
          ensure:            :present,
          rule_type:         :path,
          type:              rule_collection_type,
          mode:              rule_collection_mode,
          action:            fr.attribute('Action').to_string.slice(/=['|"]*(.*)['|"]/,1),
          name:              fr.attribute('Name').to_string.slice(/=['|"]*(.*)['|"]/,1),
          description:       fr.attribute('Description').to_string.slice(/=['|"]*(.*)['|"]/,1),
          id:                fr.attribute('Id').to_string.slice(/=['|"]*(.*)['|"]/,1),
          user_or_group_sid: fr.attribute('UserOrGroupSid').to_string.slice(/=['|"]*(.*)['|"]/,1),
          conditions:        conditions2hasharray(fr),
          exceptions:        exceptions2array(fr),
        }
        # push new Puppet::Provider object into an array after property hash created.
        provider_array.push(self.new(rule))
      end
      rc.each_element('FilePublisherRule') do |pr|
        rule = {
          ensure:            :present,
          rule_type:         :publisher,
          type:              rule_collection_type,
          mode:              rule_collection_mode,
          action:            pr.attribute('Action').to_string.slice(/=['|"]*(.*)['|"]/,1),
          name:              pr.attribute('Name').to_string.slice(/=['|"]*(.*)['|"]/,1),
          description:       pr.attribute('Description').to_string.slice(/=['|"]*(.*)['|"]/,1),
          id:                pr.attribute('Id').to_string.slice(/=['|"]*(.*)['|"]/,1),
          user_or_group_sid: pr.attribute('UserOrGroupSid').to_string.slice(/=['|"]*(.*)['|"]/,1),
          conditions:        conditions2hasharray(pr),
          exceptions:        exceptions2array(pr),
        }
        # push new Puppet::Provider object into an array after property hash created.
        provider_array.push(self.new(rule))
      end
      rc.each_element('FileHashRule') do |hr|
        rule = {
          ensure:            :present,
          rule_type:         :hash,
          type:              rule_collection_type,
          mode:              rule_collection_mode,
          action:            hr.attribute('Action').to_string.slice(/=['|"]*(.*)['|"]/,1),
          name:              hr.attribute('Name').to_string.slice(/=['|"]*(.*)['|"]/,1),
          description:       hr.attribute('Description').to_string.slice(/=['|"]*(.*)['|"]/,1),
          id:                hr.attribute('Id').to_string.slice(/=['|"]*(.*)['|"]/,1),
          user_or_group_sid: hr.attribute('UserOrGroupSid').to_string.slice(/=['|"]*(.*)['|"]/,1),
          conditions:        conditions2hasharray(hr),
          exceptions:        exceptions2array(hr),
        }
        # push new Puppet::Provider object into an array after property hash created.
        provider_array.push(self.new(rule))
      end
    end
    provider_array
  end

  def exists?
    Puppet.debug 'applocker_rule: powershell.rb: exists?'
    @property_hash[:ensure] == :present
  end

  def create
    begin
      Puppet.debug "applocker_rule: powershell.rb: create [rule_type=#{@resource[:rule_type]}]"
      is_valid_rule_type = [:path, :hash, :publisher].include? @resource[:rule_type]
      raise "applocker_rule: powershell.rb: create: undefined rule type: #{@resource[:rule_type]}" unless is_valid_rule_type
      invalid = @resource[:rule_type].nil? || @resource[:rule_type].empty? || @resource[:user_or_group_sid].nil? || @resource[:user_or_group_sid].empty? || @resource[:name].nil? || @resource[:name].empty?
      raise 'applocker_rule: powershell.rb: create: The applocker_rule create method failed, missing required parameters [rule_type, user_or_group_sid].' if invalid
      # Find the filepath for the FileInformation object
      filepath = ''
      is_filepath_set = false
      conditions_hash = {}
      conditions_hash = @resource[:conditions].first unless @resource[:conditions].nil? || @resource[:conditions].empty?
      # is_conditions_hash_complete = false
      case @resource[:rule_type]
      when :path
        if !@resource[:filepath].nil? && !@resource[:filepath].empty?
          filepath = @resource[:filepath]
          is_filepath_set = true
        elsif !conditions_hash.nil? && !conditions_hash.empty?
          filepath = conditions_hash['path']
          is_filepath_set = true
          # is_conditions_hash_complete = !conditions_hash['path'].empty?
          # Puppet.debug "#{@resource[:rule_type]} rule: is_conditions_hash_complete = #{is_conditions_hash_complete}"
        end
      when :hash
        filepath = @resource[:filepath]
        is_filepath_set = true
        # filehashrules might have multiple files defined in conditions.
        # maybe just support a single file right now via this filepath parameter.
      when :publisher
        filepath = @resource[:filepath]
        is_filepath_set = true
      end
      #
      # TODO: pass this filename to a ps(Get-AppLockerFileInformation) and see if it errors grabbing the publisher information (must pipe to New Publisher Rule to get error).
      no_filepath = filepath.nil? || filepath.empty?
      no_conditions = conditions_hash.nil? || conditions_hash.empty?
      is_incomplete_hash = true
      is_directory = false
      unless no_conditions
        case @resource[:rule_type]
        when :path
          is_incomplete_hash = conditions_hash['path'].nil?
        when :hash
          is_incomplete_hash = conditions_hash['hash'].nil? || conditions_hash['size'].nil? || conditions_hash['file'].nil? || conditions_hash['type'].nil?
        when :publisher
          is_incomplete_hash = conditions_hash['publisher'].nil? || conditions_hash['product'].nil? || conditions_hash['binaryname'].nil? || conditions_hash['hi_version'].nil? || conditions_hash['lo_version'].nil?
        end
      end
      # need to supply a specific file's path to the FileInformation cmdlet, unless a full conditions hash is specified...
      # can only resolve conditions hash between manifest and prefetch if all the keys in the hash are completely specified, or the hash is omitted.
      # condtions property is given precedence over filepath parameter (properties over parameters.)
      invalid_resource = no_filepath && ( no_conditions || is_incomplete_hash )
      use_conditions_hash = !( no_conditions || is_incomplete_hash )
      use_filepath_param = !use_conditions_hash && !no_filepath
      err_msg = "applocker_rule: powershell.rb: create: error creating AppLocker '#{@resource[:name]}' rule: invalid resource definition - no filepath or conditions hash found, please specify either a filepath (parameter) or a complete conditions hash (property); a conditions property takes precedence over the filepath parameter."
      raise err_msg if invalid_resource
      # Environment variable substitution
      # AppLocker only recognizes the "%Variable%" format in the xml attributes,
      # vars are not recognized as an input param to Get-AppLockerFileInformation -Path "%Variable%" <= NOT ALLOWED
      # so must substitute the variables for input into Get-AppLockerFileInformation -Path argument...
      unless no_filepath
        filepath = filepath.gsub(/%[Oo][Ss][Dd][Rr][Ii][Vv][Ee]%/,'$Env:SystemDrive')
        filepath = filepath.gsub(/%[Pp][Rr][Oo][Gg][Rr][Aa][Mm][Ff][Ii][Ll][Ee][Ss]%/,'$Env:ProgramFiles')
        filepath = filepath.gsub(/%[Ww][Ii][Nn][Dd][Ii][Rr]%/,'$Env:WinDir')
        filepath = filepath.gsub(/%[Ss][Yy][Ss][Tt][Ee][Mm]32%/,'$Env:WinDir\System32')
        # The AppLocker variables "%REMOVABLE%" and "%HOT%" will not be recognized by Get-AppLockerFileInformation
        # So, setting is_filepath_set to false, below the Get-AppLockerFileInformation will be fed
        # the dummy value ComSpec to avoid breaking the powershell call.
        is_filepath_set = false if filepath.upcase.include?('%REMOVABLE%') || filepath.upcase.include?('%HOT%')
        is_directory = filepath.end_with?('*','\\','\*')
        # GUI is okay with paths ending in '\*',
        # but Get-AppLockerFileInformation seems to reject some paths.
        # remove trailing slash, *, or *.*
        filepath = filepath[/.*[^\\|*|\.$]/]
      end
      # set filepath to a known o/s file (you know will exist) to supply something for Get-AppLockerFileInformation
      # we can use 'dummy' xml output and set attributes ourselves.
      # For directories, just set -Path to a known file just to generate XML to modify later...
      filepath = '$Env:ComSpec' if no_filepath
      filepath = '$Env:ComSpec' if is_directory
      ps_arg = '-Path'
      # ps_arg = '-Directory' if is_directory
      xml_out = ps("Get-AppLockerFileInformation #{ps_arg} \"#{filepath}\" | New-AppLockerPolicy -Xml -Optimize -RuleType #{@resource[:rule_type]} -User \"#{@resource[:user_or_group_sid]}\"")
      xml_doc = Document.new xml_out
      #
      # The New-AppLockerPolicy cmdlet overwrites some supplied values when it generate the xml
      # Set xml attributes to, again, match what's in the puppet manifest resource declaration.
      # Update 'name', 'description', 'action' properties.  The descrption and action properties are not required.
      # Also update 'type', but note it is associated with an attribute from an element 1 level higher (RuleCollection).
      xml_doc.root.elements[1].attributes['Type'] = @resource[:type] unless @resource[:type].nil?
      xml_doc.root.elements[1].elements[1].attributes['Name'] = @resource[:name] unless @resource[:name].nil? || @resource[:name].empty?
      xml_doc.root.elements[1].elements[1].attributes['Id'] = @resource[:id] unless @resource[:id].nil? || @resource[:id].empty?
      xml_doc.root.elements[1].elements[1].attributes['Description'] = @resource[:description] unless @resource[:description].nil?
      xml_doc.root.elements[1].elements[1].attributes['Action'] = @resource[:action] unless @resource[:action].nil? || @resource[:action].empty?
      #
      # process conditions property
      # NOTE:
      # Get-AppLockerFileInformation sometimes changes the 'path' to include environment vars (e.g. C:\Windows => %WINDIR%)
      # Since we must match the 'path' supplied in the puppet manifest (so the provider knows whether property has changed),
      # set the xml values explicitly to match the resource declaration in the puppet manifest.
      unless no_conditions
        case @resource[:rule_type]
        when :path
          xml_doc.root.elements[1].elements[1].elements[1].elements[1].attributes['Path'] = conditions_hash['path']
        when :hash
          xml_doc.root.elements[1].elements[1].elements[1].elements[1].elements[1].attributes['Data'] = conditions_hash['hash']
          xml_doc.root.elements[1].elements[1].elements[1].elements[1].elements[1].attributes['SourceFileLength'] = conditions_hash['size']
          xml_doc.root.elements[1].elements[1].elements[1].elements[1].elements[1].attributes['SourceFileName'] = conditions_hash['file']
          xml_doc.root.elements[1].elements[1].elements[1].elements[1].elements[1].attributes['Type'] = conditions_hash['type']
        when :publisher
          xml_doc.root.elements[1].elements[1].elements[1].elements[1].attributes['PublisherName'] = conditions_hash['publisher']
          xml_doc.root.elements[1].elements[1].elements[1].elements[1].attributes['ProductName'] = conditions_hash['product']
          xml_doc.root.elements[1].elements[1].elements[1].elements[1].attributes['BinaryName'] = conditions_hash['binaryname']
          xml_doc.root.elements[1].elements[1].elements[1].elements[1].elements[1].attributes['HighSection'] = conditions_hash['hi_version']
          xml_doc.root.elements[1].elements[1].elements[1].elements[1].elements[1].attributes['LowSection'] = conditions_hash['lo_version']
        end
      end
      #
      # process exceptions property
      # NOTE: Limited exceptions support...
      # only supporting an array of filepaths to create filepathrules.
      # support publisher and hash exceptions in a future release.
      exceptions_array = []
      exceptions_array = @resource[:exceptions]
      unless exceptions_array.nil? || exceptions_array.empty?
        # exceptions_node = Element.new 'Exceptions'
        exceptions_node = xml_doc.root.elements[1].elements[1].add_element('Exceptions')
        # exceptions_node = xml_doc.root.get_elements '//Exceptions'
        exceptions_array.each do |path|
          # check for, if !path.strip.empty?, because powershell didn't like an empty path: <FilePathCondition Path=''/>
          exceptions_node.add_element('FilePathCondition', 'Path' => path) if !path.strip.empty?
        end
      end
      #
      # xml complete, use it to create applocker rule...
      Puppet.debug
      Puppet.debug 'applocker_rule: powershell.rb: create: xml_doc (final)...'
      Puppet.debug xml_doc
      Puppet.debug
      testfile = File.open(tempfile, 'w')
      testfile.puts xml_doc
      testfile.close
      # NOTE: Used Set-AppLockerPolicy because New-AppLockerPolicy had an unusual interface.
      # NOTE: The '-Merge' option is very important, use it or it will purge any rules not defined in the Xml.
      ps("Set-AppLockerPolicy -Merge -XMLPolicy #{tempfile}")
      File.unlink(tempfile)
    rescue err
      Puppet.debug "applocker_rule: powershell.rb: create: Error = #{err}"
    end
  end

  def destroy
    Puppet.debug 'applocker_rule: powershell.rb: destroy'
    @property_flush[:ensure] = :absent
    # read all xml
    xml_all_policies = ps('Get-AppLockerPolicy -Effective -Xml')
    xml_doc_should = Document.new xml_all_policies
    x = ''
    case @property_hash[:rule_type]
    when :path
      x = "//FilePathRule[@Id='#{@property_hash[:id]}']"
    when :hash
      x = "//FileHashRule[@Id='#{@property_hash[:id]}']"
    when :publisher
      x = "//FilePublisherRule[@Id='#{@property_hash[:id]}']"
    end
    a = xml_doc_should.root.get_elements x
    del_node = xml_doc_should.root.delete_element x unless a.first.nil?
    Puppet.debug "applocker_rule: powershell.rb: destroy: rexml.element.delete_element = #{del_node}" unless del_node.nil?
    xmlfile = File.open(tempfile, 'w')
    xmlfile.puts xml_doc_should
    xmlfile.close
    # Set-AppLockerPolicy (no merge). Leave off -Merge to update, XML should have all remaining policies.
    ps("Set-AppLockerPolicy -XMLPolicy #{tempfile}")
    File.unlink(tempfile)
  end

  # called when a property is changed.
  # check @property_flush hash for keys to changed properties.
  # at the end of flush, update the @property_hash from the 'is' to 'should' values.
  def flush
    Puppet.debug 'applocker_rule: powershell.rb: flush'
    set
  end

  def set
    Puppet.debug 'applocker_rule: powershell.rb: set'
    # Avoid calling create after a destroy, or a 2nd create call after being created.
    # The property hash is empty when item is created (is it practical to update hash in create?)
    unless @property_flush[:ensure] == :absent || @property_hash.empty?
      # read all xml
      xml_all_policies = ps('Get-AppLockerPolicy -Effective -Xml')
      xml_doc_should = Document.new xml_all_policies
      # an empty applocker query returns this string (after removing whitespaces)...
      unless xml_all_policies.strip == '<AppLockerPolicy Version="1" />'
        begin
          a = xml_doc_should.root.get_elements "//FilePathRule[@Id='#{@property_hash[:id]}']"
          # set attributes if xpath found the element, create element if not found.
          unless a.first.nil?
            # an Array of Elements is returned, so to set Element attributes we must get it from Array first.
            rule = a.first
            rule.attributes['Name'] = @property_hash[:name]
            rule.attributes['Description'] = @property_hash[:description] unless @property_hash[:description].nil?
            rule.attributes['Id'] = @property_hash[:id] unless @property_hash[:id].nil?
            rule.attributes['UserOrGroupSid'] = @property_hash[:user_or_group_sid] unless @property_hash[:user_or_group_sid].nil?
            rule.attributes['Action'] = @property_hash[:action] unless @property_hash[:action].nil?
            # conditions & exceptions are handled by the following method...
            set_other_properties rule
            xmlfile = File.open(tempfile, 'w')
            xmlfile.puts xml_doc_should
            xmlfile.close
            # Set-AppLockerPolicy (no merge)
            # NOTE: The Set-AppLockerPolicy powershell command would not work with the '-Merge' option.
            #       Since I have to leave off -Merge to update, I have to set all the policies.
            #       The -Merge option discards any attribute changes to existing rules.
            ps("Set-AppLockerPolicy -XMLPolicy #{tempfile}")
            File.unlink(tempfile)
          end
        rescue err
          Puppet.debug "applocker_rule: powershell.rb: set Error = #{err}"
        end
      end
    end
  end

  def set_other_properties(node)
    Puppet.debug 'applocker_rule: powershell.rb: set_other_properties'
    c = @property_hash[:conditions]
    e = @property_hash[:exceptions]
    any_conditions = !c.nil? && !c.empty?
    any_exceptions = !e.nil? && !e.empty?
    conditions_hash = {}
    conditions_hash = c.first if any_conditions
    # delete all Rule's children, which are Condition and Exception elements.
    node.elements.delete_all './*'
    if any_conditions
      node_conditions = Element.new 'Conditions'
      case @resource[:rule_type]
      when :path
        node_conditions.add_element('FilePathCondition', 'Path' => conditions_hash['path'])
      when :hash
        xtra_xml_node = node_conditions.add_element('FileHashCondition')
        xtra_xml_node.add_element('FileHash', { 'Data' => conditions_hash['hash'], 'Type' => conditions_hash['type'], 'SourceFileName' => conditions_hash['file'], 'SourceFileLength' => conditions_hash['size'] })
      when :publisher
        xtra_xml_node = node_conditions.add_element('FilePublisherCondition', { 'PublisherName' => conditions_hash['publisher'], 'ProductName' => conditions_hash['product'], 'BinaryName' => conditions_hash['binaryname'] })
        xtra_xml_node.add_element('BinaryVersionRange', { 'HighSection' => conditions_hash['hi_version'], 'LowSection' => conditions_hash['lo_version'] })
      end
      node.add_element node_conditions
    end
    #
    # Exceptions...
    if any_exceptions
      node_exceptions = Element.new 'Exceptions'
      node.add_element node_exceptions
      # check for !path.strip.empty? because powershell didn't like an empty path: <FilePathCondition Path=''/>
      e.each do |path|
        node_exceptions.add_element('FilePathCondition', 'Path' => path) if !path.strip.empty?
      end
    end
    node
  end

  def mergeLDAPPolicies
    # TBD
    # set-applockerpolicy -Merge to interface w/LDAP
  end

  def xml_policy_passthrough
    # TBD
    # create param => xml_policy_filepath
    # allow xml to be executed via Set-AppLockerPolicy
  end

  # This method exists to map the dscl values to the correct Puppet
  # properties. This stays relatively consistent, but who knows what
  # Apple will do next year...
  def self.xml2resource_attribute_map
    {
      'Type'            => :type,
      'EnforcementMode' => :mode,
      'Name'            => :name,
      'Description'     => :description,
      'Id'              => :id,
      'UserOrGroupSid'  => :user_or_group_sid,
      'Action'          => :action,
    }
  end

  def self.resource2xml_attribute_map
    @resource2xml_attribute_map ||= xml2resource_attribute_map.invert
  end

  def clear
    Puppet.debug 'applocker_rule: powershell.rb: clear'
    xml_clear_all_rules = '<AppLockerPolicy Version="1">'
    xml_clear_all_rules << '<RuleCollection Type="Appx" EnforcementMode="NotConfigured" />'
    xml_clear_all_rules << '<RuleCollection Type="Exe" EnforcementMode="NotConfigured" />'
    xml_clear_all_rules << '<RuleCollection Type="Msi" EnforcementMode="NotConfigured" />'
    xml_clear_all_rules << '<RuleCollection Type="Script" EnforcementMode="NotConfigured" />'
    xml_clear_all_rules << '<RuleCollection Type="Dll" EnforcementMode="NotConfigured" />'
    xml_clear_all_rules << '</AppLockerPolicy>'
    clearfile = File.open(tempfile, 'w')
    clearfile.puts xml_clear_all_rules
    clearfile.close
    ps("Set-AppLockerPolicy -XMLPolicy #{tempfile}")
    File.unlink(tempfile)
  end
end
