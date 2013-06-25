Pod::Spec.new do |s|
  s.name     = 'SecureFoundation'
  s.version  = '0.0.0-dev'
  s.summary  = 'iMAS - Secure Foundation'
  s.description = %[
        The "iMAS App Password" framework provides a simple way to include passcode support into your application. It has the logic to enforce passcode strength, and can react to any passcode input. The framework contains two types of passcode controls, a simple passcode (numeric) and a complex passcode (a combination of numbers and characters). The framework utilizes the "iMAS Secure Foundation" framework in order to provide advanced security for both types of controls.
  ]
  s.homepage = 'http://project-imas.github.io'
  s.license  = 'Apache License 2.0'
  s.platform = :ios
  s.authors  = { 'MITRE' => 'project-imas-list@lists.mitre.org' }
  s.source   = { :git => 'https://github.com/project-imas/securefoundation.git' } 
  s.source_files = 'SecureFoundation/**/*.{h,m}'
  s.framework = 'Security'
  s.requires_arc = true
end
