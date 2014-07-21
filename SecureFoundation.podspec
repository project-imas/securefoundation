Pod::Spec.new do |s|
    s.name        = 'SecureFoundation'
    s.version     = '1.0'
    s.license     = 'Apache License 2.0'

    s.summary     = 'Secure components enabling application authentication, secure file storage, app level file-based keychain, and shredding for files on disk'
    s.description = %[
        The "iMAS Secure Foundation" project is designed to provide advanced application-level security based on simple encryption mechanisms. It contains four components: a suite of cipher utilities, a collection of functions to assist with encryption through an application key, a file-based keychain replacement, and the ability to shred files on disk.
    ]
    s.homepage    = 'https://github.com/project-imas/securefoundation'
    s.authors     = {
        'MITRE' => 'imas-proj-list@lists.mitre.org'
    }

    s.source      = {
        :git => 'https://github.com/project-imas/securefoundation.git',
        :tag => s.version.to_s
    }
    s.source_files = 'SecureFoundation/**/*.{h,m}'
    s.framework = 'Security'

    s.platform = :ios
    s.requires_arc = true
end
