Pod::Spec.new do |s|
  s.name         = 'GSLCrypto'
  s.version      = '2.0.3'
  s.author       = 'GyazSquare'
  s.license      = { :type => 'MIT' }
  s.homepage     = 'https://github.com/GyazSquare/GSLCrypto'
  s.source       = { :git => 'https://github.com/GyazSquare/GSLCrypto.git', :tag => 'v2.0.3' }
  s.summary      = 'A simple digest library for iOS, macOS, watchOS and tvOS.'
  s.ios.deployment_target = '8.0'
  s.osx.deployment_target = '10.6'
  s.tvos.deployment_target = '9.0'
  s.watchos.deployment_target = '2.0'
  s.requires_arc = true
  s.module_name  = 'GSL'
  s.source_files = 'GSLCrypto/*.{h,m}'
end
