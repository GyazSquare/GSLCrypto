Pod::Spec.new do |s|
  s.name         = 'GSLCrypto'
  s.version      = '0.0.0'
  s.author       = 'GyazSquare'
  s.license      = { :type => 'MIT' }
  s.homepage     = 'https://github.com/GyazSquare/GSLCrypto'
  s.source       = { :git => 'https://github.com/GyazSquare/GSLCrypto.git', :tag => 'v0.0.0' }
  s.summary      = 'A simple digest library for iOS, OS X, watchOS and tvOS.'
  s.ios.deployment_target = '8.0'
  s.osx.deployment_target = '10.6'
  s.tvos.deployment_target = '9.0'
  s.watchos.deployment_target = '2.0'
  s.requires_arc = true
  s.pod_target_xcconfig = {
    'HEADER_SEARCH_PATHS' => '$(inherited) $(PODS_ROOT)/GSLCrypto/CommonCrypto'
  }
  s.user_target_xcconfig = {
    'HEADER_SEARCH_PATHS' => '$(inherited) $(PODS_ROOT)/GSLCrypto/CommonCrypto'
  }
  s.source_files = 'GSLCrypto/*.{h,m}'
  s.preserve_path = 'CommonCrypto/module.modulemap'
end
