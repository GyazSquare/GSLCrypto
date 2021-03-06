;;; Directory Local Variables
;;; For more information see (info "(emacs) Directory Variables")

(("GSLCryptoTests"
  . ((objc-mode
      . ((eval . (add-to-list
                  'flycheck-objc-clang-framework-paths
                  (expand-file-name
                   "Platforms/iPhoneOS.platform/Developer/Library/Frameworks"
                   (getenv "DEVELOPER_DIR"))))))))
 (objc-mode
  . ((flycheck-objc-clang-xcrun-sdk . "iphoneos")
     (flycheck-objc-clang-arc . t)
     (flycheck-objc-clang-modules . t)
     (flycheck-objc-clang-archs . ("arm64" "armv7"))
     (flycheck-objc-clang-ios-version-min . "9.0")
     (eval . (set 'flycheck-objc-clang-include-paths
                      (list library-root)))))
 (nil
  . ((eval . (setenv "DEVELOPER_DIR"
                     "/Applications/Xcode.app/Contents/Developer"))
     (fill-column . 80)
     (whitespace-style . (face lines indentation:space))
     (eval . (set (make-local-variable 'project-dir)
                  (file-name-directory
                   (let ((d (or (dir-locals-find-file ".") default-directory)))
                     (if (stringp d) d (car d))))))
     (eval . (set (make-local-variable 'library-root)
                  (expand-file-name "GSLCrypto" project-dir))))))
