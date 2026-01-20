package trivy

import data.lib.trivy

default ignore = false

ignore {
    # Match any kernel-related package (image, headers, modules)
    kernel_prefixes := ["linux-image-", "linux-headers-", "linux-modules-"]
    startswith(input.PkgName, kernel_prefixes[_])
    
    # Ignore if the package version does NOT match our 'current_kernel' data
    # 'data.current_kernel' comes from our JSON file
    not contains(input.PkgName, data.current_kernel)
}