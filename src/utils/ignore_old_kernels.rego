package trivy

default ignore = false

ignore {
    # Match any kernel-related package (image, headers, modules)
    kernel_prefixes := ["linux-image-", "linux-headers-", "linux-modules-"]
    startswith(input.PkgName, kernel_prefixes[_])
    
    # Ignore if the package version does NOT match our injected 'current_kernel' data
    not contains(input.PkgName, "{{current_kernel}}")
}