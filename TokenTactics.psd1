@{
# Script module or binary module file associated with this manifest.
RootModule = 'TokenTactics.psm1'

# Version number of this module.
ModuleVersion = '0.0.2'

# ID used to uniquely identify this module
GUID = '1fd32d8d-69a8-4778-b5b7-7738f81f27f4'

# Author of this module
Author = 'Stephan Borosh & Bobby Cooke'

# Copyright statement for this module
Copyright = 'BSD 3-Clause'

# Description of the functionality provided by this module
Description = 'Azure JSON Web Token ("JWT")Token Manipulation Toolset'

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = '*'

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        Tags = @('security','pentesting','red team','offense','jwt','token','azure')
        LicenseUri = 'https://github.com/rvrsh3ll/TokenTactics/blob/main/LICENSE'
        ProjectUri = 'https://github.com/rvrsh3ll/TokenTactics'

    } # End of PSData hashtable

} # End of PrivateData hashtable

}

