# Root folder where home directories are stored
$rootfolder = Get-ChildItem -Path "\\FileServer\HomeDirectories$"

 foreach ($userfolder in $rootfolder) {
	 # Does this folder match a user in Active Directory?
         If (get-aduser "$userfolder")
         {
             Get-Acl $userfolder.FullName | Format-List
             # Remove the everyone has full control permision
             $acl = Get-Acl $userfolder.FullName
             $acl.SetAccessRuleProtection($True, $False)
             $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
             $acl.RemoveAccessRuleAll($rule)
             
             # Admins have full control
             $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
             $acl.AddAccessRule($rule)

             # User can modify
             $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($userfolder.Name,"Modify", "ContainerInherit, ObjectInherit", "None", "Allow")
             $acl.AddAccessRule($rule)    
             
             # System - Full Control
             $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
             $acl.AddAccessRule($rule)

             # Owner - Full Control
             $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("CREATOR OWNER","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
             $acl.AddAccessRule($rule)

             # Local Admin Owner
             $acct=New-Object System.Security.Principal.NTAccount("BUILTIN","Administrators")
             $acl.SetOwner($acct)

             # Set ACL
             Set-Acl $userfolder.FullName $acl
             #Get-Acl $userfolder.FullName  | Format-List
         }
 }
