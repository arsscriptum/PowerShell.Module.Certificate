


Function Get-TimeStampServer {
[CmdletBinding()]
Param(
	[Parameter(HelpMessage="List of known good timestamp servers")]
	$TimeStampServers = @("http://timestamp.globalsign.com/scripts/timstamp.dll","http://timestamp.comodoca.com/rfc3161")
)
	$TimeStampHostnames = $TimeStampServers -Replace("^http:\/\/","") -Replace ("\/.*","") #Isolate hostnames for Test-NetConnection
	$Count = ($TimeStampHostnames.Count - 1)
	For ($i = 0; $i -le $Count; $i++) {
		Try {
			If ([bool](Test-NetConnection $TimeStampHostnames[$i] -Port 80 | Select-Object -ExpandProperty TcpTestSucceeded)) {
				Write-Verbose "$($TimeStampHostnames[$i]) selected"
				$script:TimeStampServer = $TimeStampServers[$i]
				Break #Once we find a valid server, stop looking.
			}
		}
		Catch {
			Write-Verbose "Could not connect to $($TimeStampHostnames[$i])"
		}
	}
	Return $TimeStampServer
} #End Get-TimeStampServer

Function New-BinarySignature {
[CmdletBinding()]
Param(
	[Parameter(HelpMessage="Specify the path to the file to be signed")]
	[ValidateScript({Test-Path $_ -PathType 'Leaf'})]$BinPath
)

	DynamicParam {
		$ParamName_CodeSigningCert = 'CodeSigningCertName'
		$ParamAttrib  = New-Object System.Management.Automation.ParameterAttribute
		$ParamAttrib.Mandatory  = $true
		$ParamAttrib.ParameterSetName  = '__AllParameterSets'
		$AttribColl = New-Object  System.Collections.ObjectModel.Collection[System.Attribute]
		$AttribColl.Add($ParamAttrib)
		$CodeSigningCertName  = (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object FriendlyName | Where-Object FriendlyName -notlike $Null).FriendlyName
		$AttribColl.Add((New-Object  System.Management.Automation.ValidateSetAttribute($CodeSigningCertName)))
		$RuntimeParam  = New-Object System.Management.Automation.RuntimeDefinedParameter('CodeSigningCertName',  [string], $AttribColl)
		$RuntimeParamDic  = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
		$RuntimeParamDic.Add('CodeSigningCertName',  $RuntimeParam)
		Return $RuntimeParamDic
	}
	Begin {
		$CertFriendlyName = $PSBoundParameters.CodeSigningCertName
	}
	Process {
		Try {
			Get-TimeStampServer
		}
		Catch {
			Write-Error "TimeStampServer could not be reached"
		}
		Write-Verbose $CertFriendlyName
		$CodeSigningCert = Get-ChildItem Cert:\CurrentUser\My | Where-Object FriendlyName -like $CertFriendlyName
		Set-AuthenticodeSignature -Certificate $CodeSigningCert -TimestampServer $TimeStampServer -HashAlgorithm SHA256 -FilePath $BinPath
	}
} #End New-BinarySignature



Function script:New-CodeSigningCert {
[CmdletBinding()]
Param(
	[Parameter(Mandatory=$True,HelpMessage="Certificate subject name")]
	[String]$Subject,

	[Parameter(Mandatory=$True,HelpMessage="Certificate e-mail address")]
	[string]$EMail,

	[Parameter(Mandatory=$True,HelpMessage="Certificate friendly name")]
	[string]$FriendlyName,

	[Parameter(Mandatory=$True,HelpMessage="Certificate PFX password for export")]
	[string]$PFXPassword,

	[Parameter(HelpMessage="Certificate export path")]
	$CertFilePath = $([Environment]::GetFolderPath("Desktop")),

	[Parameter(HelpMessage="Certificate validity in years")]
	[int]$CertValidYears
)

$MajorVersion = [System.Environment]::OSVersion.Version | Select-Object -ExpandProperty Major
If ($MajorVersion -lt 10) {
	Write-Error "Windows 10 / Server 2016 or better is required to use the New-SelfSignedCertificate cmdlet"
	Break
}

$SubjectFull = "CN=$Subject,E=$EMail"
$SecurePassword = ConvertTo-SecureString -String $PFXPassword -AsPlainText -Force

$DuplicateName = Get-ChildItem Cert:\CurrentUser\My | Where-Object FriendlyName -like $FriendlyName
If ($null -notlike $DuplicateName) {
	Write-Warning "An existing certificate exists with this friendly name." -WarningAction Inquire
}

#Generate certificate
$CodeSigningCert = New-SelfSignedCertificate -Type CodeSigningCert -KeyUsage DigitalSignature -KeyAlgorithm RSA -CertStoreLocation "Cert:\CurrentUser\My" -Subject $SubjectFull -NotAfter $(Get-Date).AddYears($CertValidYears) -FriendlyName $FriendlyName

#Export certificate
Export-PfxCertificate -Cert $CodeSigningCert -FilePath $CertFilePath\$FriendlyName.pfx -Password $SecurePassword

#Install cert in root store so it is trusted - Requires RunAsAdministrator in script usage
Import-PfxCertificate -FilePath $CertFilePath\$FriendlyName.pfx -CertStoreLocation "Cert:\LocalMachine\Root\" -Password $SecurePassword
} #End New-CodeSigningCert
