
<#
	.SYNOPSIS
		Installs Sinequa on the given nodes.
	.DESCRIPTION
		This script runs as a VM extension and installs Sinequa on the cluster nodes. It can be used to setup either a single VM (when run as VM extension) or a cluster (when run from within an ARM template)
	.PARAMETER sinequaSearchVersion
		Version of sinequasearch to install e.g. 1.7.3
    .PARAMETER jdkDownloadLocation
        Url of the JDK installer e.g. http://download.oracle.com/otn-pub/java/jdk/8u65-b17/jdk-8u65-windows-x64.exe
    .PARAMETER sinequaSearchBaseFolder
        Disk location of the base folder of sinequasearch installation.
    .PARAMETER discoveryEndpoints
        Formatted string of the allowed subnet addresses for unicast internode communication e.g. 10.0.0.4-3 is expanded to [10.0.0.4,10.0.0.5,10.0.0.6]
    .PARAMETER sinequaClusterName
        Name of the sinequasearch cluster
    .PARAMETER masterOnlyNode
        Setup a VM as master only node
    .PARAMETER clientOnlyNode
        Setup a VM as client only node
    .PARAMETER dataOnlyNode
        Setup a VM as data only node
	.EXAMPLE
		sinequaSearchVersion 1.7.2 -sinequaClusterName evilescluster -discoveryEndpoints 10.0.0.4-5 -masterOnlyNode
        Installs 1.7.2 version of sinequasearch with cluster name evilescluster and 5 allowed subnet addresses from 4 to 8. Sets up the VM as master node.
    .EXAMPLE
        sinequaSearchVersion 1.7.3 -sinequaSearchBaseFolder software -sinequaClusterName evilescluster -discoveryEndpoints 10.0.0.3-4 -dataOnlyNode
        Installs 1.7.3 version of sinequasearch with cluster name evilescluster and 4 allowed subnet addresses from 3 to 6. Sets up the VM as data node.
#>
Param(
    [Parameter(Mandatory=$true)][string]$sinequaSearchVersion,
    [string]$jdkDownloadLocation,
	[string]$sinequaSearchBaseFolder,
    [string]$discoveryEndpoints,
	[string]$sinequaClusterName,
    [string]$storageKey,
    [string]$marvelEndpoints,
    [switch]$marvelOnlyNode,
	[switch]$masterOnlyNode,
	[switch]$clientOnlyNode,
	[switch]$dataOnlyNode,
	[switch]$m,
	[switch]$jmeterConfig
)

# To set the env vars permanently, need to use registry location
Set-Variable regEnvPath -Option Constant -Value 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment'

function Log-Output(){
	$args | Write-Host -ForegroundColor Cyan
}

function Log-Error(){
	$args | Write-Host -ForegroundColor Red
}

Set-Alias -Name lmsg -Value Log-Output -Description "Displays an informational message in green color" 
Set-Alias -Name lerr -Value Log-Error -Description "Displays an error message in red color" 

function Initialize-Disks{
	
    # Get raw disks
    $disks = Get-Disk | Where partitionstyle -eq 'raw' | sort number
    
    # Get letters starting from F
    $label = 'datadisk-'
    $letters = 70..90 | ForEach-Object { ([char]$_) }
    $letterIndex = 0
	if($disks -ne $null)
	{
        $numberedDisks = $disks.Number -join ','
        lmsg "Found attached VHDs with raw partition and numbers $numberedDisks"
        try{
            foreach($disk in $disks){
                $driveLetter = $letters[$letterIndex].ToString()
                lmsg "Formatting disk...$driveLetter"
		        $disk | Initialize-Disk -PartitionStyle MBR -PassThru |	New-Partition -UseMaximumSize -DriveLetter $driveLetter | Format-Volume -FileSystem NTFS -NewFileSystemLabel "$label$letterIndex" -Confirm:$false -Force | Out-Null
                $letterIndex++
            }
        }catch [System.Exception]{
			lerr $_.Exception.Message
            lerr $_.Exception.StackTrace
			Break
		}
	}
    
    return $letterIndex
}

function Create-DataFolders([int]$numDrives, [string]$folder)
{
    $letters = 70..90 | ForEach-Object { ([char]$_) }

    $pathSet = @(0) * $numDrives
    for($i=0;$i -lt $numDrives;$i++)
    {
        $pathSet[$i] = $letters[$i] + ':\' + $folder
        New-Item -Path $pathSet[$i]  -ItemType Directory | Out-Null
    }

    $retVal = $pathSet -join ','

    lmsg "Created data folders: $retVal" 
    
    return $retVal
}

function Download-Jdk
{
    param(
        [Parameter(Mandatory=$true)]
        [string]$targetDrive,
        [string]$downloadLocation
    )
	# download JDK from a given source URL to destination folder
	try{
			$destination = "$targetDrive`:\Downloads\Java\jdk-8u65-windows-x64.exe"
			$source = if ($downloadLocation -eq '') {'http://download.oracle.com/otn-pub/java/jdk/8u65-b17/jdk-8u65-windows-x64.exe'} else {$downloadLocation}
            
            # create folder if doesn't exists and suppress the output
            $folder = split-path $destination
            if (!(Test-Path $folder)) {
                New-Item -Path $folder -ItemType Directory | Out-Null
            }

			$client = new-object System.Net.WebClient 
			$cookie = "oraclelicense=accept-securebackup-cookie"

            lmsg "Downloading JDK from $source to $destination"

			$client.Headers.Add([System.Net.HttpRequestHeader]::Cookie, $cookie) 
			$client.downloadFile($source, $destination) | Out-Null
		}catch [System.Net.WebException],[System.Exception]{
			lerr $_.Exception.Message
            lerr $_.Exception.StackTrace
			Break
		}

	return $destination
}

function Install-Jdk
{
    param(
        [Parameter(Mandatory=$true)]
        [string]$sourceLoc,
        [Parameter(Mandatory=$true)]
        [string]$targetDrive
    )

	$installPath = "$targetDrive`:\Program Files\Java\Jdk"

    $homefolderPath = (Get-Location).Path
    $logPath = "$homefolderPath\java_install_log.txt"
    $psLog = "$homefolderPath\java_install_ps_log.txt"
    $psErr = "$homefolderPath\java_install_ps_err.txt"

	try{
        lmsg "Installing java on the box under $installPath..."
		$proc = Start-Process -FilePath $sourceLoc -ArgumentList "/s INSTALLDIR=`"$installPath`" /L `"$logPath`"" -Wait -PassThru -RedirectStandardOutput $psLog -RedirectStandardError $psErr -NoNewWindow
        $proc.WaitForExit()
        lmsg "JDK installed under $installPath" "Log file location: $logPath"
        
        #if($proc.ExitCode -ne 0){
            #THROW "JDK installation error"
        #}
		
    }catch [System.Exception]{
		lerr $_.Exception.Message
        lerr $_.Exception.StackTrace
	    Break
	}
	
	return $installPath
}

function Download-sinequaSearch
{
    param(
        [Parameter(Mandatory=$true)]
        [string]$sinequaVersion,
        [Parameter(Mandatory=$true)]
        [string]$targetDrive
    )
	# download sinequaSearch from a given source URL to destination folder
	try{
			$source = if ($sinequaVersion -match '2.') {"https://download.sinequasearch.org/sinequasearch/release/org/sinequasearch/distribution/zip/sinequasearch/$sinequaVersion/sinequasearch-$sinequaVersion.zip"} else { "https://download.sinequa.co/sinequasearch/sinequasearch/sinequasearch-$sinequaVersion.zip" }
			$destination = "$targetDrive`:\Downloads\sinequaSearch\sinequa-Search.zip"
            
            # create folder if doesn't exists and suppress the output
            $folder = split-path $destination
            if (!(Test-Path $folder)) {
                New-Item -Path $folder -ItemType Directory | Out-Null
            }

			$client = new-object System.Net.WebClient 

            lmsg "Downloading sinequasearch version $sinequaVersion from $source to $destination"

			$client.downloadFile($source, $destination) | Out-Null
		}catch [System.Net.WebException],[System.Exception]{
			lerr $_.Exception.Message
            lerr $_.Exception.StackTrace
			Break
		}

	return $destination
}

function Unzip-Archive($archive, $destination){
	
	$shell = new-object -com shell.application

	$zip = $shell.NameSpace($archive)
	
	# Test destination folder
	if (!(Test-Path $destination))
	{
        lmsg "Creating $destination folder"
		New-Item -Path $destination -ItemType Directory | Out-Null
    }

	$destination = $shell.NameSpace($destination)

    #TODO a progress dialog pops up though not sure of its effect on the deployment
	$destination.CopyHere($zip.Items())
}

function SetEnv-JavaHome($jdkInstallLocation)
{
    $homePath = $jdkInstallLocation
    
    lmsg "Setting JAVA_HOME in the registry to $homePath..."
	Set-ItemProperty -Path $regEnvPath -Name JAVA_HOME -Value $homePath | Out-Null
    
    lmsg 'Setting JAVA_HOME for the current session...'
    Set-Item Env:JAVA_HOME "$homePath" | Out-Null

    # Additional check
    if ([environment]::GetEnvironmentVariable("JAVA_HOME","machine") -eq $null)
	{
	    [environment]::setenvironmentvariable("JAVA_HOME",$homePath,"machine") | Out-Null
	}

    lmsg 'Modifying path variable to point to java executable...'
    $currentPath = (Get-ItemProperty -Path $regEnvPath -Name PATH).Path
    $currentPath = $currentPath + ';' + "$homePath\bin"
    Set-ItemProperty -Path $regEnvPath -Name PATH -Value $currentPath
    Set-Item Env:PATH "$currentPath"
}

function SetEnv-HeapSize
{
    # Obtain total memory in MB and divide in half
    $halfRamCnt = [math]::Round(((Get-WmiObject Win32_PhysicalMemory | measure-object Capacity -sum).sum/1mb)/2,0)
    $halfRamCnt = [math]::Min($halfRamCnt, 31744)
    $halfRam = $halfRamCnt.ToString() + 'm'
    lmsg "Half of total RAM in system is $halfRam mb."

    lmsg "Setting ES_HEAP_SIZE in the registry to $halfRam..."
	Set-ItemProperty -Path $regEnvPath -Name ES_HEAP_SIZE -Value $halfRam | Out-Null

    lmsg 'Setting ES_HEAP_SIZE for the current session...'
    Set-Item Env:ES_HEAP_SIZE $halfRam | Out-Null

    # Additional check
    if ([environment]::GetEnvironmentVariable("ES_HEAP_SIZE","machine") -eq $null)
	{
	    [environment]::setenvironmentvariable("ES_HEAP_SIZE",$halfRam,"machine") | Out-Null
	}
}


function Install-sinequaSearch ($driveLetter, $sinequaSearchZip, $subFolder = $sinequaSearchBaseFolder)
{
	
	# Designate unzip location 
	$sinequaSearchPath =  Join-Path "$driveLetter`:" -ChildPath $subFolder
	
	# Unzip
	Unzip-Archive $sinequaSearchZip $sinequaSearchPath

	return $sinequaSearchPath
}

function Implode-Host([string]$discoveryHost)
{
    # Discovery host must be in a given format e.g. 10.0.0.4-3 for the below code to work
    $discoveryHost = $discoveryHost.Trim()

    $ipPrefix = $discoveryHost.Substring(0, $discoveryHost.LastIndexOf('.'))
    $dotSplitArr = $discoveryHost.Split('.')
    $lastDigit = $dotSplitArr[$dotSplitArr.Length-1].Split('-')[0]
    $loop = $dotSplitArr[$dotSplitArr.Length-1].Split('-')[1]

    $ipRange = @(0) * $loop
    for($i=0; $i -lt $loop; $i++)
    {
        $format = "$ipPrefix." + ($i+ $lastDigit)
        $ipRange[$i] = '"' +$format + '"'
    }

    $addresses = $ipRange -join ','
    return $addresses
}

function Implode-Host2([string]$discoveryHost)
{
    # Discovery host must be in a given format e.g. 10.0.0.1-3 for the below code to work
    # 10.0.0.1-3 would be converted to "10.0.0.10 10.0.0.11 10.0.0.12"
    $discoveryHost = $discoveryHost.Trim()

    $dashSplitArr = $discoveryHost.Split('-')
    $prefixAddress = $dashSplitArr[0]
    $loop = $dashSplitArr[1]

    $ipRange = @(0) * $loop
    for($i=0; $i -lt $loop; $i++)
    {
        $format = "$prefixAddress$i"
        $ipRange[$i] = '"' +$format + '"'
    }

    $addresses = $ipRange -join ','
    return $addresses
}


function sinequaSearch-InstallService($scriptPath)
{
	# Install and start Sinequa as a service
	$sinequaService = (get-service | Where-Object {$_.Name -match "sinequasearch"}).Name
	if($sinequaService -eq $null) 
    {	
        # First set heap size
        SetEnv-HeapSize

        lmsg 'Installing sinequasearch as a service...'
        cmd.exe /C "$scriptPath install"
        if ($LASTEXITCODE) {
            throw "Command '$scriptPath': exit code: $LASTEXITCODE"
        }
    }
}


function sinequaSearch-StartService()
{
    # Check if the service is installed and start it
    $sinequaService = (get-service | Where-Object {$_.Name -match 'sinequasearch'}).Name
    if($sinequaService -ne $null)
    {
        lmsg 'Starting sinequasearch service...'
        Start-Service -Name $sinequaService | Out-Null
        $svc = Get-Service | Where-Object { $_.Name -Match 'sinequasearch'}
        
        if($svc -ne $null)
        {
            $svc.WaitForStatus('Running', '00:00:10')
        }

		lmsg 'Setting the sinequasearch service startup to automatic...'
        Set-Service $sinequaService -StartupType Automatic | Out-Null
    }
}

function sinequaSearch-VerifyInstall
{
    $esRequest = [System.Net.WebRequest]::Create("http://localhost:9200")
    $esRequest.Method = "GET"
	$esResponse = $esRequest.GetResponse()
	$reader = new-object System.IO.StreamReader($esResponse.GetResponseStream())
	lmsg 'sinequaSearch service response status: ' $esResponse.StatusCode
	lmsg 'sinequaSearch service response full text: ' $reader.ReadToEnd()
}

function Jmeter-Download($drive)
{
	try{
			$destination = "$drive`:\Downloads\Jmeter\Jmeter_server_agent.zip"
			$source = 'http://jmeter-plugins.org/downloads/file/ServerAgent-2.2.1.zip'
            
            # create folder if doesn't exists and suppress the output
            $folder = split-path $destination
            if (!(Test-Path $folder)) {
                New-Item -Path $folder -ItemType Directory | Out-Null
            }

			$client = new-object System.Net.WebClient 

            lmsg "Downloading Jmeter SA from $source to $destination"

			$client.downloadFile($source, $destination) | Out-Null
		}catch [System.Net.WebException],[System.Exception]{
			lerr $_.Exception.Message
            lerr $_.Exception.StackTrace
			Break
		}
    
    return $destination
}

function Jmeter-Unzip($source, $drive)
{
    # Unzip now
    $shell = new-object -com shell.application

	$zip = $shell.NameSpace($source)

    $loc = "$drive`:\jmeter_sa"
	
	# Test destination folder
	if (!(Test-Path $loc))
	{
        lmsg "Creating $loc folder"
		New-Item -Path $loc -ItemType Directory | Out-Null
    }

	$locShell = $shell.NameSpace($loc)

    #TODO a progress dialog pops up though not sure of its effect on the deployment
	$locShell.CopyHere($zip.Items())

    return $loc
}

function Jmeter-ConfigFirewall
{
    for($i=4440; $i -le 4444; $i++)
    {
        lmsg 'Adding firewall rule - Allow Jmeter Inbound Port ' $i
        New-NetFirewallRule -Name "Jmeter_ServerAgent_IN_$i" -DisplayName "Allow Jmeter Inbound Port $i" -Protocol tcp -LocalPort $i -Action Allow -Enabled True -Direction Inbound | Out-Null
    
        lmsg 'Adding firewall rule - Allow Jmeter Outbound Port ' $i
        New-NetFirewallRule -Name "Jmeter_ServerAgent_OUT_$i" -DisplayName "Allow Jmeter Outbound Port $i" -Protocol tcp -LocalPort $i -Action Allow -Enabled True -Direction Outbound | Out-Null
    }
}

function sinequasearch-OpenPorts
{
	# Add firewall rules
    lmsg 'Adding firewall rule - Allow sinequasearch Inbound Port 9200'
    New-NetFirewallRule -Name 'sinequaSearch_In_Lb' -DisplayName 'Allow sinequasearch Inbound Port 9200' -Protocol tcp -LocalPort 9200 -Action Allow -Enabled True -Direction Inbound | Out-Null

    lmsg 'Adding firewall rule - Allow sinequasearch Outbound Port 9200 for Marvel'
    New-NetFirewallRule -Name 'sinequaSearch_Out_Lb' -DisplayName 'Allow sinequasearch Outbound Port 9200 for Marvel' -Protocol tcp -LocalPort 9200 -Action Allow -Enabled True -Direction Outbound | Out-Null

    lmsg 'Adding firewall rule - Allow sinequasearch Inter Node Communication Inbound Port 9300'
    New-NetFirewallRule -Name 'sinequaSearch_In_Unicast' -DisplayName 'Allow sinequasearch Inter Node Communication Inbound Port 9300' -Protocol tcp -LocalPort 9300 -Action Allow -Enabled True -Direction Inbound | Out-Null
    
    lmsg 'Adding firewall rule - Allow sinequasearch Inter Node Communication Outbound Port 9300'
    New-NetFirewallRule -Name 'sinequaSearch_Out_Unicast' -DisplayName 'Allow sinequasearch Inter Node Communication Outbound Port 9300' -Protocol tcp -LocalPort 9300 -Action Allow -Enabled True -Direction Outbound | Out-Null

}

function Jmeter-Run($unzipLoc)
{
    $targetPath = Join-Path -Path $unzipLoc -ChildPath 'startAgent.bat'

    lmsg 'Starting jmeter server agent at ' $targetPath
    Start-Process -FilePath $targetPath -WindowStyle Minimized | Out-Null
}

function Install-WorkFlow
{
	# Start script
    Startup-Output
	
    # Discover raw data disks and format them
    $dc = Initialize-Disks
    
    # Create data folders on raw disks
    if($dc -gt 0)
    {
        $folderPathSetting = (Create-DataFolders $dc 'sinequasearch\data')
    }

	# Set first drive
    $firstDrive = (get-location).Drive.Name
    
    # Download Jdk
	$jdkSource = Download-Jdk $firstDrive
	
	# Install Jdk
	$jdkInstallLocation = Install-Jdk $jdkSource $firstDrive

	# Download Sinequa zip
	$sinequaSearchZip = Download-sinequaSearch $sinequaSearchVersion $firstDrive
	
	# Unzip (install) Sinequa
	if($sinequaSearchBaseFolder.Length -eq 0) { $sinequaSearchBaseFolder = 'sinequaSearch'}
	$sinequaSearchInstallLocation = Install-sinequaSearch $firstDrive $sinequaSearchZip

	# Set JAVA_HOME
    SetEnv-JavaHome $jdkInstallLocation
	
	# Configure cluster name and other properties
		
		# Cluster name
		if($sinequaClusterName.Length -eq 0) { $sinequaClusterName = 'sinequasearch_cluster' }
        
        # Unicast host setup
        if($discoveryEndpoints.Length -ne 0) { $ipAddresses = Implode-Host2 $discoveryEndpoints }
		
		# Extract install folders
		$sinequaSearchBinParent = (gci -path $sinequaSearchInstallLocation -filter "bin" -Recurse).Parent.FullName
		$sinequaSearchBin = Join-Path $sinequaSearchBinParent -ChildPath "bin"
		$sinequaSearchConfFile = Join-Path $sinequaSearchBinParent -ChildPath "config\sinequasearch.yml"
		
		# Set values
        lmsg "Configure cluster name to $sinequaClusterName"
        $textToAppend = "`n#### Settings automatically added by deployment script`ncluster.name: $sinequaClusterName"

        # Use hostname for node name
        $hostname = (Get-WmiObject -Class Win32_ComputerSystem -Property Name).Name
        $textToAppend = $textToAppend + "`nnode.name: $hostname"

        # Set data paths
        if($folderPathSetting -ne $null)
        {
            $textToAppend = $textToAppend + "`npath.data: $folderPathSetting"
        }

        if($masterOnlyNode)
        {
            lmsg 'Configure node as master only'
            $textToAppend = $textToAppend + "`nnode.master: true`nnode.data: false"
        }
        elseif($dataOnlyNode)
        {
            lmsg 'Configure node as data only'
            $textToAppend = $textToAppend + "`nnode.master: false`nnode.data: true"
        }
        elseif($clientOnlyNode)
        {
            lmsg 'Configure node as client only'
            $textToAppend = $textToAppend + "`nnode.master: false`nnode.data: false"
        }
        else
        {
            lmsg 'Configure node as master and data'
            $textToAppend = $textToAppend + "`nnode.master: true`nnode.data: true"
        }

		$textToAppend = $textToAppend + "`ndiscovery.zen.minimum_master_nodes: 2"
        $textToAppend = $textToAppend + "`ndiscovery.zen.ping.multicast.enabled: false"

        if($ipAddresses -ne $null)
        {
            $textToAppend = $textToAppend + "`ndiscovery.zen.ping.unicast.hosts: [$ipAddresses]"
        }

        # In ES 2.x you explicitly need to set network host to _non_loopback_ or the IP address of the host else other nodes cannot communicate
        if ($sinequaSearchVersion -match '2.')
        {
            $textToAppend = $textToAppend + "`nnetwork.host: _non_loopback_"
        }

        # configure marvel as required
        if($marvelEndpoints.Length -ne 0)
        {
            $marvelIPAddresses = Implode-Host2 $marvelEndpoints
            if ($sinequaSearchVersion -match '2.')
            {
                $textToAppend = $textToAppend + "`nmarvel.agent.exporters:`n  id1:`n    type: http`n    host: [$marvelIPAddresses]"
            }
            else
            {
                $textToAppend = $textToAppend + "`nmarvel.agent.exporter.hosts: [$marvelIPAddresses]"
            }
        }
        
        if ($marvelOnlyNode -and ($sinequaSearchVersion -match '1.'))
        {
            $textToAppend = $textToAppend + "`nmarvel.agent.enabled: false"
        }

        Add-Content $sinequaSearchConfFile $textToAppend
		
    # Add firewall exceptions
    sinequasearch-OpenPorts

    # Install service using the batch file in bin folder
    $scriptPath = Join-Path $sinequaSearchBin -ChildPath "service.bat"
    sinequaSearch-InstallService $scriptPath

    # Start service
    sinequaSearch-StartService

    # Install marvel if specified
    if ($m)
    {
        if ($sinequaSearchVersion -match '2.')
        {
            cmd.exe /C "$sinequaSearchBin\plugin.bat install license"
            cmd.exe /C "$sinequaSearchBin\plugin.bat install marvel-agent"
        }
        else
        {
            cmd.exe /C "$sinequaSearchBin\plugin.bat -i sinequasearch/marvel/1.3.1"
        }
    }		
		
	# Temporary measure to configure each ES node for JMeter server agent
	if ($jmeterConfig)
	{
		$jmZip = Jmeter-Download $firstDrive
		$unzipLocation = Jmeter-Unzip $jmZip $firstDrive
		Jmeter-ConfigFirewall
		Jmeter-Run $unzipLocation
	}


    # Verify service TODO: Investigate why verification fails during ARM deployment
    # sinequaSearch-VerifyInstall
}

function Startup-Output
{
    lmsg 'Install workflow starting with following params:'
    lmsg "sinequasearch version: $sinequaSearchVersion"
    if($sinequaClusterName.Length -ne 0) { lmsg "sinequasearch cluster name: $sinequaClusterName" }
    if($jdkDownloadLocation.Length -ne 0) { lmsg "Jdk download location: $jdkDownloadLocation" }
    if($sinequaSearchBaseFolder.Length -ne 0) { lmsg "sinequasearch base folder: $sinequaSearchBaseFolder" }
    if($discoveryEndpoints.Length -ne 0) { lmsg "Discovery endpoints: $discoveryEndpoints" }
    if($marvelEndpoints.Length -ne 0) { lmsg "Marvel endpoints: $marvelEndpoints" }
    if($masterOnlyNode) { lmsg 'Node installation mode: Master' }
    if($clientOnlyNode) { lmsg 'Node installation mode: Client' }
    if($dataOnlyNode) { lmsg 'Node installation mode: Data' }
    if($marvelOnlyNode) { lmsg 'Node installation mode: Marvel' }
}

Install-WorkFlow