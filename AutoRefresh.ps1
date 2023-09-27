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
        
        Supply an interval in seconds to refresh the token. Default 55 minutes.
    
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
    [Parameter(Mandatory = $True)]
    $RefreshInterval =  (60 * 55),
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
        Start-Sleep -Seconds $InitializationDelay
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
                Start-Sleep -Seconds $RefreshInterval
            }
        } 
}