#Email-Stats.ps1
#Created by Joshua Robinson
#version 1
#Pull percentage of emails blocked, total blocked emails based on malicious or inappropriate URLs,
#total emails with a rewritten URL, total emails blocked by AMP, and total emails with verdict updates.
#Built for PowerShell version 5.1

#Added to allow bypass of SSL errors.
add-type @"
   using System.Net;
   using System.Security.Cryptography.X509Certificates;
   public class TrustAllCertsPolicy : ICertificatePolicy {
      public bool CheckValidationResult(
      ServicePoint srvPoint, X509Certificate certificate,
      WebRequest request, int certificateProblem) {
      return true;
   }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

$IP = " " #Add your SMA/SEG IP

#Process to diplay login box
$Cred = Get-Credential -Message "Please enter your credentials for accessing the SEGs."

#get the current year from the host and previous year
$year = get-date -Format yyyy
$old_year = (Get-Date).AddYears(-1).ToString("yyyy")

#Display selection menu and set variable as choice
Write-Host "1. Quarter 1 - January 1 - March 31"
Write-Host "2. Quarter 2 - April 1 - June 30"
Write-Host "3. Quarter 3 - July 1 - September 31"
Write-Host "4. Quarter 4 - October 1 - December 31"
Write-Host "5. Custom Date Search"
$d_selection = Read-Host -Prompt 'Make a selection: '

#Set firstDate and lastDate based on choice. 
#lastDate is set 1 day later to allow for the data on the date requested to be included. 
#SEG API call works from midnight to midnight. 
if ($d_selection -eq 1 )
{
    $firstDate = $year+"-01-01"
    $lastDate = $year+"-04-01"
    $selection_date = "Quarter 1 - January 1 - March 31"
}
if ($d_selection -eq 2 )
{
    $firstDate = $year+"-04-01"
    $lastDate = $year+"-07-01"
    $selection_date = "Quarter 2 - April 1 - June 30"
}
if ($d_selection -eq 3 )
{
    $firstDate = $year+"-07-01"
    $lastDate = $year+"-10-01"
    $selection_date = "Quarter 3 - July 1 - September 31"
}
if ($d_selection -eq 4 )
{
    $firstDate = $old_year+"-10-01"
    $lastDate = $year+"-01-01"
    $selection_date = "Quarter 4 - October 1 - December 31"
}
#Allow for custom date range
#Adds 1 to endDate to allow the date to be included in the results.
if ($d_selection -eq 5 )
{
    $firstDate = Read-Host -Prompt 'Start date yyyy-mm-dd'
    $endDate =  Read-Host -Prompt 'End date yyyy-mm-dd'
    $lastDate = [Datetime]::ParseExact($endDate, "yyyy-MM-dd",$null)
    $lastDate = $lastDate.AddDays(1)
    $lastDate = $lastDate.tostring("yyyy-MM-dd")
    $selection_date = $firstDate+" - "+$endDate
}

#Declare arrays to be used to store data
$threat_emails = @()
$recipients = @()
$URL_Rewrite = @()
$URL_Malicious = @()
$URL_Inappropriate = @()
$AMP_Malicious = @()
$MAR_Total = @()

	
#Encode the provided credentials into a base64 string to be passed to the SEG
$encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($cred.UserName):$($cred.GetNetworkCredential().password)"))

#Create the header required to make the API call. Encoded credentials are passed here. 
$headers = @{
	Authorization = "Basic "+ $encodedCreds
	Cookie = "SEG"
}

#Set the urls that will be used to gather required data.
$url_mail_summary = "https://"+$IP+":6443/sma/api/v2.0/reporting/mail_incoming_traffic_summary?device_type=esa&startDate="+$firstDate+"T04:00:00.000Z&endDate="+$lastDate+"T04:00:00.000Z"
$url_content_filters = "https://"+$IP+":6443/sma/api/v2.0/reporting/mail_content_filter_incoming?device_type=esa&startDate="+$firstDate+"T04:00:00.000Z&endDate="+$lastDate+"T04:00:00.000Z"
$url_amp = "https://"+$IP+":6443/sma/api/v2.0/reporting/mail_incoming_amp_summary?device_type=esa&startDate="+$firstDate+"T04:00:00.000Z&endDate="+$lastDate+"T04:00:00.000Z"
$url_mar = "https://"+$IP+":6443/sma/api/v2.0/reporting/mail_mar_summary?device_type=esa&startDate="+$firstDate+"T04:00:00.000Z&endDate="+$lastDate+"T04:00:00.000Z"

#Send the API call and set results to variable.
$response_email_summary = Invoke-RestMethod -Method GET -Uri $url_mail_summary -Headers $headers -ContentType application/json
$response_content_filters = Invoke-RestMethod -Method GET -Uri $url_content_filters -Headers $headers -ContentType application/json
$response_amp = Invoke-RestMethod -Method GET -Uri $url_amp -Headers $headers -ContentType application/json
$response_mar = Invoke-RestMethod -Method GET -Uri $url_mar -Headers $headers -ContentType application/json

#Add specific results to the corrisponding array created earlier
$threat_emails += $response_email_summary.data.resultSet.total_threat_recipients
$recipients += $response_email_summary.data.resultSet.total_recipients
$URL_Rewrite += $response_content_filters.data.resultSet.recipients_matched.URL_Rewrite_Suspicious
$URL_Malicious += $response_content_filters.data.resultSet.recipients_matched.URL_Quarantine_Malicious
$URL_Inappropriate += $response_content_filters.data.resultSet.recipients_matched.URL_INAPPROPRIATE
$AMP_Malicious += $response_amp.data.resultSet.malware
$MAR_Total += $response_mar.data.resultSet.msgs_total

	
#Clear EncodedCreds from memory 
$EncodedCreds = Get-Random

#Sum the data in each array. 
#Prefrom further calculations as needed.
$all_threat_emails = $threat_emails | Measure-Object -Sum
$all_recipients = $recipients | Measure-Object -Sum
$percent_blocked = ($all_threat_emails.Sum/$all_recipients.Sum).tostring("P")
$all_url_inappropriate = $URL_Inappropriate | Measure-Object -Sum
$all_url_Malicious = $URL_Malicious | Measure-Object -Sum
$all_url_block = $all_url_inappropriate.Sum+$all_url_Malicious.Sum
$all_url_rewrite = $URL_Rewrite | Measure-Object -Sum
$all_amp_malcious = $AMP_Malicious | Measure-Object -Sum
$all_mar = $MAR_Total | Measure-Object -Sum	

#Set final output text
$final_text = "SEG $($selection_date) `n `n$($percent_blocked) of emails were blocked by the SEGs. `n `nURL `nA total of $($all_url_block) emails were quarantined because of a malicious or inappropriate URL. `nA total of $($all_url_rewrite.Sum) emails had an URL rewritten. `n `nAMP `nA total of $($all_amp_malcious.Sum) emails were dropped by AMP. `n `nMAR `nA total of $($all_mar.SUM) emails were flagged after delivery as malicious and INS was notified for further investigation. "

#Send output text to text file in local directory
$final_text | Out-File .\Email-Statistics.txt

#Open text file in the local directory with the default program. 
Invoke-Item .\Email-Statistics.txt 