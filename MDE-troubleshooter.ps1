# Author: Thomas Verheyden
# Created: 28.06.2023
# Update: 15.01.2025
# Version: 1.5
# Blogpost: https://vertho.tech/2023/06/30/tool-mde-troubleshooter-is-born/
# Website: vertho.tech
# Twitter: @thomasvrhydn
# Disclaimer: Script provided as is. Use at own risk. No guarantees or warranty provided.

<#

README:

This tool is designed to assist you in analyzing issues related to Defender for Endpoint on your local endpoint. It offers a centralized view of the security configuration, log files, updates, and provides access to the Performance Analyzer.

Please note that this is the initial version of the tool. If you encounter any bugs or have suggestions for enhancements, I encourage you to submit them on my GitHub page. Your feedback and reports are greatly appreciated.
This is the first version of the tool. Bugs and reports can be submitted at my github.

References:

https://github.com/ugurkocde/Intune/blob/main/Defender%20for%20Endpoint/MDE%20-%20Update%20Tool/MDE_Update_Tool.ps1
https://github.com/directorcia/Office365/blob/master/win10-asr-get.ps1
ASR Overview - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/overview-attack-surface-reduction
Reduce attack surfaces with attack surface reduction rules - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction
ASR FAQ - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction-faq



#>


[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
[xml]$xaml = @"
<Window 
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:WpfApp1"
        Title="MDE troubleshooter" Height="648" Width="841" WindowStyle="ToolWindow" ResizeMode="NoResize" Background="White">

    <Grid Name="MainWindow1" Width="800" Margin="52,24,53,69">

        <Border BorderBrush="Black" BorderThickness="1" HorizontalAlignment="Left" Height="127" Margin="0,394,0,0" VerticalAlignment="Top" Width="302"/>
        <Border BorderBrush="Black" BorderThickness="1" HorizontalAlignment="Left" Height="130" Margin="512,391,0,0" VerticalAlignment="Top" Width="214"/>

        <Border BorderBrush="Black" BorderThickness="1" HorizontalAlignment="Left" Height="303" Margin="508,44,0,0" VerticalAlignment="Top" Width="212"/>

        <Border BorderBrush="Black" BorderThickness="1" HorizontalAlignment="Left" Height="304" Margin="0,43,0,0" VerticalAlignment="Top" Width="302"/>

        <Label Name="lblPUAProtect_text" Content="N/A PUAProtect" HorizontalAlignment="Left" Margin="160,231,0,0" VerticalAlignment="Top" FontStyle="Italic" RenderTransformOrigin="0.5,0.5" Width="151">
            <Label.RenderTransform>
                <TransformGroup>
                    <ScaleTransform/>
                    <SkewTransform/>
                    <RotateTransform Angle="-0.446"/>
                    <TranslateTransform/>
                </TransformGroup>
            </Label.RenderTransform>
        </Label>
        <Label Name="lblAMServiceVersion" Content="AMServiceVersion:" Margin="7,121,673,4" VerticalAlignment="Top" Height="24" FontWeight="Bold" Width="120"/>
        <Label Name="lblSignatureVersion" Content="SignatureVersion:" Margin="7,135,673,0" VerticalAlignment="Top" Height="26" RenderTransformOrigin="0.406,-1.147" FontWeight="Bold" Width="120"/>
        <Label Name="lblAMEngineVersion" Content="AMEngineVersion:" Margin="7,73,673,4" VerticalAlignment="Top" Height="36" FontWeight="Bold" Width="120"/>
        <Label Name="lblTamperSource" Content="TamperSource:" Margin="7,149,673,0" VerticalAlignment="Top" Height="25" FontWeight="Bold" Width="120"/>
        <Label Name="lblAMRunningMode" Content="AMRunningMode:" Margin="7,106,673,4" VerticalAlignment="Top" Height="30" FontWeight="Bold" Width="120"/>
        <Label Name="lblAMProductVersion" Content="AMProductVersion:" Margin="7,91,673,4" VerticalAlignment="Top" Height="25" FontWeight="Bold" Width="120"/>
        <Label Name="lblTamper" Content="TamperProtection:" Margin="7,163,673,0" VerticalAlignment="Top" Height="26" FontWeight="Bold" Width="120"/>
        <Label Name="lblSigUpdates" Content="Signature Last Update:" Margin="7,177,653,0" VerticalAlignment="Top" Height="32" FontWeight="Bold"/>
        <Label Name="lblSignatureFallBackOrder" Content="SignatureFallBackOrder:" Margin="7,191,647,0" VerticalAlignment="Top" Height="35" RenderTransformOrigin="0.406,-1.147" FontWeight="Bold"/>
        <Label Name="lblSettings" Content="Defender AV:" HorizontalAlignment="Left" Margin="7,43,0,0" VerticalAlignment="Top" Height="30" Width="128" FontWeight="Bold" FontSize="16"/>
        <Label Name="lblAMEngineVersion_txt" Content="N/A Engine Version" HorizontalAlignment="Left" Margin="160,74,0,0" VerticalAlignment="Top" FontStyle="Italic" Width="120"/>
        <Label Name="lblTamper_txt" Content="N/A lblTamper" HorizontalAlignment="Left" Margin="160,165,0,0" VerticalAlignment="Top" FontStyle="Italic" Width="120"/>
        <Label Name="lblTamperSource_txt" Content="N/A TamperSource" HorizontalAlignment="Left" Margin="160,152,0,0" VerticalAlignment="Top" FontStyle="Italic" Width="120"/>
        <Label Name="lblAMRunningMode_txt" Content="N/A Running" HorizontalAlignment="Left" Margin="160,108,0,0" VerticalAlignment="Top" FontStyle="Italic" Width="120"/>
        <Label Name="lblAMServiceVersion_txt" Content="N/A ServiceVersion" HorizontalAlignment="Left" Margin="160,122,0,0" VerticalAlignment="Top" FontStyle="Italic" Width="120"/>
        <Label Name="lblAMProductVersion_txt" Content="N/A Product Version" HorizontalAlignment="Left" Margin="160,92,0,0" VerticalAlignment="Top" RenderTransformOrigin="0.97,0.497" FontStyle="Italic" Width="120"/>
        <Label Name="lblSigUpdates_txt" Content="N/A SigUpdates" HorizontalAlignment="Left" Margin="160,179,0,0" VerticalAlignment="Top" FontStyle="Italic" Width="120"/>
        <Label Name="lblSignatureFallBackOrder_txt" Content="N/A Fallback Order" HorizontalAlignment="Left" Margin="160,193,0,0" VerticalAlignment="Top" FontStyle="Italic" Width="120"/>
        <Button Name="btnRunPerformance" Content="Run Performance Analyze" HorizontalAlignment="Left" Margin="528,83,0,0" VerticalAlignment="Top" Width="178" FontWeight="Bold" BorderBrush="#FF0E0D0D" Background="#FF707070" RenderTransformOrigin="0.5,0.5" >
            <Button.RenderTransform>
                <TransformGroup>
                    <ScaleTransform/>
                    <SkewTransform/>
                    <RotateTransform/>
                    <TranslateTransform X="-2"/>
                </TransformGroup>
            </Button.RenderTransform>
        </Button>
        <Button Name="btnShowPerformanceReport" Content="ShowPerformanceReport" HorizontalAlignment="Left" Margin="528,113,0,0" VerticalAlignment="Top" Width="178" FontWeight="Bold" IsEnabled="False" BorderBrush="#FF0E0D0D" Background="#FF707070"/>
        <CheckBox Name="rdbTopfiles" Content="Top 10 Files " HorizontalAlignment="Left" Margin="528,157,0,0" VerticalAlignment="Top" IsChecked="True" IsEnabled="False"/>
        <CheckBox Name="rdbTopExtensions" Content="Top 10 Extensions" HorizontalAlignment="Left" Margin="528,178,0,0" VerticalAlignment="Top" IsEnabled="False"/>
        <CheckBox Name="rdbTopProcess" Content="Top 10 Processes" HorizontalAlignment="Left" Margin="528,198,0,0" VerticalAlignment="Top" IsEnabled="False"/>
        <CheckBox Name="rdbTopScans" Content="Top 10 Scans" HorizontalAlignment="Left" Margin="528,218,0,0" VerticalAlignment="Top" IsEnabled="False"/>
        <Button Name="btnShowSenseLogs" Content="Show Sense logs" HorizontalAlignment="Left" Margin="534,398,0,0" VerticalAlignment="Top" RenderTransformOrigin="0.486,-5.099" Width="178" FontWeight="Bold" Background="#FF707070" BorderBrush="#FF707070"/>
        <Button Name="btnShowDefenderAVLogs" Content="Show Defender AV logs" HorizontalAlignment="Left" Margin="534,441,0,0" VerticalAlignment="Top" Width="178" FontWeight="Bold" Background="#FF707070" BorderBrush="#FF0E0D0D"/>
        <Label Name="lblComputerName" Content="ComputerName" HorizontalAlignment="Left" Margin="7,0,0,0" VerticalAlignment="Top" FontSize="16" FontWeight="Bold"/>
        <Label Name="lblSignatureVersion_txt" Content="N/A Signature Version" HorizontalAlignment="Left" Margin="160,137,0,0" VerticalAlignment="Top" FontStyle="Italic" Width="151"/>
        <Label Name="lblOrgID" Content="OrgID:" HorizontalAlignment="Left" Margin="373,5,0,0" VerticalAlignment="Top" Height="26" Width="150" RenderTransformOrigin="0.406,-1.147" FontSize="11" FontWeight="Bold"/>
        <Label Name="lblOrgID_txt" Content="OrgID GUID N/A" HorizontalAlignment="Left" Margin="425,5,0,0" VerticalAlignment="Top" Height="26" Width="320" RenderTransformOrigin="0.406,-1.147" FontSize="11" FontStyle="Italic"/>
        <Label Name="lblSettings_Copy1" Content="Performance Tooling:" HorizontalAlignment="Left" Margin="523,47,0,0" VerticalAlignment="Top" Height="31" Width="106" FontWeight="Bold" FontSize="16"/>
        <Label Name="lblLastestEngineVersion" Content="MS lastest Engine:" HorizontalAlignment="Left" Margin="7,399,0,0" VerticalAlignment="Top" Height="25" Width="152" FontWeight="Bold"/>
        <Label Name="lblLastestEngineVersion_txt" Content="N/A Engine Version" HorizontalAlignment="Left" Margin="160,402,0,0" VerticalAlignment="Top" FontStyle="Italic"/>
        <Label Name="lblLastestPlatformVersion" Content="MS lastest Platform:" HorizontalAlignment="Left" Margin="7,415,0,0" VerticalAlignment="Top" Height="25" Width="152" FontWeight="Bold"/>
        <Label Name="lblLastestPlatformVersion_txt" Content="N/A Platform Version" HorizontalAlignment="Left" Margin="160,417,0,0" VerticalAlignment="Top" FontStyle="Italic"/>
        <Label Name="lblLatestSigVersion" Content="MS lastest Signature:" HorizontalAlignment="Left" Margin="7,429,0,0" VerticalAlignment="Top" Height="42" Width="152" FontWeight="Bold"/>
        <Label Name="lblLatestSigVersion_txt" Content="N/A Signature Version" HorizontalAlignment="Left" Margin="160,431,0,0" VerticalAlignment="Top" FontStyle="Italic"/>
        <Button Name="btnExclusions" Content="Show Exclusions" HorizontalAlignment="Left" Margin="536,484,0,0" VerticalAlignment="Top" Width="174" FontWeight="Bold" Background="#FF707070" BorderBrush="#FF0E0D0D"/>
        <Button Name="btnCheckForLastestUpdate" Content="Check for latest Updates" HorizontalAlignment="Left" Margin="111,462,0,0" VerticalAlignment="Top" Width="175" FontWeight="Bold" Background="#FF707070" BorderBrush="#FF101010"/>
        <Label Name="lblCloudBlockLevel" Content="CloudBlockLevel:" Margin="7,217,673,0" VerticalAlignment="Top" Height="26" RenderTransformOrigin="0.406,-1.147" FontWeight="Bold" Width="120"/>
        <Label Name="lblCloudBlockLevel_txt" Content="N/A lblCloudBlockLevel" HorizontalAlignment="Left" Margin="160,218,0,0" VerticalAlignment="Top" FontStyle="Italic" RenderTransformOrigin="0.5,0.5" Width="182">
            <Label.RenderTransform>
                <TransformGroup>
                    <ScaleTransform/>
                    <SkewTransform/>
                    <RotateTransform Angle="-0.446"/>
                    <TranslateTransform/>
                </TransformGroup>
            </Label.RenderTransform>
        </Label>
        <Label Name="lblblockatFirst" Content="BlockatFirst:" Margin="7,230,673,0" VerticalAlignment="Top" Height="26" RenderTransformOrigin="0.406,-1.147" FontWeight="Bold" Width="120"/>
        <Label Name="lblQuarantine" Content="Quarantine:" Margin="7,0,673,0" VerticalAlignment="Center" Height="26" RenderTransformOrigin="0.406,-1.147" FontWeight="Bold" Width="120"/>
        <Label Name="lblQuarantine_text" Content="N/A Quarantine" HorizontalAlignment="Left" Margin="160,259,0,0" VerticalAlignment="Top" FontStyle="Italic" Width="120"/>
        <Label Name="lblCloudTImeout" Content="CloudTimeout:" Margin="7,243,673,0" VerticalAlignment="Top" Height="26" RenderTransformOrigin="0.406,-1.147" FontWeight="Bold" Width="120"/>
        <Label Name="lblCloudTimeout_text" Content="N/A Timeout" HorizontalAlignment="Left" Margin="160,245,0,0" VerticalAlignment="Top" FontStyle="Italic" RenderTransformOrigin="0.5,0.5" Width="120">
            <Label.RenderTransform>
                <TransformGroup>
                    <ScaleTransform/>
                    <SkewTransform/>
                    <RotateTransform Angle="-0.446"/>
                    <TranslateTransform/>
                </TransformGroup>
            </Label.RenderTransform>
        </Label>
        <Button Name="btnShowASR" Content="Show ASR rules" HorizontalAlignment="Left" Margin="111,315,0,0" VerticalAlignment="Top" Width="175" FontWeight="Bold" Background="#FF707070" BorderBrush="#FF101010"/>
        <Button Name="btnProtectionLogs" Content="Show Microsoft Protection Log" HorizontalAlignment="Left" Margin="521,272,0,0" VerticalAlignment="Top" Width="190" FontWeight="Bold" BorderBrush="#FF0E0D0D" Background="#FF707070" RenderTransformOrigin="0.5,0.5" >
            <Button.RenderTransform>
                <TransformGroup>
                    <ScaleTransform/>
                    <SkewTransform/>
                    <RotateTransform/>
                    <TranslateTransform X="-2"/>
                </TransformGroup>
            </Button.RenderTransform>
        </Button>
        <Label Name="lblEnableFileHashComputation" Content="EnableFileHashComputation:" Margin="7,284,673,0" VerticalAlignment="Top" Height="26" RenderTransformOrigin="0.406,-1.147" FontWeight="Bold" Width="120"/>
        <Label Name="lblEnableFileHashComputation_Text" Content="N/A" HorizontalAlignment="Left" Margin="160,283,0,0" VerticalAlignment="Top" FontStyle="Italic" RenderTransformOrigin="0.5,0.5" Width="120">
            <Label.RenderTransform>
                <TransformGroup>
                    <ScaleTransform/>
                    <SkewTransform/>
                    <RotateTransform Angle="-0.446"/>
                    <TranslateTransform/>
                </TransformGroup>
            </Label.RenderTransform>
        </Label>
        <Button Name="btnUpdateIntel" Content="Update intel updates" HorizontalAlignment="Left" Margin="111,487,0,0" VerticalAlignment="Top" Width="175" FontWeight="Bold" Background="#FF707070" BorderBrush="#FF101010"/>
        <Button Name="btnDownloadClientAnalyzer" Content="Download ClientAnalyzer" HorizontalAlignment="Left" Margin="521,305,0,0" VerticalAlignment="Top" Width="190" FontWeight="Bold" BorderBrush="#FF0E0D0D" Background="#FF707070" RenderTransformOrigin="0.5,0.5" >
            <Button.RenderTransform>
                <TransformGroup>
                    <ScaleTransform/>
                    <SkewTransform/>
                    <RotateTransform/>
                    <TranslateTransform X="-2"/>
                </TransformGroup>
            </Button.RenderTransform>
        </Button>

    </Grid>
</Window>






"@
#Check if script is running as admin:

# Check if the script is run as administrator
$adminCheck = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $adminCheck.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# If not run as admin, show a message box and exit the script
if (-not $isAdmin) {
    Add-Type -AssemblyName 'System.Windows.Forms'
    [System.Windows.Forms.MessageBox]::Show('This script requires administrator privileges.', 'Admin Privileges Required', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    exit
}

#Read XAML
$reader = (New-Object System.Xml.XmlNodeReader $xaml) 
try { $Form = [Windows.Markup.XamlReader]::Load( $reader ) }
catch { Write-Host "Unable to load Windows.Markup.XamlReader"; exit }

# Store Form Objects In PowerShell
$xaml.SelectNodes("//*[@Name]") | ForEach-Object { Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name) }


$WorkingPath = split-path -parent $MyInvocation.MyCommand.Definition
#write-host $CurrentDirectory
#write-host $WorkingPath

# This Function get the ASR rules currently configured on your endpoint
Function GetASRRuleStatus {

    try {    
    
    $ASRs = @()
        $ASRValue = @()
       $asrrules = @()
$asrrules += [PSCustomObject]@{ # 0
    Name = "Block executable content from email client and webmail";
    GUID = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"
    ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-executable-content-from-email-client-and-webmail
}
$asrrules += [PSCustomObject]@{ # 1
    Name = "Block all Office applications from creating child processes";
    GUID = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"
    ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-all-office-applications-from-creating-child-processes
}
$asrrules += [PSCustomObject]@{ # 2
    Name = "Block Office applications from creating executable content";
    GUID = "3B576869-A4EC-4529-8536-B80A7769E899"
    ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-office-applications-from-creating-executable-content
}
$asrrules += [PSCustomObject]@{ # 3
    Name = "Block Office applications from injecting code into other processes";
    GUID = "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"
    ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-office-applications-from-injecting-code-into-other-processes
}
$asrrules += [PSCustomObject]@{ # 4
    Name = "Block JavaScript or VBScript from launching downloaded executable content";
    GUID = "D3E037E1-3EB8-44C8-A917-57927947596D"
    ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-javascript-or-vbscript-from-launching-downloaded-executable-content
}
$asrrules += [PSCustomObject]@{ # 5
    Name = "Block execution of potentially obfuscated scripts";
    GUID = "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"
    ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-execution-of-potentially-obfuscated-scripts
}
$asrrules += [PSCustomObject]@{ # 6
    Name = "Block Win32 API calls from Office macros";
    GUID = "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"
    ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-win32-api-calls-from-office-macros
}
$asrrules += [PSCustomObject]@{ # 7
    Name = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion";
    GUID = "01443614-cd74-433a-b99e-2ecdc07bfc25"
    ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-executable-files-from-running-unless-they-meet-a-prevalence-age-or-trusted-list-criterion
}
$asrrules += [PSCustomObject]@{ # 8 
    Name = "Use advanced protection against ransomware";
    GUID = "c1db55ab-c21a-4637-bb3f-a12568109d35"
    ## reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#use-advanced-protection-against-ransomware
}
$asrrules += [PSCustomObject]@{ # 9
    Name = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)";
    GUID = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
    ## https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-credential-stealing-from-the-windows-local-security-authority-subsystem
}
$asrrules += [PSCustomObject]@{ # 10
    Name = "Block process creations originating from PSExec and WMI commands";
    GUID = "d1e49aac-8f56-4280-b9ba-993a6d77406c"
    ## https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-process-creations-originating-from-psexec-and-wmi-commands
}
$asrrules += [PSCustomObject]@{ # 11
    Name = "Block untrusted and unsigned processes that run from USB";
    GUID = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"
    ## https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-untrusted-and-unsigned-processes-that-run-from-usb
}
$asrrules += [PSCustomObject]@{ # 12
    Name = "Block Office communication application from creating child processes";
    GUID = "26190899-1602-49e8-8b27-eb1d0a1ce869"
    ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-office-communication-application-from-creating-child-processes
}
$asrrules += [PSCustomObject]@{ # 13
    Name = "Block Adobe Reader from creating child processes";
    GUID = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"
    ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-adobe-reader-from-creating-child-processes
}
$asrrules += [PSCustomObject]@{ # 14
    Name = "Block persistence through WMI event subscription";
    GUID = "e6db77e5-3df2-4cf1-b95a-636979351e5b"
    ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-persistence-through-wmi-event-subscription
}
$asrrules += [PSCustomObject]@{ # 15 
    Name = "Block abuse of exploited vulnerable signed drivers";
    GUID = "56a863a9-875e-4185-98a7-b882c64b5ce5"
    ## Reference - https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules?view=o365-worldwide#block-abuse-of-exploited-vulnerable-signed-drivers
}
$asrrules += [PSCustomObject]@{ # 16 
    Name = "Block rebooting machine in Safe Mode (preview)";
    GUID = "33ddedf1-c6e0-47cb-833e-de6133960387"
    ## Reference - https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-rebooting-machine-in-safe-mode-preview
}
$asrrules += [PSCustomObject]@{ # 17 
    Name = "Block use of copied or impersonated system tools (preview)";
    GUID = "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb"
    ## Reference - https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-use-of-copied-or-impersonated-system-tools-preview
}
$asrrules += [PSCustomObject]@{ # 18 
    Name = "Block Webshell creation for Servers";
    GUID = "a8f5898e-1dc8-49a9-9878-85004b8a61e6"
    ## Reference - https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-webshell-creation-for-servers
}

        $enabledvalues = "Not Enabled", "Enabled", "Audit", "NA3", "NA4", "NA5", "Warning" ## $NA3-5 just added for the list to fit from 0-6
        
        ## https://docs.microsoft.com/en-us/powershell/module/defender/?view=win10-ps
        $results = Get-MpPreference
                

       

        if (-not [string]::isnullorempty($results.AttackSurfaceReductionRules_ids)) {
    foreach ($id in $asrrules.GUID) {      
        switch ($id) {
            "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" {$index=0;break}
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" {$index=1;break}
            "3B576869-A4EC-4529-8536-B80A7769E899" {$index=2;break}
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" {$index=3;break}
            "D3E037E1-3EB8-44C8-A917-57927947596D" {$index=4;break}
            "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" {$index=5;break}
            "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" {$index=6;break}
            "01443614-cd74-433a-b99e-2ecdc07bfc25" {$index=7;break}
            "c1db55ab-c21a-4637-bb3f-a12568109d35" {$index=8;break}
            "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" {$index=9;break}
            "d1e49aac-8f56-4280-b9ba-993a6d77406c" {$index=10;break}
            "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" {$index=11;break}
            "26190899-1602-49e8-8b27-eb1d0a1ce869" {$index=12;break}
            "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" {$index=13;break}
            "e6db77e5-3df2-4cf1-b95a-636979351e5b" {$index=14;break}
            "56a863a9-875e-4185-98a7-b882c64b5ce5" {$index=15;break}
            "33ddedf1-c6e0-47cb-833e-de6133960387" {$index=16;break}
            "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" {$index=17;break}
            "a8f5898e-1dc8-49a9-9878-85004b8a61e6" {$index=18;break}
        }
                $count = 0
                $notfound = $true
                foreach ($entry in $results.AttackSurfaceReductionRules_ids) {
                    if ($entry -match $id) {
                        $enabled = $results.AttackSurfaceReductionRules_actions[$count]             
                        switch ($enabled) {
                            0 { $ASRs += $asrrules[$index].name; $ASRValue += $enabledvalues[$enabled]; break }
                            1 { $ASRs += $asrrules[$index].name; $ASRValue += $enabledvalues[$enabled]; break }
                            2 { $ASRs += $asrrules[$index].name; $ASRValue += $enabledvalues[$enabled]; break }
                            6 { $ASRs += $asrrules[$index].name; $ASRValue += $enabledvalues[$enabled]; break }
                        }
                        $notfound = $false
                    }
                    $count++         
                }    
                if ($notfound) {            
                }    
         
            }
            

            [int]$max = $ASRs.Count

            $Results = for ( $i = 0; $i -lt $max; $i++) {
                Write-Verbose "$($ASRs[$i]),$($ASRValue[$i])"
                [PSCustomObject]@{
                    ASR    = $ASRs[$i]
                    Status = $ASRValue[$i] 
                }
            }
            Return $results 
        }
        else {
            $results = "ASR rules empty"
            return $results
        }
    }
    catch { [System.Windows.MessageBox]::Show($Error[0], 'Confirm', 'OK', 'Error') }
}


Function GetSignatureVersion {

    try {

        # Check current version from Microsoft

        $website = Invoke-WebRequest -Uri https://www.microsoft.com/en-us/wdsi/definitions/antimalware-definition-release-notes -UseBasicParsing

        $Pattern = '<span id="(?<dropdown>.*)" tabindex=(?<tabindex>.*) aria-label=(?<arialabel>.*) versionid=(?<versionid>.*)>(?<version>.*)</span>'

        $AllMatches = ($website | Select-String $Pattern -AllMatches).Matches

        $SignatureVersionList = foreach ($group in $AllMatches) {
            [PSCustomObject]@{
                'version' = ($group.Groups.Where{ $_.Name -like 'version' }).Value
            }
        }

        $SignatureCurrentVersion = $SignatureVersionList | Select-Object -First 1
        return $SignatureCurrentVersion.version

    }
    catch { [System.Windows.MessageBox]::Show($Error[0], 'Confirm', 'OK', 'Error') }

}

Function GetPlatformVersionAndEngine {

    try {

        ## Check Platform & Engine Version Start ##
        # Check current version from Microsoft

        $PlatformURL = "https://www.microsoft.com/en-us/wdsi/defenderupdates?ranMID=24542&ranEAID=TnL5HPStwNw&ranSiteID=TnL5HPStwNw-ywv7diDw5Zx1d5vlZitDSQ&epi=TnL5HPStwNw-ywv7diDw5Zx1d5vlZitDSQ&irgwc=1&OCID=AID2000142_aff_7593_1243925&tduid=%28ir__cdyqnmiqgckftliekk0sohzjxn2xpksmaywdhgac00%29%287593%29%281243925%29%28TnL5HPStwNw-ywv7diDw5Zx1d5vlZitDSQ%29%28%29&irclickid=_cdyqnmiqgckftliekk0sohzjxn2xpksmaywdhgac00"

        $Platformwebsite = Invoke-WebRequest -Uri $PlatformURL -UseBasicParsing
        $PlatformPattern = "<li>Platform Version: <span>(?<Platform>.*)</span></li>" 
        $PlatformMatches = ($Platformwebsite | Select-String $PlatformPattern -AllMatches).Matches
        $PlatformVersionList = foreach ($group in $PlatformMatches) {
            [PSCustomObject]@{
                'Platform_Version' = ($group.Groups.Where{ $_.Name -like 'Platform' }).Value
            }
        }

        $CurrentPlatformVersion = ($PlatformVersionList).Platform_Version

        $EnginePattern = "<li>Engine Version: <span>(?<Engine>.*)</span></li>"

        $EngineMatches = ($Platformwebsite | Select-String $EnginePattern -AllMatches).Matches

        $EngineVersionList = foreach ($group in $EngineMatches) {
            [PSCustomObject]@{
                'Engine_Version' = ($group.Groups.Where{ $_.Name -like 'Engine' }).Value
            }
        }

        $CurrentEngineVersion = ($EngineVersionList).Engine_Version
        return $CurrentPlatformVersion, $CurrentEngineVersion
    }
    catch { [System.Windows.MessageBox]::Show($Error[0], 'Confirm', 'OK', 'Error') }

}



$MainWindow1.Add_Loaded({ 

        try {

            WindowLoader

        }
        catch { [System.Windows.MessageBox]::Show($Error[0], 'Confirm', 'OK', 'Error') }

    })

#Assign event


$btnDownloadClientAnalyzer.Add_Click({ 

        try {

           # Prompt the user to select a destination folder
            $folder = (New-Object -ComObject Shell.Application).BrowseForFolder(0, "Select Destination Folder", 0).Self.Path

            # Check if the user selected a folder
            if ($folder) {
                # Define the URL of the .exe file to download
                $url = "https://aka.ms/mdatpanalyzer"

                # Define the destination file path
                $destination = Join-Path -Path $folder -ChildPath "yourfile.exe"

                # Download the file
                Invoke-WebRequest -Uri $url -OutFile $destination

                Write-Host "File downloaded to $destination"
            } else {
                Write-Host "No folder selected. Download canceled."
            }

        }
        catch { [System.Windows.MessageBox]::Show($Error[0], 'Confirm', 'OK', 'Error') }

    })



$btnUpdateIntel.Add_Click({

        try {


        $arg3 = " -SignatureUpdate"
        Start-Process "C:\Program Files\Windows Defender\MpCmdRun.exe" -ArgumentList $arg3 -Wait

        ##& "



        }
        catch { [System.Windows.MessageBox]::Show($Error[0], 'Confirm', 'OK', 'Error') }

    })




$btnShowSenseLogs.Add_Click({

        try {

            $MainWindow1.Cursor = [System.Windows.Input.Cursors]::Wait

            get-winevent -LogName "Microsoft-Windows-SENSE/Operational" | Out-GridView -Title "Sense Logs"

            $MainWindow1.Cursor = [System.Windows.Input.Cursors]::Arrow

        }
        catch { [System.Windows.MessageBox]::Show($Error[0], 'Confirm', 'OK', 'Error') }

    })

$btnShowASR.Add_Click({
        $MainWindow1.Cursor = [System.Windows.Input.Cursors]::Wait

        try {

            $GetASRRuleStatus = GetASRRuleStatus
            $GetASRRuleStatus | Out-GridView -title "ASR Rules status"

            $MainWindow1.Cursor = [System.Windows.Input.Cursors]::Arrow

        }
        catch { [System.Windows.MessageBox]::Show($Error[0], 'Confirm', 'OK', 'Error') }

    })

$btnCheckForLastestUpdate.Add_Click({
        $MainWindow1.Cursor = [System.Windows.Input.Cursors]::Wait

        try {

            $ReturnGetPlatformVersionAndEngine = GetPlatformVersionAndEngine
            $lblLastestEngineVersion_txt.content = $ReturnGetPlatformVersionAndEngine[0]
            $lblLastestPlatformVersion_txt.content = $ReturnGetPlatformVersionAndEngine[1]
            $lblLatestSigVersion_txt.content = GetSignatureVersion
            $lblLastestEngineVersion_txt.Foreground = "#FF000000"
            $lblLastestPlatformVersion_txt.Foreground = "#FF000000"

        $MainWindow1.Cursor = [System.Windows.Input.Cursors]::Arrow

        }
        catch { [System.Windows.MessageBox]::Show($Error[0], 'Confirm', 'OK', 'Error') }


    })

$btnShowDefenderAVLogs.Add_Click({
        $MainWindow1.Cursor = [System.Windows.Input.Cursors]::Wait
        $MainWindow1.Cursor = [System.Windows.Input.Cursors]::Arrow

        try {

            Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | Out-GridView -Title "Defender AV logs"

        

        }
        catch { [System.Windows.MessageBox]::Show($Error[0], 'Confirm', 'OK', 'Error') }

    })


$btnShowPerformanceReport.Add_Click({
        $MainWindow1.Cursor = [System.Windows.Input.Cursors]::Wait

        PerformanceReport

        $MainWindow1.Cursor = [System.Windows.Input.Cursors]::Arrow

    })

$btnExclusions.Add_Click({
        $MainWindow1.Cursor = [System.Windows.Input.Cursors]::Wait

        try {

            $MPpreference = Get-MpPreference
            $Exclusions += $MPpreference.ExclusionPath
            $Exclusions += $MPpreference.ExclusionExtension
            $Exclusions += $MPpreference.ExclusionIpAddress
            $Exclusions += $MPpreference.ExclusionProcess
            $Exclusions | Out-GridView -Title "Exclusions"

        $MainWindow1.Cursor = [System.Windows.Input.Cursors]::Arrow

        }
        catch { [System.Windows.MessageBox]::Show($Error[0], 'Confirm', 'OK', 'Error') }


    })

$btnRunPerformance.Add_Click({
        PerformanceAnalyze
    })

Function PerformanceReport {

    try {

        $date = (get-date -f yyyy-MM-dd)
        $PerformanceReport = Get-MpPerformanceReport -Path $WorkingPath\MDAV_Recording.etl -TopFiles:10 -TopExtensions:10 -TopProcesses:10 -TopScans:10


        If ($rdbTopfiles.IsChecked -eq $true) {

            $TempFileReportTopFiles = $WorkingPath + "\TempFileReportTopFiles-" + $date + ".csv"
            #$PerformanceReport.TopFiles | Out-GridView
            $PerformanceReport.TopFiles | export-csv $TempFileReportTopFiles
            import-csv $TempFileReportTopFiles | out-gridview
        }
        If ($rdbTopExtensions.IsChecked -eq $true ) {
            $TempFileReportTopExtensions = $WorkingPath + "\TempFileReportTopExtensions-" + $date + ".csv"
            $PerformanceReport.TopExtensions | export-csv $TempFileReportTopExtensions
            import-csv $TempFileReportTopExtensions | out-gridview
        }
        if ($rdbTopProcess.IsChecked -eq $true) {
            $TempReportFileTopProcesses = $WorkingPath + "\TempReportFileTopProcesses-" + $date + ".csv"
            $PerformanceReport.TopProcesses | export-csv $TempReportFileTopProcesses
            import-csv $TempReportFileTopProcesses | out-gridview
        }
        if ($rdbTopScans.IsChecked -eq $true) {
            $TempReportFileTopScans = $WorkingPath + "\TempReportFileTopScans-" + $date + ".csv"
            $PerformanceReport.TopScans | export-csv $TempReportFileTopScans
            import-csv $TempReportFileTopScans | out-gridview -Title "Top File Scans"
        }

    }
    catch { [System.Windows.MessageBox]::Show($Error[0], 'Confirm', 'OK', 'Error') }
}


Function PerformanceAnalyze {

    try { 

        $arg = "New-MpPerformanceRecording -RecordTo " + '"' + $WorkingPath + "\MDAV_Recording.etl" + '"'

        Start-Process powershell.exe -ArgumentList "-Command", $arg
        $btnShowPerformanceReport.IsEnabled = $true
        $rdbTopfiles.IsEnabled = $true
        $rdbTopExtensions.IsEnabled = $true
        $rdbTopProcess.IsEnabled = $true
        $rdbTopScans.IsEnabled = $true

    }
    catch { [System.Windows.MessageBox]::Show($Error[0], 'Confirm', 'OK', 'Error') }
}

Function ReadHashComputation{

  # Read EnableFileHashComputation
        

        if(test-path "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine"){
        $KeyReadHashComputation = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine" -Name "EnableFileHashComputation" -ErrorAction SilentlyContinue

        if ($KeyReadHashComputation) {
        Return "Enabled by GPO"
                 }else {
    
           if(test-path "HKLM:\Software\Microsoft\Windows Defender\MpEngine"){
        $KeyReadHashComputation = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows Defender\MpEngine" -Name "EnableFileHashComputation" -ErrorAction SilentlyContinue

        if ($KeyReadHashComputation) {
        Return "Enabled by GPO"
                 }else {
         return "Disabled"
                }
        }Else  {
         Return "Disabled"

        }



                }
        }

    


     

}

Function WindowLoader {

    try {

        $MPpreference = Get-MpPreference
        $MPComputerstatus = Get-MpComputerStatus


        $lblAMEngineVersion_txt.Content = $MPComputerstatus.AMEngineVersion
        $lblAMProductVersion_txt.content = $MPComputerstatus.AMProductVersion
        $lblAMRunningMode_txt.content = $MPComputerstatus.AMRunningMode
        $lblAMServiceVersion_txt.content = $MPComputerstatus.AMServiceVersion
        $lblTamper_txt.content = $MPComputerstatus.IsTamperProtected
        $lblTamperSource_txt.content = $MPComputerstatus.TamperProtectionSource
        $lblSigUpdates_txt.content = $MPComputerstatus.NISSignatureLastUpdated
        $lblSignatureFallBackOrder_txt.content = $MPpreference.SignatureFallbackOrder
        $lblSignatureVersion_txt.content = $MPComputerstatus.NISSignatureVersion
        $lblComputerName.content = [System.Net.Dns]::GetHostName()
        $lblQuarantine_text.content = $MPpreference.QuarantinePurgeItemsAfterDelay
        $lblPUAProtect_text.content = $MPpreference.DisableBlockAtFirstSeen
        $lblCloudTimeout_text.content = $MPpreference.CloudExtendedTimeout
        $lblEnableFileHashComputation_Text.content = ReadHashComputation
      

       

        switch ($MPpreference.CloudBlockLevel) {
            0 { $lblCloudBlockLevel_txt.content = "Default" }
            1 { $lblCloudBlockLevel_txt.content = "Moderate" }
            2 { $lblCloudBlockLevel_txt.content = "High" }
            3 { $lblCloudBlockLevel_txt.content = "High+" }
            4 { $lblCloudBlockLevel_txt.content = "Zero tolerance" }
        }

    }
    catch { [System.Windows.MessageBox]::Show($Error[0], 'Confirm', 'OK', 'Error') }
    


    if (test-path "HKLM:\\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status") {

        $RegisteryOrgID = (get-itemproperty -path "HKLM:\\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -name "OrgId").OrgId

        $lblOrgID_txt.Content = $RegisteryOrgID
    }
}

#Show Form
$Form.ShowDialog() | out-null

