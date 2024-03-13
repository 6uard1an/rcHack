function voiceLogger {
    param (
        [System.Speech.Recognition.SpeechRecognitionEngine]$speech
    )

    while ($true) {
        $result = $speech.Recognize()
        if ($result) {
            $results = $result.Text
            Write-Output $results
            $logPath = "$env:TEMP\voicelog.txt"
            $results | Out-File -Append -FilePath $logPath
        }
    }
}


$filePath = "$env:TEMP\voicelog.txt"
New-Item -ItemType File -Path $filePath -Force

$content = @"
===============================
VOICE                       LOG
===============================
All voice will be logged below:
"@
Set-Content -Path $filePath -Value $content -Force
Add-Type -AssemblyName System.Speech
$speech = New-Object System.Speech.Recognition.SpeechRecognitionEngine
$grammar = New-Object System.Speech.Recognition.DictationGrammar
$speech.LoadGrammar($grammar)
$speech.SetInputToDefaultAudioDevice()
Start-Job -ScriptBlock { param($speech) voiceLogger -speech $speech } -ArgumentList $speech
