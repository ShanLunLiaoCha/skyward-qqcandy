param([Parameter(Mandatory=$true)][string]$BuildDirectory)
$ErrorActionPreference='Stop'
$project=$PSScriptRoot
$base=Split-Path $project -Parent
$build=[IO.Path]::GetFullPath($BuildDirectory)
function WslPath([string]$p) {
    if($p -notmatch '^([A-Za-z]):[\\/](.*)$'){throw "Expected local drive: $p"}
    return '/mnt/'+$Matches[1].ToLowerInvariant()+'/'+$Matches[2].Replace('\','/')
}
function Run([string]$exe,[string[]]$arguments) {
    & $exe @arguments
    if($LASTEXITCODE -ne 0){throw "$exe returned $LASTEXITCODE"}
}
if(Test-Path -LiteralPath $build){throw 'Use a fresh build directory'}
New-Item -ItemType Directory -Path $build | Out-Null
Run 'wsl.exe' @('--exec','sh',(WslPath (Join-Path $project 'build_native.sh')),(WslPath $build))
$sdk=Join-Path $env:LOCALAPPDATA 'Android\Sdk'
$bt=Join-Path $sdk 'build-tools\36.1.0'
$android=Join-Path $sdk 'platforms\android-36.1\android.jar'
$app=Join-Path $project 'app\src\main'
$classes=Join-Path $build 'classes'; $dex=Join-Path $build 'dex'; $gen=Join-Path $build 'gen'
New-Item -ItemType Directory -Path $classes,$dex,$gen | Out-Null
$res=Join-Path $build 'res.zip'; $unsigned=Join-Path $build 'unsigned.apk'; $aligned=Join-Path $build 'aligned.apk'
Run (Join-Path $bt 'aapt2.exe') @('compile','--dir',(Join-Path $app 'res'),'-o',$res)
Run (Join-Path $bt 'aapt2.exe') @('link','-o',$unsigned,'-I',$android,'--manifest',(Join-Path $app 'AndroidManifest.xml'),'--java',$gen,'--min-sdk-version','30','--target-sdk-version','35','--version-code','8','--version-name','1.9-Fix78','-A',(Join-Path $build 'assets'),$res)
$sources=@(Get-ChildItem -LiteralPath (Join-Path $app 'java'),(Join-Path $project 'backend\src'),$gen -Recurse -Filter '*.java' -File | ForEach-Object {$_.FullName})
Run 'javac.exe' (@('-encoding','UTF-8','--release','17','-classpath',$android,'-d',$classes)+$sources)
$jar=Join-Path $build 'compiled.jar'
Run 'jar.exe' @('cf',$jar,'-C',$classes,'.')
# Calling D8 directly avoids cmd.exe path/encoding conversion.
Run 'java.exe' @('-cp',(Join-Path $bt 'lib\d8.jar'),'com.android.tools.r8.D8','--lib',$android,'--min-api','30','--output',$dex,$jar)
Run 'wsl.exe' @('--exec','python3','-B',(WslPath (Join-Path $project 'assemble_apk.py')),(WslPath $build))
Run (Join-Path $bt 'zipalign.exe') @('-P','16','-f','4',$unsigned,$aligned)
$keydir=Join-Path $env:LOCALAPPDATA 'SkywardPorter'; New-Item -ItemType Directory -Force -Path $keydir | Out-Null
$key=Join-Path $keydir 'porter-test.jks'
if(!(Test-Path -LiteralPath $key)) { Run 'keytool.exe' @('-genkeypair','-keystore',$key,'-storepass','android','-keypass','android','-alias','skyward-porter','-keyalg','RSA','-keysize','2048','-validity','3650','-dname','CN=Skyward Porter Local Test') }
$apk=Join-Path $build 'Skyward-Porter-arm64.apk'
$signer=Join-Path $bt 'lib\apksigner.jar'
Run 'java.exe' @('-jar',$signer,'sign','--ks',$key,'--ks-key-alias','skyward-porter','--ks-pass','pass:android','--key-pass','pass:android','--out',$apk,$aligned)
Run 'java.exe' @('-jar',$signer,'verify','--verbose','--print-certs',$apk)
Run (Join-Path $bt 'zipalign.exe') @('-c','-P','16','4',$apk)
Get-FileHash -LiteralPath $apk -Algorithm SHA256
