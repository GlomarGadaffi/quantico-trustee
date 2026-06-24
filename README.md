# rdp-publisher-cert

RDP file publisher for Windows. Microsoft decided your .rdp files needed a publisher — this tool provisions one. self-elevates to admin, generates or retrieves a self-signed certificate, signs all .rdp files on Desktop, configures Group Policy to trust the certificate, and sets up per-user consent bypass.

## workflow

```powershell
# Run as user (self-elevates to admin)
.\RDPtrustme.ps1
```

**what it does**:

1. check if 10-year code-signing cert exists; create if not
2. export cert, import to `Cert:\LocalMachine\Root` and `Cert:\LocalMachine\TrustedPublisher`
3. configure Group Policy (`HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services`)
   - enable `AllowSignedFiles`
   - whitelist cert thumbprint in `TrustedCertThumbprints`
4. set user consent bypass (`HKCU:\Software\Microsoft\Terminal Server Client\RdpLaunchConsentAccepted`)
5. iterate Desktop, sign each unsigned .rdp with `rdpsign.exe /sha256`

## result

RDP files signed by the cert are now launchable without the user consent dialog. no intervention needed for repeated connections — Windows recognizes the publisher.

## use cases

- **managed homelabs**: sign your own RDP files once, no more consent dialogs
- **automation**: automated RDP connections in scripts/scheduled tasks
- **consistency**: all machines in a domain use the same publisher cert

## security note

this signs RDP files locally; the trust chain is self-signed (not rooted to a public CA). suitable for private networks.
