# Microsoft Entra ID (Azure AD) Unauthenticated Enumeration

**Source:** EvilMist Toolkit - `Invoke-EntraEnum.ps1` - https://github.com/Logisek/EvilMist

---

## 1. Tenant Discovery (-TenantInfo)

Discovers tenant information using public APIs.

### 1.1 azmap.dev API

Retrieves tenant details from the azmap.dev service.

```bash
# Replace DOMAIN with target domain (e.g., contoso.com)
curl -s "https://azmap.dev/api/tenant?domain=DOMAIN&extract=true"
```

**Response contains:** `tenantId`, `displayName`, `countryCode`

### 1.2 OpenID Configuration

Retrieves OpenID Connect configuration including token endpoints.


```bash
# Replace DOMAIN with target domain
curl -s "https://login.microsoftonline.com/DOMAIN/v2.0/.well-known/openid-configuration"
```

**Response contains:** `token_endpoint`, `authorization_endpoint`, `jwks_uri`, `issuer`

---

## 2. Domain Realm Information (-DomainRealm)

Retrieves domain namespace and federation configuration.

```bash
# Replace DOMAIN with target domain
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=enum@DOMAIN&json=1"
```

**Response contains:**
- `NameSpaceType` - "Managed" or "Federated"
- `AuthURL` - Federation authentication URL (if federated)
- `CloudInstanceName` - Cloud instance (e.g., "microsoftonline.com")
- `FederationBrandName` - Organization branding name
- `DomainName` - Verified domain

---

## 3. User Enumeration via GetCredentialType (-UserEnum)

Checks if a user exists in Azure AD. Returns different codes based on user existence.

```bash
# Replace EMAIL with target email address
curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
  -H "Content-Type: application/json" \
  -d '{
    "Username": "EMAIL",
    "isOtherIdpSupported": true,
    "checkPhones": false,
    "isRemoteNGCSupported": true,
    "isCookieBannerShown": false,
    "isFidoSupported": true,
    "originalRequest": "",
    "country": "US",
    "forceotclogin": false,
    "isExternalFederationDisallowed": false,
    "isRemoteConnectSupported": false,
    "federationFlags": 0,
    "isSignup": false,
    "flowToken": "",
    "isAccessPassSupported": true
  }'
```

**IfExistsResult codes:**
- `0` = User exists (Azure IdP)
- `1` = User does not exist
- `2` = Invalid request
- `4` = Server error
- `5` = User exists (Federated IdP)
- `6` = User exists (External non-MS IdP)

---

## 4. DNS Reconnaissance (-DnsEnum)

DNS queries for Azure/M365 related records. Use dig, nslookup, or host commands.

### 4.1 CNAME Records

```bash
# Main domain CNAME
dig CNAME DOMAIN

# Autodiscover CNAME
dig CNAME autodiscover.DOMAIN
dig CNAME lyncdiscover.DOMAIN
dig CNAME sip.DOMAIN
```

### 4.2 TXT/SPF Records

```bash
dig TXT DOMAIN
```

### 4.3 SRV Records

```bash
dig SRV _ldap._tcp.DOMAIN
dig SRV _kerberos._tcp.DOMAIN
dig SRV _autodiscover._tcp.DOMAIN
dig SRV _sip._tls.DOMAIN
dig SRV _sipfederationtls._tcp.DOMAIN
```

### 4.4 MX Records

```bash
dig MX DOMAIN
```

---

## 5. OneDrive User Enumeration (-OneDriveEnum)

**Completely undetectable** - No audit logs generated.

Checks if a user exists by probing their OneDrive personal site URL.

```bash
# Replace TENANT with tenant name (e.g., contoso)
# Replace USERPATH with email formatted as: user_domain_com (@ and . replaced with _)
# Example: john.doe@contoso.com becomes john_doe_contoso_com

curl -s -o /dev/null -w "%{http_code}" -I \
  "https://TENANT-my.sharepoint.com/personal/USERPATH/_layouts/15/onedrive.aspx"
```

**Status codes:**
- `200` = User exists, OneDrive accessible
- `401/403` = User exists, access denied
- `404` = User does not exist

### Example for user john.doe@contoso.com:

```bash
curl -s -o /dev/null -w "%{http_code}" -I \
  "https://contoso-my.sharepoint.com/personal/john_doe_contoso_com/_layouts/15/onedrive.aspx"
```

---

## 6. Federation Metadata (-FederationMeta)

Retrieves federation metadata including signing certificates and token endpoints.

```bash
# Replace DOMAIN with target domain
curl -s "https://login.microsoftonline.com/DOMAIN/FederationMetadata/2007-06/FederationMetadata.xml"
```

**Response contains (XML):**
- Entity ID
- X509 Signing Certificates
- Token Endpoints
- NameID Formats
- Claim Types
- ADFS server information (if federated)

---

## 7. Seamless SSO Detection (-SeamlessSSO)

Detects if Desktop SSO (Seamless Single Sign-On) is enabled.

### 7.1 Check SSO Configuration

```bash
# Replace DOMAIN with target domain
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@DOMAIN&json=1"
```

**Look for:** `DesktopSsoEnabled: true`

### 7.2 Test Autologon Endpoint (if SSO enabled)

```bash
# Replace TENANT_ID with the tenant GUID
curl -s -o /dev/null -w "%{http_code}" \
  "https://autologon.microsoftazuread-sso.com/TENANT_ID/winauth/trust/2005/usernamemixed"
```

---

## 8. Azure Subdomain Enumeration (-SubdomainEnum)

Discovers Azure resources associated with a tenant. Uses DNS resolution.

### Core Azure Subdomains to Check:

```bash
# Replace TENANT with tenant name

# Primary tenant domain
dig A TENANT.onmicrosoft.com

# SharePoint
dig A TENANT.sharepoint.com

# OneDrive
dig A TENANT-my.sharepoint.com

# Azure Blob Storage
dig A TENANT.blob.core.windows.net

# Azure Files
dig A TENANT.file.core.windows.net

# Azure Queue
dig A TENANT.queue.core.windows.net

# Azure Table
dig A TENANT.table.core.windows.net

# Key Vault
dig A TENANT.vault.azure.net

# Azure SQL
dig A TENANT.database.windows.net

# App Service
dig A TENANT.azurewebsites.net

# Kudu/Git Deployment
dig A TENANT.scm.azurewebsites.net

# Cloud Services
dig A TENANT.cloudapp.net
dig A TENANT.cloudapp.azure.com

# Exchange Online Protection
dig A TENANT.mail.protection.outlook.com

# Container Registry
dig A TENANT.azurecr.io

# Redis Cache
dig A TENANT.redis.cache.windows.net

# Service Bus
dig A TENANT.servicebus.windows.net

# Front Door
dig A TENANT.azurefd.net

# Azure AD B2C
dig A TENANT.b2clogin.com

# API Management
dig A TENANT.azure-api.net

# Traffic Manager
dig A TENANT.trafficmanager.net

# HDInsight
dig A TENANT.azurehdinsight.net

# Cosmos DB
dig A TENANT.documents.azure.com

# Cognitive Search
dig A TENANT.search.windows.net

# Cognitive Services
dig A TENANT.cognitiveservices.azure.com
```

### Permutation Examples:

```bash
# Common suffixes: dev, prod, staging, test, uat, qa, backup, dr, api, app, web, data
dig A TENANTdev.blob.core.windows.net
dig A TENANTprod.azurewebsites.net
dig A TENANTstaging.vault.azure.net
```

---

## 9. Autodiscover V2 Enumeration (-AutodiscoverEnum)

Checks user existence via Autodiscover V2 JSON endpoint.

```bash
# Replace EMAIL with target email address
curl -s -o /dev/null -w "%{http_code}" -L --max-redirs 0 \
  "https://autodiscover-s.outlook.com/autodiscover/autodiscover.json?Email=EMAIL&Protocol=Autodiscoverv1"
```

**Status codes:**
- `200` = User exists
- `302` (redirect) = User does not exist
- `401/403` = User exists (auth required)

---

## 10. Autodiscover V1 Enumeration (-AutodiscoverV1Enum)

Legacy XML-based Autodiscover endpoint for user enumeration.

```bash
# Replace DOMAIN with target domain
# Replace EMAIL with target email address

curl -s -X POST "https://autodiscover.DOMAIN/autodiscover/autodiscover.xml" \
  -H "Content-Type: text/xml; charset=utf-8" \
  -d '<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
  <Request>
    <EMailAddress>EMAIL</EMailAddress>
    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
  </Request>
</Autodiscover>'
```

**Response indicators:**
- `RedirectAddr` in response = User exists
- `RedirectUrl` in response = May indicate existence
- `ErrorCode: InvalidUser` = User does not exist
- `ErrorCode: NoError` = User exists

---

## 11. Exchange Web Services (EWS) Probe (-EwsProbe)

Probes EWS endpoints for exposure.

```bash
# Office 365 EWS endpoints
curl -s -o /dev/null -w "%{http_code}" \
  "https://outlook.office365.com/EWS/Exchange.asmx"

curl -s -o /dev/null -w "%{http_code}" \
  "https://outlook.office.com/EWS/Exchange.asmx"

# On-premises/custom domain endpoints
# Replace DOMAIN with target domain
curl -s -o /dev/null -w "%{http_code}" \
  "https://DOMAIN/EWS/Exchange.asmx"

curl -s -o /dev/null -w "%{http_code}" \
  "https://mail.DOMAIN/EWS/Exchange.asmx"

curl -s -o /dev/null -w "%{http_code}" \
  "https://ews.DOMAIN/EWS/Exchange.asmx"
```

**Status codes indicating availability:**
- `200`, `301`, `302`, `307`, `308` = Available
- `401`, `403` = Available (authentication required)
- `404` = Not available

---

## 12. SharePoint/Teams Discovery (-SharePointEnum)

Discovers SharePoint and Teams sites.

```bash
# Replace TENANT with tenant name

# Tenant root
curl -s -o /dev/null -w "%{http_code}" \
  "https://TENANT.sharepoint.com"

# OneDrive root
curl -s -o /dev/null -w "%{http_code}" \
  "https://TENANT-my.sharepoint.com"

# Common site names to check
# Sites: intranet, portal, hr, finance, it, projects, marketing, sales, support, admin, security, dev

curl -s -o /dev/null -w "%{http_code}" \
  "https://TENANT.sharepoint.com/sites/intranet"

curl -s -o /dev/null -w "%{http_code}" \
  "https://TENANT.sharepoint.com/sites/portal"

curl -s -o /dev/null -w "%{http_code}" \
  "https://TENANT.sharepoint.com/sites/hr"

# Teams sites
curl -s -o /dev/null -w "%{http_code}" \
  "https://TENANT.sharepoint.com/teams/intranet"

curl -s -o /dev/null -w "%{http_code}" \
  "https://TENANT.sharepoint.com/teams/it"
```

**Status codes:**
- `200` = Site exists and is publicly accessible
- `401`, `403` = Site exists, authentication required
- `301`, `302`, `307`, `308` = Site exists, redirecting
- `404` = Site does not exist

---

## 13. Lync Discovery (-LyncProbe)

Probes Lync for Business discovery endpoints.

```bash
# Replace DOMAIN with target domain

curl -s -o /dev/null -w "%{http_code}" \
  "https://lyncdiscover.DOMAIN"

curl -s -o /dev/null -w "%{http_code}" \
  "https://lyncdiscoverinternal.DOMAIN"

curl -s -o /dev/null -w "%{http_code}" \
  "https://sip.DOMAIN"
```

---

## 14. Enhanced Mail Security Enumeration (-MailEnum)

### 14.1 DNS Records (use dig/nslookup)

```bash
# MX Records
dig MX DOMAIN

# SPF (TXT record)
dig TXT DOMAIN

# DMARC
dig TXT _dmarc.DOMAIN

# DKIM (common selectors)
dig TXT selector1._domainkey.DOMAIN  # Microsoft 365
dig TXT selector2._domainkey.DOMAIN  # Microsoft 365
dig TXT google._domainkey.DOMAIN     # Google Workspace
dig TXT default._domainkey.DOMAIN
dig TXT dkim._domainkey.DOMAIN
dig TXT mail._domainkey.DOMAIN
dig TXT k1._domainkey.DOMAIN         # Mailchimp
dig TXT s1._domainkey.DOMAIN
dig TXT s2._domainkey.DOMAIN

# MTA-STS
dig TXT _mta-sts.DOMAIN

# BIMI
dig TXT default._bimi.DOMAIN

# TLS-RPT
dig TXT _smtp._tls.DOMAIN
```

### 14.2 MTA-STS Policy (HTTP)

```bash
# Replace DOMAIN with target domain
curl -s "https://mta-sts.DOMAIN/.well-known/mta-sts.txt"
```

---

## 15. Tenant ID Resource Discovery (-TenantReverse)

Given a Tenant ID, discovers associated resources.

```bash
# Replace TENANT_ID with the tenant GUID

# OpenID Configuration (v2.0)
curl -s "https://login.microsoftonline.com/TENANT_ID/v2.0/.well-known/openid-configuration"

# OpenID Configuration (v1.0)
curl -s "https://login.microsoftonline.com/TENANT_ID/.well-known/openid-configuration"

# Graph Tenant Information (requires auth but reveals info in error)
curl -s "https://graph.microsoft.com/v1.0/tenantRelationships/findTenantInformationByTenantId(tenantId='TENANT_ID')"

# Device Code Endpoint
curl -s "https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/devicecode"

# OAuth Authorize (reveals tenant branding)
curl -s "https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/authorize?client_id=00000000-0000-0000-0000-000000000000&response_type=code&scope=openid"
```

---

## 16. OAuth Configuration Probe (-OAuthProbe)

Enumerates OAuth configuration through error message analysis of well-known application IDs.

```bash
# Replace TENANT with tenant ID or domain

# Well-known Microsoft Application IDs to test:

# Microsoft Graph
curl -s "https://login.microsoftonline.com/TENANT/oauth2/v2.0/authorize?client_id=00000003-0000-0000-c000-000000000000&response_type=code&scope=openid"

# Azure AD Graph (Deprecated)
curl -s "https://login.microsoftonline.com/TENANT/oauth2/v2.0/authorize?client_id=00000002-0000-0000-c000-000000000000&response_type=code&scope=openid"

# Office 365 Exchange Online
curl -s "https://login.microsoftonline.com/TENANT/oauth2/v2.0/authorize?client_id=00000002-0000-0ff1-ce00-000000000000&response_type=code&scope=openid"

# Office 365 SharePoint Online
curl -s "https://login.microsoftonline.com/TENANT/oauth2/v2.0/authorize?client_id=00000003-0000-0ff1-ce00-000000000000&response_type=code&scope=openid"

# Skype for Business Online
curl -s "https://login.microsoftonline.com/TENANT/oauth2/v2.0/authorize?client_id=00000004-0000-0ff1-ce00-000000000000&response_type=code&scope=openid"

# Azure Service Management API
curl -s "https://login.microsoftonline.com/TENANT/oauth2/v2.0/authorize?client_id=797f4846-ba00-4fd7-ba43-dac1f8f63013&response_type=code&scope=openid"

# Microsoft Azure PowerShell
curl -s "https://login.microsoftonline.com/TENANT/oauth2/v2.0/authorize?client_id=1950a258-227b-4e31-a9cf-717495945fc2&response_type=code&scope=openid"

# Microsoft Azure CLI
curl -s "https://login.microsoftonline.com/TENANT/oauth2/v2.0/authorize?client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&response_type=code&scope=openid"

# Microsoft Office
curl -s "https://login.microsoftonline.com/TENANT/oauth2/v2.0/authorize?client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&response_type=code&scope=openid"

# Microsoft Teams
curl -s "https://login.microsoftonline.com/TENANT/oauth2/v2.0/authorize?client_id=1fec8e78-bce4-4aaf-ab1b-5451cc387264&response_type=code&scope=openid"

# Microsoft Planner
curl -s "https://login.microsoftonline.com/TENANT/oauth2/v2.0/authorize?client_id=9bc3ab49-b65d-410a-85ad-de819febfddc&response_type=code&scope=openid"

# Microsoft Graph Command Line Tools
curl -s "https://login.microsoftonline.com/TENANT/oauth2/v2.0/authorize?client_id=de8bc8b5-d9f9-48b1-a8ad-b748da725064&response_type=code&scope=openid"

# Azure Portal
curl -s "https://login.microsoftonline.com/TENANT/oauth2/v2.0/authorize?client_id=c44b4083-3bb0-49c1-b47d-974e53cbdf3c&response_type=code&scope=openid"

# Microsoft App Access Panel
curl -s "https://login.microsoftonline.com/TENANT/oauth2/v2.0/authorize?client_id=0000000c-0000-0000-c000-000000000000&response_type=code&scope=openid"

# Microsoft Outlook
curl -s "https://login.microsoftonline.com/TENANT/oauth2/v2.0/authorize?client_id=5d661950-3475-41cd-a2c3-d671a3162bc1&response_type=code&scope=openid"

# Microsoft OneDrive
curl -s "https://login.microsoftonline.com/TENANT/oauth2/v2.0/authorize?client_id=eb1cec80-a830-486e-b45b-f57094f163f9&response_type=code&scope=openid"

# SharePoint Online Client
curl -s "https://login.microsoftonline.com/TENANT/oauth2/v2.0/authorize?client_id=57fb890c-0dab-4253-a5e0-7188c88b2bb4&response_type=code&scope=openid"
```

**AADSTS Error Codes to analyze:**
- `AADSTS700016` = Application not found in directory
- `AADSTS650057` = Invalid resource (app exists but config issue)
- `AADSTS65001` = User/admin consent required (app exists)
- `AADSTS50011` = Reply URL mismatch (app exists)
- `AADSTS90002` = Tenant not found

---

## Quick Reference: All Endpoints Summary

| Method | Endpoint | HTTP Method |
|--------|----------|-------------|
| Tenant Info | `https://azmap.dev/api/tenant?domain={domain}&extract=true` | GET |
| OpenID Config | `https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration` | GET |
| Domain Realm | `https://login.microsoftonline.com/getuserrealm.srf?login=user@{domain}&json=1` | GET |
| User Enum | `https://login.microsoftonline.com/common/GetCredentialType` | POST |
| OneDrive Enum | `https://{tenant}-my.sharepoint.com/personal/{user_path}/_layouts/15/onedrive.aspx` | HEAD |
| Federation Meta | `https://login.microsoftonline.com/{domain}/FederationMetadata/2007-06/FederationMetadata.xml` | GET |
| Autologon | `https://autologon.microsoftazuread-sso.com/{tenant_id}/winauth/trust/2005/usernamemixed` | GET |
| Autodiscover V2 | `https://autodiscover-s.outlook.com/autodiscover/autodiscover.json?Email={email}&Protocol=Autodiscoverv1` | GET |
| Autodiscover V1 | `https://autodiscover.{domain}/autodiscover/autodiscover.xml` | POST |
| EWS | `https://outlook.office365.com/EWS/Exchange.asmx` | GET |
| SharePoint | `https://{tenant}.sharepoint.com/sites/{site}` | GET |
| Lync | `https://lyncdiscover.{domain}` | GET |
| MTA-STS Policy | `https://mta-sts.{domain}/.well-known/mta-sts.txt` | GET |
| OAuth Probe | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?client_id={app_id}&response_type=code&scope=openid` | GET |

---

## Notes

- **No authentication required** for any of these requests
- OneDrive enumeration is **completely undetectable** (no audit logs)
- Use appropriate throttling/delays to avoid rate limiting
- Some methods may trigger alerts in security monitoring systems
- Always ensure proper authorization before performing enumeration

---
