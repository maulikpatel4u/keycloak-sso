### **Windows Server Active Directory (AD) Integration with Keycloak SSO**
---

### **Set Up Keycloak**

**1. Access Keycloak Admin Console**
- Log in to your Keycloak Admin Console and select your realm.

**2. Navigate to User Federation**
- Go to User Federation in the left-hand menu in the admin console.

**3. Add LDAP Provider**
- Click Add provider and select LDAP.

**4. Configure LDAP Settings**
- **Vendor:** Active Directory
- **Connection URL:** ldap://<AD-IP>:389 or ldaps://<AD-IP>:636 (for secure connection)
- **Bind DN:** The service account in AD to connect to LDAP
  
    ```python
    e.g., CN=Administrator,CN=Users,DC=example,DC=com
    ```
    - Use PowerShell to find the Bind DN value
      
      ```python
      Get-ADUser -Filter * | Select-Object Name, DistinguishedName
      ```
- **Bind Credential:** Password for the service account.
- **Edit mode:** READ_ONLY
- **Users DN:** This specifies the base DN where the user accounts are stored in Active Directory.

    ```Python
    e.g., CN=Users,DC=example,DC=com
    ```
- **Periodic changed users sync:** Enable it.
