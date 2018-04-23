package main

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/ldap.v2"
)

// Parameters
var ldapServer = "127.0.0.1"
var ldapServerPort = 389
var ldapSearchBase = "dc=example,dc=local"
var ldapSearchBase2 = ",DC=example,DC=local"

// Credentials / RO User
var ldapBindusername = "ROUser"
var ldapBindpassword = "asd.1234"

// Establish a connection to a AD/OpenLDAP server.
func adDial() (*ldap.Conn, error) {
	return ldap.Dial("tcp", fmt.Sprintf("%s:%d", ldapServer, ldapServerPort))
}

// Connects to the AD/OpenLDAP server using the credentials defined above.
func adConnect() (*ldap.Conn, error) {

	// Establish de connection
	l, err := adDial()
	if err != nil {
		return nil, err
	}

	// Authenticate with a read only user's credentials
	err = l.Bind(ldapBindusername, ldapBindpassword)
	if err != nil {
		return nil, err
	}

	return l, nil
}

// Create a AD/LDAP search request.
func adSearchReq(extraBase string, filter string) *ldap.SearchRequest {
	return adSearchReqAttr(extraBase, filter, []string{"dn"})
}

// Create a AD/LDAP search request with an extra base
// which could be another DC or OU.
func adSearchReqAttr(extraBase string, filter string, attributes []string) *ldap.SearchRequest {

	// Prepend the extra base
	var base bytes.Buffer
	if extraBase != "" {
		base.WriteString(extraBase)
		base.WriteString(",")
	}
	base.WriteString(ldapSearchBase)

	// Build the search request
	return ldap.NewSearchRequest(
		base.String(), ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attributes, nil,
	)
}

// Builds a tree containing all OU under the defined base
// in the server
//
// 1 - Searchs for all OU getting al entries of the form
// OU=level3,OU=level2,OU=level1,DC=example,DC=local
//
// 2 - Flip those entries to the form
// DC=local,DC=example,OU=level1,OU=level2,OU=level3
//
// 3 - Split that string and build a map where the first
// index is meant to describe the depth of the OU, and the
// second.
// Every object on the map has a pointer to it's parent. It
// isn't a pointer itself, but has it's parent name's value
// so it can be matched with the real one.
//
// 4 - Iterate over the map and build the tree finding for
// every level any children of the current OU based on the
// first index and the pointer.
func adGetTree() *ADOrganizationalUnit {

	l, err := adConnect()
	if l == nil {
		return nil
	}
	defer l.Close()

	// Make the search and list the neccesary attributes
	sr, err := l.Search(adSearchReq("", "(ou=*)"))
	if err != nil {
		return nil
	}

	allOrgUnits := map[int][]ADOrganizationalUnitR{}

	// Parse every OU found, find its parent and add an entry to the map
	for _, entry := range sr.Entries[1:] {

		// Reverse the OU's slice
		ous := flipSlice(strings.Split(strings.Split(entry.DN, ldapSearchBase2)[0], "OU="))

		for k := 0; k < len(ous); k++ {

			// Remove the trailing comma
			// i.e. DC=local, => DC=local
			ous[k] = trimTrailingComma(ous[k])

			// Check if the ou is already present on the map
			present := false
			for l := 0; l < len(allOrgUnits[k]); l++ {
				if allOrgUnits[k][l].name == ous[k] {
					present = true
				}
			}

			if !present {

				// Detect the parent
				parent := ""
				if k > 0 {
					parent = ous[k-1]
				}

				// Add the ou to the map
				allOrgUnits[k] = append(allOrgUnits[k],
					ADOrganizationalUnitR{name: ous[k], parent: parent})
			}
		}
	}

	// Create an empty/root OU and add all the level 0 OUs as its children
	ouMaster := ADOrganizationalUnit{Name: "", Children: &[]ADOrganizationalUnit{}}
	for _, ou := range allOrgUnits[0] {
		*ouMaster.Children = append(*ouMaster.Children, ADOrganizationalUnit{
			Name: ou.name, Children: &[]ADOrganizationalUnit{}})
	}

	// Make the tree starting at level 1
	genTree(ouMaster.Children, allOrgUnits, 1)

	return &ouMaster
}

// Generate the tree given a set of OUs, the original map and the current level
// where the tree is being build
func genTree(c *[]ADOrganizationalUnit, a map[int][]ADOrganizationalUnitR, nlevel int) {
	for _, ou := range *c {
		for _, aou := range a[nlevel] {
			if aou.parent == ou.Name && strings.TrimSpace(aou.name) != "" {
				*ou.Children = append(*ou.Children, ADOrganizationalUnit{
					Name:     aou.name,
					Children: &[]ADOrganizationalUnit{},
				})
			}
		}
		genTree(ou.Children, a, nlevel+1)
	}
}

// Search for all users under a specific OU.
//
// The ou parameter must not be the full OU's DN
// i.e. level1.
// i.e. level3,OU=level2,OU=level1.
func adGetUsers(ou string) []*ADUser {

	l, err := adConnect()
	if l == nil {
		return nil
	}
	defer l.Close()

	// Search for the maxPwdAge attribute
	sr, _ := l.Search(adSearchReqAttr("", "(cn=Builtin)", []string{"maxPwdAge"}))
	maxPwdAge, _ := strconv.ParseInt(sr.Entries[0].GetAttributeValue("maxPwdAge"), 10, 64)

	// Make the search and list the neccesary attributes
	sr, err = l.Search(adSearchReqAttr(adOuString(ou), "(objectClass=user)",
		[]string{
			"dn", "sAMAccountName", "cn", "description", "displayName", "givenName", "homeDrive", "initials",
			"name", "physicalDeliveryOfficeName", "postOfficeBox", "profilePath", "title",
			"userPrincipalName", "mail", "company", "department", "homephone", "L", "City",
			"manager", "mobile", "pwdLastSet", "postalCode", "st", "streetAddress", "telephoneNumber",
			"scriptPath"}))
	if err != nil {
		return nil
	}

	users := []*ADUser{}

	// For each user found, convert every one of the entry to an ADUser struct,
	// and attach its groups
	for _, entry := range sr.Entries {

		user := initADUser(entry, maxPwdAge)

		// Build the search filter for the user's groups
		var groupFilter bytes.Buffer
		groupFilter.WriteString("(&(objectcategory=group)(member=")
		groupFilter.WriteString(entry.DN)
		groupFilter.WriteString("))")

		sr, err := l.Search(adSearchReqAttr(
			"", groupFilter.String(), []string{"cn"}))
		if err == nil {
			groups := []string{}

			// Attach the groups to the user's struct
			for _, entry := range sr.Entries {
				groups = append(groups, entry.GetAttributeValue("cn"))
			}
			user.Groups = groups
		}

		users = append(users, user)
	}

	return users
}

// Searchs for a User based on the name / username (more specifically the
// sAMAccountName and CN attributes)
func adGetUser(name string) []*ADUser {

	l, err := adConnect()
	if l == nil {
		return nil
	}
	defer l.Close()

	// Search for the maxPwdAge attribute
	sr, _ := l.Search(adSearchReqAttr("", "(cn=Builtin)", []string{"maxPwdAge"}))
	maxPwdAge, _ := strconv.ParseInt(sr.Entries[0].GetAttributeValue("maxPwdAge"), 10, 64)

	// Build the search filter for the user
	var filter bytes.Buffer
	filter.WriteString("(&(objectclass=user)(objectcategory=user)(|(SAMAccountName=")
	filter.WriteString(name)
	filter.WriteString("*)(CN=")
	filter.WriteString(name)
	filter.WriteString("*)))")

	// Make the search and list the neccesary attributes
	sr, err = l.Search(adSearchReqAttr("", filter.String(),
		[]string{
			"dn", "sAMAccountName", "cn", "description", "displayName", "givenName", "homeDrive", "initials",
			"name", "physicalDeliveryOfficeName", "postOfficeBox", "profilePath", "title",
			"userPrincipalName", "mail", "company", "department", "homephone", "L", "City",
			"manager", "mobile", "pwdLastSet", "postalCode", "st", "streetAddress", "telephoneNumber",
			"scriptPath"}))
	if err != nil {
		return nil
	}

	users := []*ADUser{}

	// For each user found, convert every one of the entry to an ADUser struct,
	// and attach its groups
	for _, entry := range sr.Entries {
		user := initADUser(entry, maxPwdAge)

		// Build the search filter for the user's groups
		var groupFilter bytes.Buffer
		groupFilter.WriteString("(&(objectcategory=group)(member=")
		groupFilter.WriteString(entry.DN)
		groupFilter.WriteString("))")

		sr, err := l.Search(adSearchReqAttr(
			"", groupFilter.String(), []string{"cn"}))
		if err == nil {

			// Attach the groups to the user's struct
			groups := []string{}
			for _, entry := range sr.Entries {
				groups = append(groups, entry.GetAttributeValue("cn"))
			}
			user.Groups = groups
		}

		users = append(users, user)
	}

	return users
}

// Initializes and retrieve an ADUser struct based on a ldap.Entry
//
// The entry parameter is meant to be a response to a search which
// objectClass or objectCategory is "user".
// The maxPwdAge is a variable found in the Builtin object of any
// Active Directory server that contains the max age that a password
// can take in the Active Directory timestamp format.
func initADUser(entry *ldap.Entry, maxPwdAge int64) *ADUser {

	// Retrieves and transform Active Directory timestamp to Unix timestamp
	pwdLastSet, _ := strconv.ParseInt(entry.GetAttributeValue("pwdLastSet"), 10, 64)
	pwdExpires := pwdLastSet - maxPwdAge
	pwdLastSetUnix := int64(int64(pwdLastSet/10000000) - int64(11644473600))
	pwdExpiresUnix := int64(int64(pwdExpires/10000000) - int64(11644473600))

	// Initialize the ADUser struct
	user := &ADUser{
		DN:             entry.DN,
		CN:             entry.GetAttributeValue("cn"),
		SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
		Description:    entry.GetAttributeValue("description"),
		DisplayName:    entry.GetAttributeValue("displayName"),
		GivenName:      entry.GetAttributeValue("givenName"),
		HomeDrive:      entry.GetAttributeValue("homeDrive"),
		Name:           entry.GetAttributeValue("name"),
		PhysicalDeliveryOfficeName: entry.GetAttributeValue("physicalDeliveryOfficeName"),
		PostOfficeBox:              entry.GetAttributeValue("postOfficeBox"),
		ProfilePath:                entry.GetAttributeValue("profilePath"),
		Title:                      entry.GetAttributeValue("title"),
		UserPrincipalName:          entry.GetAttributeValue("userPrincipalName"),
		Mail:                       entry.GetAttributeValue("mail"),
		Company:                    entry.GetAttributeValue("company"),
		Department:                 entry.GetAttributeValue("department"),
		Homephone:                  entry.GetAttributeValue("homephone"),
		L:                          entry.GetAttributeValue("L"),
		City:                       entry.GetAttributeValue("city"),
		Manager:                    entry.GetAttributeValue("manager"),
		Mobile:                     entry.GetAttributeValue("mobile"),
		PwdLastSet:                 fmt.Sprintf("%v", pwdLastSetUnix),
		PwdExpires:                 fmt.Sprintf("%v", pwdExpiresUnix),
		PostalCode:                 entry.GetAttributeValue("postalCode"),
		ST:                         entry.GetAttributeValue("ST"),
		StreetAddress:              entry.GetAttributeValue("streetAddress"),
		TelephoneNumber:            entry.GetAttributeValue("telephoneNumber"),
		Groups:                     []string{},
		ScriptPath:                 entry.GetAttributeValue("scriptPath"),
	}

	return user
}

// Extra AD/LDAP useful functions
func adOuString(ouStr string) string {
	var ou bytes.Buffer
	ou.WriteString("ou=")
	ou.WriteString(ouStr)
	return ou.String()
}
